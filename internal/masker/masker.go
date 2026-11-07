package masker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/limpjungle/aegis3311/internal/dataclass"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

// RulesVersion — версия правил; менять при любой правке правил: попадает в decision record (Version).
const RulesVersion = "1.2.0"

const (
	// MaxScanBytes — предел суммарного размера строк и ключей фрагмента; больше — ошибка (fail-closed).
	MaxScanBytes = 8 << 20
	// maxDepth — предел вложенности значения.
	maxDepth = 512
)

// Config — настройки маскировщика.
type Config struct {
	PseudonymKey []byte         // мастер-ключ псевдонимов, ≥ 32 байт (см. LoadKey)
	InternalNets []netip.Prefix // внутренние сети, IP из которых не маскируются; nil → DefaultInternalNets()
}

// Masker — rule-based маскировщик (dataclass.Masker). Неизменяем, безопасен для конкурентного использования.
type Masker struct {
	key     []byte
	nets    []netip.Prefix
	version string
}

var _ dataclass.Masker = (*Masker)(nil)

// New проверяет и копирует настройки.
func New(cfg Config) (*Masker, error) {
	if len(cfg.PseudonymKey) < minKeyBytes {
		return nil, fmt.Errorf("masker: ключ псевдонимов короче %d байт", minKeyBytes)
	}
	nets := cfg.InternalNets
	if nets == nil {
		nets = DefaultInternalNets()
	}
	nets = append([]netip.Prefix(nil), nets...)
	names := make([]string, len(nets))
	for i, n := range nets {
		if !n.IsValid() {
			return nil, errors.New("masker: некорректная внутренняя сеть")
		}
		nets[i] = n.Masked()
		names[i] = nets[i].String()
	}
	sort.Strings(names)
	sum := sha256.Sum256([]byte(strings.Join(names, "\n")))
	return &Masker{
		key:     append([]byte(nil), cfg.PseudonymKey...),
		nets:    nets,
		version: "aegis-rules/" + RulesVersion + "+cfg." + hex.EncodeToString(sum[:])[:8],
	}, nil
}

// Version — "aegis-rules/<RulesVersion>+cfg.<8 hex хэша списка сетей>"; ключ в версию не входит.
func (m *Masker) Version() string { return m.version }

// state — состояние одного вызова Mask.
type state struct {
	ctx               context.Context
	m                 *Masker
	inc               []byte // ключ псевдонимов инцидента
	nodes, bytes      int
	secrets, personal int
}

// Mask возвращает копию v с вырезанными секретами и замаскированными ПДн. v не меняется.
// Любой сбой (ctx, лимиты, секрет в ключе объекта) — ошибка; частичный результат не возвращается.
func (m *Masker) Mask(ctx context.Context, meta dataclass.FragmentMeta, v *pyjson.Value) (*pyjson.Value, dataclass.MaskReport, error) {
	if err := ctx.Err(); err != nil {
		return nil, dataclass.MaskReport{}, fmt.Errorf("masker: %w", err)
	}
	if v == nil {
		return nil, dataclass.MaskReport{}, errors.New("masker: нет значения")
	}
	if meta.IncidentID == "" {
		return nil, dataclass.MaskReport{}, errors.New("masker: пустой IncidentID (соль псевдонимов не вывести)")
	}
	out := v.Clone()
	st := &state{ctx: ctx, m: m, inc: incidentKey(m.key, meta.IncidentID)}
	if err := st.walk(out, "", false, 0); err != nil {
		return nil, dataclass.MaskReport{}, err
	}
	var rep dataclass.MaskReport
	if st.secrets > 0 {
		rep.Findings = append(rep.Findings, dataclass.Finding{Category: dataclass.CategorySecret, Count: st.secrets})
	}
	if st.personal > 0 {
		rep.Findings = append(rep.Findings, dataclass.Finding{Category: dataclass.CategoryPersonal, Count: st.personal})
	}
	rep.Removed = st.secrets + st.personal
	return out, rep, nil
}

func (st *state) checkCtx() error {
	if err := st.ctx.Err(); err != nil {
		return fmt.Errorf("masker: %w", err)
	}
	return nil
}

// account учитывает размер строки; сверх MaxScanBytes — ошибка. Перед крупной строкой проверяет ctx.
func (st *state) account(n int) error {
	st.bytes += n
	if st.bytes > MaxScanBytes {
		return fmt.Errorf("masker: фрагмент больше %d байт", MaxScanBytes)
	}
	if n >= 64<<10 {
		return st.checkCtx()
	}
	return nil
}

func (st *state) walk(val *pyjson.Value, field string, force bool, depth int) error {
	if depth > maxDepth {
		return errors.New("masker: слишком глубокая вложенность")
	}
	st.nodes++
	if st.nodes&255 == 0 {
		if err := st.checkCtx(); err != nil {
			return err
		}
	}
	switch val.Kind {
	case pyjson.Null, pyjson.Bool:
		return nil
	case pyjson.Number:
		st.walkNumber(val, field, force)
		return nil
	case pyjson.String:
		return st.walkString(val, field, force)
	case pyjson.Array:
		for _, it := range val.Items {
			if err := st.walk(it, field, force, depth+1); err != nil {
				return err
			}
		}
		return nil
	case pyjson.Object:
		return st.walkObject(val, force, depth)
	}
	return fmt.Errorf("masker: неизвестный вид значения %d", val.Kind)
}

// normForKind — нормализованная форма значения для псевдонима.
func normForKind(k fieldKind, s string) (kind, norm string) {
	s = strings.TrimSpace(s)
	switch k {
	case fkDoc:
		return "DOC", normDoc(s)
	}
	switch {
	case strings.Contains(s, "@"):
		return "PERSON", strings.ToLower(s)
	case len(digitsOnly(s)) >= 7 && strings.IndexFunc(s, func(r rune) bool { return r >= 'A' && r <= 'z' || r > 0x7f }) < 0:
		return "PERSON", normPhone(s)
	}
	return "PERSON", normFIO(s)
}

func (st *state) walkString(val *pyjson.Value, field string, force bool) error {
	if err := st.account(len(val.S)); err != nil {
		return err
	}
	if force {
		if !isPlaceholder(val.S) {
			val.S = secretRepl
			st.secrets++
		}
		return nil
	}
	if k := kindKeys[field]; k != fkNone && !isPlaceholder(val.S) {
		kind, norm := normForKind(k, val.S)
		val.S = pseudonym(st.inc, kind, norm)
		st.personal++
		return nil
	}
	s, err := st.scanString(val.S)
	val.S = s
	return err
}

// walkNumber: целое под ПДн-ключом → псевдоним; целое из 13–19 цифр с Luhn → <CARD>. Остальные числа не трогаем.
func (st *state) walkNumber(val *pyjson.Value, field string, force bool) {
	if force || val.IsFloat {
		return
	}
	if k := kindKeys[field]; k != fkNone {
		kind, norm := normForKind(k, val.Int)
		val.Kind, val.S, val.Int = pyjson.String, pseudonym(st.inc, kind, norm), ""
		st.personal++
		return
	}
	if cardNumber(val.Int) {
		val.Kind, val.S, val.Int = pyjson.String, cardRepl, ""
		st.personal++
	}
}

func (st *state) walkObject(val *pyjson.Value, force bool, depth int) error {
	secretKind := false
	if k := val.Get("kind"); k != nil && k.Kind == pyjson.String && k.S == "Secret" {
		secretKind = true
	}
	envPair := false // {name: DB_PASSWORD, value: …}
	if n, v := val.Get("name"), val.Get("value"); n != nil && v != nil && n.Kind == pyjson.String && v.Kind == pyjson.String && isSecretKey(normKey(n.S)) {
		envPair = true
	}
	renamed := false
	for i := range val.Members {
		m := &val.Members[i]
		if err := st.account(len(m.Key)); err != nil {
			return err
		}
		nk := normKey(m.Key)
		sp, err := st.scan(m.Key)
		if err != nil {
			return err
		}
		if len(sp) > 0 {
			for _, x := range sp {
				if x.cat == dataclass.CategorySecret {
					return errors.New("masker: секрет в ключе объекта")
				}
			}
			m.Key = st.apply(m.Key, sp)
			renamed = true
		}
		cf := force || isSecretKey(nk) || (secretKind && (m.Key == "data" || m.Key == "stringData")) || (envPair && m.Key == "value")
		if err := st.walk(m.Value, nk, cf, depth+1); err != nil {
			return err
		}
	}
	if renamed {
		seen := make(map[string]bool, len(val.Members))
		for _, m := range val.Members {
			if seen[m.Key] {
				return errors.New("masker: после замены в ключах объекта появился дубль")
			}
			seen[m.Key] = true
		}
	}
	return nil
}
