package killswitch

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const (
	DocSchema    = "aegisops/kill-switch/v1"
	MaxDocBytes  = 64 << 10
	ConfigMapKey = "document" // ключ data ConfigMap aegisops-control/kill-switch

	minTTL         = time.Minute
	maxTTL         = 24 * time.Hour
	maxSignatures  = 4
	maxListEntries = 64
)

var (
	issuerRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	clusterRe = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	actionRe  = regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`)
)

// Signature — подпись одного ключа. Issuer подписи входит в подписываемое сообщение и должен совпасть с issuer'ом ключа в keyring.
type Signature struct {
	KeyID  string `json:"key_id"`
	Issuer string `json:"issuer"`
	Sig    string `json:"sig"` // base64
}

// Document — документ kill switch, одинаковые байты в обоих каналах. Массивы обязательны (не null).
type Document struct {
	Schema     string      `json:"schema"`
	Global     bool        `json:"global"`
	Clusters   []string    `json:"clusters"`
	Actions    []string    `json:"actions"`
	IssuedAt   string      `json:"issued_at"` // RFC 3339 Nano, UTC, Z
	TTL        string      `json:"ttl"`       // длительность Go, 1m..24h
	Issuer     string      `json:"issuer"`    // автор или назначение; на доверие не влияет
	Signatures []Signature `json:"signatures"`
}

// Signer — валидная подпись разобранного документа.
type Signer struct {
	KeyID  string
	Issuer string
	Role   Role
}

// Verified — разобранный документ с проверенными подписями.
type Verified struct {
	Doc           Document
	IssuedAt      time.Time
	TTL           time.Duration
	SHA256        string // sha256 опубликованных байт (Marshal)
	ContentSHA256 string // sha256 канонического документа без подписей
	Valid         []Signer
	Tainted       bool // есть валидная подпись и есть невалидная, незнакомая или с чужим issuer'ом
}

// DocError — документ отвергнут целиком. Class: unsigned | unknown_key | bad_signature | invalid | oversize.
type DocError struct {
	Class string
	Msg   string
}

func (e *DocError) Error() string {
	if e.Msg == "" {
		return "kill switch: документ отвергнут: " + e.Class
	}
	return "kill switch: документ отвергнут (" + e.Class + "): " + e.Msg
}

// ErrKind — класс для статуса канала.
func (e *DocError) ErrKind() string { return e.Class }

// ParseOptions — проверка семантики. KnownAction nil — достаточно формы «группа.действие».
type ParseOptions struct{ KnownAction func(string) bool }

func strVal(items []string) *pyjson.Value {
	vs := make([]*pyjson.Value, 0, len(items))
	for _, s := range items {
		vs = append(vs, pyjson.NewString(s))
	}
	return pyjson.NewArray(vs...)
}

func contentValue(d Document) *pyjson.Value {
	return pyjson.NewObject(
		pyjson.M("schema", pyjson.NewString(d.Schema)),
		pyjson.M("global", pyjson.NewBool(d.Global)),
		pyjson.M("clusters", strVal(d.Clusters)),
		pyjson.M("actions", strVal(d.Actions)),
		pyjson.M("issued_at", pyjson.NewString(d.IssuedAt)),
		pyjson.M("ttl", pyjson.NewString(d.TTL)),
		pyjson.M("issuer", pyjson.NewString(d.Issuer)))
}

// Content — канонический документ без подписей (pyjson.Canonical).
func Content(d Document) ([]byte, error) {
	return pyjson.Marshal(contentValue(d), pyjson.Canonical), nil
}

func sigMessage(content []byte, keyID, issuer string) []byte {
	return []byte(DocSchema + "\x00" + string(content) + "\x00" + keyID + "\x00" + issuer)
}

// SignatureFor подписывает документ (без его подписей) ключом s от имени issuer'а.
func SignatureFor(d Document, s audit.Signer, issuer string) (Signature, error) {
	if !issuerRe.MatchString(issuer) {
		return Signature{}, fmt.Errorf("некорректный issuer %q", issuer)
	}
	c, _ := Content(d)
	sig, err := s.Sign(sigMessage(c, s.KeyID(), issuer))
	if err != nil {
		return Signature{}, err
	}
	return Signature{KeyID: s.KeyID(), Issuer: issuer, Sig: base64.StdEncoding.EncodeToString(sig)}, nil
}

// AddSignature возвращает копию документа с ещё одной подписью (сортировка по key_id). Повтор key_id — ошибка.
func AddSignature(d Document, sig Signature) (Document, error) {
	for _, s := range d.Signatures {
		if s.KeyID == sig.KeyID {
			return Document{}, fmt.Errorf("ключ %s уже подписал документ", sig.KeyID)
		}
	}
	out := d
	out.Signatures = append(append([]Signature(nil), d.Signatures...), sig)
	sort.Slice(out.Signatures, func(i, j int) bool { return out.Signatures[i].KeyID < out.Signatures[j].KeyID })
	return out, nil
}

// Marshal — публикуемые байты: pyjson.Canonical всего объекта, подписи отсортированы по key_id.
func Marshal(d Document) []byte {
	v := contentValue(d)
	sigs := append([]Signature(nil), d.Signatures...)
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].KeyID < sigs[j].KeyID })
	items := make([]*pyjson.Value, 0, len(sigs))
	for _, s := range sigs {
		items = append(items, pyjson.NewObject(
			pyjson.M("key_id", pyjson.NewString(s.KeyID)),
			pyjson.M("issuer", pyjson.NewString(s.Issuer)),
			pyjson.M("sig", pyjson.NewString(s.Sig))))
	}
	v.Set("signatures", pyjson.NewArray(items...))
	return pyjson.Marshal(v, pyjson.Canonical)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func invalid(format string, a ...any) error {
	return &DocError{Class: "invalid", Msg: fmt.Sprintf(format, a...)}
}

// Parse разбирает документ. Порядок: размер, дубли ключей, строгий разбор, подписи (наличие, число, повторы),
// семантика, проверка подписей. Весь документ отвергается ошибкой *DocError; запятнанный документ (есть и валидные,
// и невалидные подписи) возвращается с Tainted.
func Parse(raw []byte, keys Keyring, o ParseOptions) (Verified, error) {
	if len(raw) > MaxDocBytes {
		return Verified{}, &DocError{Class: "oversize"}
	}
	if _, err := pyjson.Parse(raw); err != nil {
		return Verified{}, invalid("%v", err)
	}
	var d Document
	if err := strictjson.Decode(raw, &d); err != nil {
		return Verified{}, invalid("%v", err)
	}
	if d.Clusters == nil || d.Actions == nil || d.Signatures == nil {
		return Verified{}, invalid("clusters, actions и signatures — массивы обязательны")
	}
	if len(d.Signatures) == 0 {
		return Verified{}, &DocError{Class: "unsigned"}
	}
	if len(d.Signatures) > maxSignatures {
		return Verified{}, invalid("подписей больше %d", maxSignatures)
	}
	seen := map[string]bool{}
	for _, s := range d.Signatures {
		if seen[s.KeyID] {
			return Verified{}, invalid("ключ %s подписал дважды", s.KeyID)
		}
		seen[s.KeyID] = true
		if s.KeyID == "" || !issuerRe.MatchString(s.Issuer) {
			return Verified{}, invalid("подпись: некорректные key_id или issuer")
		}
	}
	v := Verified{Doc: d}
	var err error
	if d.Schema != DocSchema {
		return Verified{}, invalid("schema %q", d.Schema)
	}
	if v.IssuedAt, err = time.Parse(time.RFC3339Nano, d.IssuedAt); err != nil || v.IssuedAt.Location() != time.UTC || d.IssuedAt[len(d.IssuedAt)-1] != 'Z' {
		return Verified{}, invalid("issued_at: ожидается RFC 3339 UTC с суффиксом Z")
	}
	if v.TTL, err = time.ParseDuration(d.TTL); err != nil || v.TTL < minTTL || v.TTL > maxTTL {
		return Verified{}, invalid("ttl: ожидается длительность от %s до %s", minTTL, maxTTL)
	}
	if !issuerRe.MatchString(d.Issuer) {
		return Verified{}, invalid("issuer: некорректный")
	}
	if err := checkList("clusters", d.Clusters, clusterRe.MatchString); err != nil {
		return Verified{}, err
	}
	if err := checkList("actions", d.Actions, func(a string) bool {
		return actionRe.MatchString(a) && (o.KnownAction == nil || o.KnownAction(a))
	}); err != nil {
		return Verified{}, err
	}
	content, _ := Content(d)
	var unknown, bad int
	for _, s := range d.Signatures {
		k, ok := keys[s.KeyID]
		sig, derr := base64.StdEncoding.Strict().DecodeString(s.Sig)
		switch {
		case !ok:
			unknown++
		case k.Issuer != s.Issuer || derr != nil || len(sig) != ed25519.SignatureSize ||
			!ed25519.Verify(k.Pub, sigMessage(content, s.KeyID, s.Issuer), sig):
			bad++
		default:
			v.Valid = append(v.Valid, Signer{KeyID: s.KeyID, Issuer: s.Issuer, Role: k.Role})
		}
	}
	if len(v.Valid) == 0 {
		if unknown > 0 {
			return Verified{}, &DocError{Class: "unknown_key"}
		}
		return Verified{}, &DocError{Class: "bad_signature"}
	}
	v.Tainted = len(v.Valid) < len(d.Signatures)
	v.SHA256 = sha256Hex(Marshal(d))
	v.ContentSHA256 = sha256Hex(content)
	return v, nil
}

func checkList(name string, items []string, ok func(string) bool) error {
	if len(items) > maxListEntries {
		return invalid("%s: больше %d", name, maxListEntries)
	}
	seen := map[string]bool{}
	for _, s := range items {
		if !ok(s) {
			return invalid("%s: недопустимое значение %q", name, s)
		}
		if seen[s] {
			return invalid("%s: %q повторяется", name, s)
		}
		seen[s] = true
	}
	return nil
}

// HitsCluster — документ называет кластер c.
func (v Verified) HitsCluster(c string) bool {
	for _, x := range v.Doc.Clusters {
		if x == c {
			return true
		}
	}
	return false
}

// StopsTarget — документ останавливает цель: global или её кластер.
func (v Verified) StopsTarget(cluster string) bool { return v.Doc.Global || v.HitsCluster(cluster) }

// Confirmation — чем документ подтверждает «не остановлен» для кластера cluster: oncall | renewer | none.
// Подтверждает только незапятнанный документ без global и без этого кластера и только при двух валидных подписях
// разных ключей: oncall — две роли oncall, renewer — любые две.
func (v Verified) Confirmation(cluster string) string {
	if v.Tainted || v.StopsTarget(cluster) {
		return "none"
	}
	var oncall int
	for _, s := range v.Valid {
		if s.Role == RoleOncall {
			oncall++
		}
	}
	switch {
	case oncall >= 2:
		return "oncall"
	case len(v.Valid) >= 2:
		return "renewer"
	}
	return "none"
}

// SignerIssuers — issuer'ы валидных подписей, отсортированы.
func (v Verified) SignerIssuers() []string {
	out := make([]string, 0, len(v.Valid))
	for _, s := range v.Valid {
		out = append(out, s.Issuer)
	}
	sort.Strings(out)
	return out
}
