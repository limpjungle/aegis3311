package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const (
	EntrySchema      = "aegisops/audit-entry/v1"
	CheckpointSchema = "aegisops/audit-checkpoint/v1"

	// MaxLineBytes — потолок одной записи цепочки; длиннее — ошибка и при записи, и при проверке.
	MaxLineBytes = 4 << 20
)

// GenesisHash — prev_hash первой записи цепочки.
var GenesisHash = "sha256:" + strings.Repeat("0", 64)

// Entry — строка файла цепочки (JSONL). В цепочке три типа записей: decision record (RecordSchema), событие
// роутера (RouterEventSchema) и событие kill switch (KillSwitchEventSchema); тип определяется полем schema внутри record, в хеш записи он не входит. Hash = sha256 канонического JSON {schema, chain_id, seq, prev_hash,
// record_sha256}; Sig — подпись Ed25519 над "aegisops/audit-entry/v1\x00" + Hash, base64.
type Entry struct {
	Schema       string          `json:"schema"`
	ChainID      string          `json:"chain_id"`
	Seq          uint64          `json:"seq"` // с 1, без пропусков
	PrevHash     string          `json:"prev_hash"`
	RecordSHA256 string          `json:"record_sha256"`
	Hash         string          `json:"hash"`
	KeyID        string          `json:"key_id"`
	Sig          string          `json:"sig"`
	Record       json.RawMessage `json:"record"`
}

// Head — голова цепочки: последняя проверенная запись. Seq = 0 — цепочка пуста.
type Head struct {
	ChainID string `json:"chain_id"`
	Seq     uint64 `json:"seq"`
	Hash    string `json:"hash"`
}

// Checkpoint — подписанная фиксация головы цепочки для внешнего WORM-хранилища.
// Sig — подпись над "aegisops/audit-checkpoint/v1\x00" + канонический JSON всех полей, кроме sig.
type Checkpoint struct {
	Schema    string `json:"schema"`
	ChainID   string `json:"chain_id"`
	Seq       uint64 `json:"seq"`
	HeadHash  string `json:"head_hash"`
	CreatedAt string `json:"created_at"`
	KeyID     string `json:"key_id"`
	Sig       string `json:"sig"`
}

func sha256Prefixed(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func entryHash(chainID string, seq uint64, prev, recordSHA string) string {
	b, _ := json.Marshal(struct {
		Schema       string `json:"schema"`
		ChainID      string `json:"chain_id"`
		Seq          uint64 `json:"seq"`
		PrevHash     string `json:"prev_hash"`
		RecordSHA256 string `json:"record_sha256"`
	}{EntrySchema, chainID, seq, prev, recordSHA})
	return sha256Prefixed(b)
}

func entrySigMsg(hash string) []byte { return []byte(EntrySchema + "\x00" + hash) }

func checkpointSigMsg(c Checkpoint) []byte {
	c.Sig = ""
	b, _ := json.Marshal(struct {
		Schema    string `json:"schema"`
		ChainID   string `json:"chain_id"`
		Seq       uint64 `json:"seq"`
		HeadHash  string `json:"head_hash"`
		CreatedAt string `json:"created_at"`
		KeyID     string `json:"key_id"`
	}{c.Schema, c.ChainID, c.Seq, c.HeadHash, c.CreatedAt, c.KeyID})
	return append([]byte(CheckpointSchema+"\x00"), b...)
}

// NewRecordID — случайный ID decision record'а: "dr-" + 32 hex.
func NewRecordID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand не отказывает на поддерживаемых платформах
	}
	return "dr-" + hex.EncodeToString(b[:])
}

// Timestamp — формат recorded_at и created_at: RFC 3339 с наносекундами, UTC.
func Timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// ChainError — нарушение цепочки. Line — номер строки файла (с 1), 0 — ошибка вне конкретной строки.
type ChainError struct {
	Line   int
	Seq    uint64
	Reason string
	Err    error // класс ошибки для errors.Is (ErrNewerFormat); может быть nil
}

func (e *ChainError) Unwrap() error { return e.Err }

func (e *ChainError) Error() string {
	if e.Line == 0 {
		return "цепочка аудита: " + e.Reason
	}
	return fmt.Sprintf("цепочка аудита, строка %d (seq %d): %s", e.Line, e.Seq, e.Reason)
}

// VerifyOptions — дополнительные проверки.
type VerifyOptions struct {
	// ChainID — ожидаемый ID цепочки; пусто — берётся из первой записи.
	ChainID string
	// Stats — если не nil, заполняется числом проверенных записей по типам.
	Stats *VerifyStats
	// Checkpoints — зафиксированные во WORM головы. Каждая должна быть подписана, относиться к этой цепочке
	// и совпасть с хешем записи того же seq; checkpoint с seq больше головы — признак усечения цепочки.
	Checkpoints []Checkpoint
	// OnRouterEvent — если не nil, вызывается для каждого события роутера после проверки уникальности event_id.
	OnRouterEvent func(seq uint64, ev *RouterEvent)
	// OnRecord — если не nil, вызывается для каждого decision record'а после проверки уникальности record_id.
	OnRecord func(seq uint64, rec *DecisionRecord)
	// OnKillSwitchEvent — если не nil, вызывается для каждого события kill switch после проверки уникальности event_id.
	OnKillSwitchEvent func(seq uint64, ev *KillSwitchEvent)
	// IntegrityOnly — только для чтения (aegis-audit verify -integrity-only), не для OpenWriter. Цепь, хеши, подписи и
	// checkpoint'ы проверяются полностью; запись неизвестной схемы aegisops/* или с неизвестным полем (ErrNewerFormat)
	// не считается ошибкой, а считается в VerifyStats.Unverified: содержимое не проверено, ID не сверяются, колбэки не
	// вызываются. Для приёмки аудита режим не годится. Остальные ошибки по-прежнему фатальны.
	IntegrityOnly bool
}

// VerifyStats — число проверенных записей цепочки по типам.
type VerifyStats struct {
	Records, RouterEvents, KillSwitchEvents uint64
	// Unverified — записи, содержимое которых не проверено (только при IntegrityOnly); UnverifiedSchemas — их схемы,
	// отсортированы, без повторов.
	Unverified        uint64
	UnverifiedSchemas []string
}

// Verify читает цепочку целиком и проверяет: формат строк, непрерывность seq, ссылки prev_hash, хеши записей
// и записей, подписи, схему и валидность записей всех типов, уникальность record_id и event_id и checkpoint'ы.
// Незавершённая последняя строка (без перевода строки) — ошибка: запись могла оборваться при сбое.
func Verify(r io.Reader, keys Keyring, opts VerifyOptions) (Head, error) {
	head := Head{ChainID: opts.ChainID, Hash: GenesisHash}
	cps := map[uint64][]Checkpoint{}
	for _, c := range opts.Checkpoints {
		if err := VerifyCheckpoint(c, keys); err != nil {
			return head, &ChainError{Reason: fmt.Sprintf("checkpoint seq %d: %v", c.Seq, err)}
		}
		if opts.ChainID != "" && c.ChainID != opts.ChainID {
			return head, &ChainError{Reason: fmt.Sprintf("checkpoint seq %d: chain_id %q", c.Seq, c.ChainID)}
		}
		cps[c.Seq] = append(cps[c.Seq], c)
	}
	ids := map[string]uint64{}
	var stats VerifyStats
	unverified := map[string]bool{}
	if opts.Stats != nil {
		defer func() {
			for s := range unverified {
				stats.UnverifiedSchemas = append(stats.UnverifiedSchemas, s)
			}
			sort.Strings(stats.UnverifiedSchemas)
			*opts.Stats = stats
		}()
	}
	br := bufio.NewReaderSize(r, 64<<10)
	for line := 1; ; line++ {
		raw, err := readLine(br)
		if err == io.EOF {
			break
		}
		fail := func(format string, a ...any) (Head, error) {
			return head, &ChainError{Line: line, Seq: head.Seq + 1, Reason: fmt.Sprintf(format, a...)}
		}
		if err != nil {
			return fail("%v", err)
		}
		var e Entry
		if err := strictjson.Decode(raw, &e); err != nil {
			return fail("разбор записи: %v", err)
		}
		if e.Schema != EntrySchema {
			return fail("schema %q", e.Schema)
		}
		if head.ChainID == "" {
			if !chainRe.MatchString(e.ChainID) {
				return fail("некорректный chain_id %q", e.ChainID)
			}
			head.ChainID = e.ChainID
		} else if e.ChainID != head.ChainID {
			return fail("chain_id %q, ожидается %q", e.ChainID, head.ChainID)
		}
		if e.Seq != head.Seq+1 {
			return fail("seq %d, ожидается %d", e.Seq, head.Seq+1)
		}
		if e.PrevHash != head.Hash {
			return fail("prev_hash не совпадает с хешем предыдущей записи")
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, e.Record); err != nil || !bytes.Equal(compact.Bytes(), e.Record) {
			return fail("record не в компактной форме")
		}
		if got := sha256Prefixed(e.Record); got != e.RecordSHA256 {
			return fail("record_sha256 не совпадает с содержимым")
		}
		if got := entryHash(e.ChainID, e.Seq, e.PrevHash, e.RecordSHA256); got != e.Hash {
			return fail("hash записи не совпадает")
		}
		sig, err := base64.StdEncoding.Strict().DecodeString(e.Sig)
		if err != nil {
			return fail("sig: %v", err)
		}
		if err := keys.verify(e.KeyID, entrySigMsg(e.Hash), sig); err != nil {
			return fail("подпись: %v", err)
		}
		var peek struct {
			Schema string `json:"schema"`
		}
		_ = json.Unmarshal(e.Record, &peek) // дубли ключей и неизвестные поля ловит strictjson.Decode ниже
		var id, idName string
		var routerEv *RouterEvent
		var ksEv *KillSwitchEvent
		var decRec *DecisionRecord
		newerWhat := "" // запись новее сборки: неизвестная схема или поле
		// decode разбирает запись; неизвестное поле известной схемы — запись новее сборки, прочее — нарушение формата.
		decode := func(label string, v any) (ok bool, h Head, err error) {
			if derr := strictjson.Decode(e.Record, v); derr != nil {
				var uf *strictjson.UnknownFieldError
				if errors.As(derr, &uf) {
					newerWhat = fmt.Sprintf("содержит поле %q, неизвестное этой сборке", uf.Field)
					return false, head, nil
				}
				h, err = fail("%s: %v", label, derr)
				return false, h, err
			}
			return true, head, nil
		}
		switch peek.Schema {
		case RecordSchema:
			var rec DecisionRecord
			ok, h, err := decode("decision record", &rec)
			if err != nil {
				return h, err
			}
			if ok {
				if err := rec.Validate(); err != nil {
					return fail("decision record: %v", err)
				}
				id, idName = rec.RecordID, "record_id"
				decRec = &rec
				stats.Records++
			}
		case RouterEventSchema:
			var ev RouterEvent
			ok, h, err := decode("router event", &ev)
			if err != nil {
				return h, err
			}
			if ok {
				if err := ev.Validate(); err != nil {
					return fail("router event: %v", err)
				}
				id, idName = ev.EventID, "event_id"
				routerEv = &ev
				stats.RouterEvents++
			}
		case KillSwitchEventSchema:
			var ev KillSwitchEvent
			ok, h, err := decode("kill switch event", &ev)
			if err != nil {
				return h, err
			}
			if ok {
				if err := ev.Validate(); err != nil {
					return fail("kill switch event: %v", err)
				}
				id, idName = ev.EventID, "event_id"
				ksEv = &ev
				stats.KillSwitchEvents++
			}
		default:
			if !aegisSchemaRe.MatchString(peek.Schema) {
				return fail("неизвестная схема записи %q", peek.Schema)
			}
			newerWhat = "не поддерживается этой сборкой"
		}
		if newerWhat != "" {
			if !opts.IntegrityOnly {
				return head, &ChainError{Line: line, Seq: head.Seq + 1, Err: ErrNewerFormat, Reason: fmt.Sprintf(
					"запись схемы %q %s (формат цепочки %d): обновите aegis-audit; целостность — verify -integrity-only", peek.Schema, newerWhat, ChainFormat)}
			}
			stats.Unverified++
			unverified[peek.Schema] = true
		} else {
			if prev, dup := ids[id]; dup {
				return fail("%s %s уже был в seq %d", idName, id, prev)
			}
			ids[id] = e.Seq
			if decRec != nil && opts.OnRecord != nil {
				opts.OnRecord(e.Seq, decRec)
			}
			if routerEv != nil && opts.OnRouterEvent != nil {
				opts.OnRouterEvent(e.Seq, routerEv)
			}
			if ksEv != nil && opts.OnKillSwitchEvent != nil {
				opts.OnKillSwitchEvent(e.Seq, ksEv)
			}
		}
		for _, c := range cps[e.Seq] {
			if c.ChainID != e.ChainID || c.HeadHash != e.Hash {
				return fail("не совпадает с checkpoint (%s)", c.CreatedAt)
			}
		}
		delete(cps, e.Seq)
		head.Seq, head.Hash = e.Seq, e.Hash
	}
	for seq := range cps {
		return head, &ChainError{Reason: fmt.Sprintf("checkpoint seq %d за головой цепочки (seq %d): цепочка усечена", seq, head.Seq)}
	}
	return head, nil
}

// readLine читает одну строку с '\n'. Пустой ввод — io.EOF; хвост без '\n' и слишком длинная строка — ошибка.
func readLine(br *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > MaxLineBytes+1 {
			return nil, fmt.Errorf("строка длиннее %d байт", MaxLineBytes)
		}
		switch {
		case err == nil:
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(buf) == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("незавершённая последняя строка (оборванная запись)")
		default:
			return nil, err
		}
	}
}

// VerifyCheckpoint проверяет формат и подпись checkpoint'а.
func VerifyCheckpoint(c Checkpoint, keys Keyring) error {
	if c.Schema != CheckpointSchema {
		return fmt.Errorf("schema %q", c.Schema)
	}
	if !chainRe.MatchString(c.ChainID) || c.Seq == 0 || !sha256Re.MatchString(c.HeadHash) {
		return errors.New("некорректные chain_id, seq или head_hash")
	}
	if _, err := time.Parse(time.RFC3339Nano, c.CreatedAt); err != nil {
		return fmt.Errorf("created_at: %v", err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(c.Sig)
	if err != nil {
		return fmt.Errorf("sig: %v", err)
	}
	return keys.verify(c.KeyID, checkpointSigMsg(c), sig)
}

// SignCheckpoint подписывает голову цепочки.
func SignCheckpoint(h Head, at time.Time, s Signer) (Checkpoint, error) {
	if h.Seq == 0 {
		return Checkpoint{}, errors.New("цепочка пуста: фиксировать нечего")
	}
	c := Checkpoint{Schema: CheckpointSchema, ChainID: h.ChainID, Seq: h.Seq, HeadHash: h.Hash,
		CreatedAt: Timestamp(at), KeyID: s.KeyID()}
	sig, err := s.Sign(checkpointSigMsg(c))
	if err != nil {
		return Checkpoint{}, err
	}
	c.Sig = base64.StdEncoding.EncodeToString(sig)
	return c, nil
}
