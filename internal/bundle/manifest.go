package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/pyjson"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

const (
	Schema        = "aegisops/policy-bundle/v1"
	MaxBytes      = 1 << 20
	maxSignatures = 4
	maxFiles      = 4096
	maxApprovers  = 16
	maxDiffs      = 5 // сколько отличий показывает ошибка mismatch

	// Минимум для принятия bundle агентом: те же числа, что в .github/four-eyes.json (min_approvals, min_groups).
	minApprovers = 2
	minGroups    = 2
)

var (
	issuerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,255}$`)
	hex40Re  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Re  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoRe   = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}/[A-Za-z0-9._-]{1,100}$`)
	loginRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$`)
	groupRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	pathRe   = regexp.MustCompile(`^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`)
)

// Approver — человек, одобривший PR, и группа four-eyes.json, по которой одобрение засчитано.
type Approver struct {
	Login    string `json:"login"`
	Group    string `json:"group"`
	ReviewID int64  `json:"review_id"`
}

// Approvals — одобрения PR, слитого в commit.
type Approvals struct {
	PR        int        `json:"pr"`
	Author    string     `json:"author"`
	HeadSHA   string     `json:"head_sha"`
	Approvers []Approver `json:"approvers"`
}

// Signature — подпись одного ключа. Issuer входит в подписываемое сообщение и должен совпасть с issuer'ом ключа.
type Signature struct {
	KeyID  string `json:"key_id"`
	Issuer string `json:"issuer"`
	Sig    string `json:"sig"` // base64
}

// Manifest — policy bundle. PrevCommit — коммит предыдущего подписанного bundle (null только у sequence 1).
type Manifest struct {
	Schema     string            `json:"schema"`
	Sequence   int               `json:"sequence"`
	Repository string            `json:"repository"`
	Commit     string            `json:"commit"`
	PrevCommit *string           `json:"prev_commit"`
	IssuedAt   string            `json:"issued_at"` // RFC 3339, UTC, Z
	Files      []File            `json:"files"`
	Digests    map[string]string `json:"digests"` // policy_bundle_digest, catalog_digest, llm_assets_digest
	Approvals  Approvals         `json:"approvals"`
	Signatures []Signature       `json:"signatures"`
}

// Error — bundle отвергнут. Class: oversize | invalid | unsigned | unknown_key | bad_signature | approvals | mismatch.
type Error struct {
	Class string
	Msg   string
}

func (e *Error) Error() string {
	if e.Msg == "" {
		return "policy bundle отвергнут: " + e.Class
	}
	return "policy bundle отвергнут (" + e.Class + "): " + e.Msg
}

func invalid(format string, a ...any) error {
	return &Error{Class: "invalid", Msg: fmt.Sprintf(format, a...)}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func strVal(s string) *pyjson.Value { return pyjson.NewString(s) }

func contentValue(m Manifest) *pyjson.Value {
	files := make([]*pyjson.Value, 0, len(m.Files))
	for _, f := range m.Files {
		files = append(files, pyjson.NewObject(pyjson.M("path", strVal(f.Path)), pyjson.M("sha256", strVal(f.SHA256))))
	}
	digests := make([]pyjson.Member, 0, len(m.Digests))
	for k, v := range m.Digests {
		digests = append(digests, pyjson.M(k, strVal(v)))
	}
	approvers := make([]*pyjson.Value, 0, len(m.Approvals.Approvers))
	for _, a := range m.Approvals.Approvers {
		approvers = append(approvers, pyjson.NewObject(pyjson.M("login", strVal(a.Login)), pyjson.M("group", strVal(a.Group)),
			pyjson.M("review_id", pyjson.NewInt(a.ReviewID))))
	}
	prev := pyjson.NewNull()
	if m.PrevCommit != nil {
		prev = strVal(*m.PrevCommit)
	}
	return pyjson.NewObject(
		pyjson.M("schema", strVal(m.Schema)),
		pyjson.M("sequence", pyjson.NewInt(int64(m.Sequence))),
		pyjson.M("repository", strVal(m.Repository)),
		pyjson.M("commit", strVal(m.Commit)),
		pyjson.M("prev_commit", prev),
		pyjson.M("issued_at", strVal(m.IssuedAt)),
		pyjson.M("files", pyjson.NewArray(files...)),
		pyjson.M("digests", pyjson.NewObject(digests...)),
		pyjson.M("approvals", pyjson.NewObject(
			pyjson.M("pr", pyjson.NewInt(int64(m.Approvals.PR))),
			pyjson.M("author", strVal(m.Approvals.Author)),
			pyjson.M("head_sha", strVal(m.Approvals.HeadSHA)),
			pyjson.M("approvers", pyjson.NewArray(approvers...)))))
}

// ContentBytes — канонический манифест без подписей (pyjson.Canonical): то, что подписывается.
func ContentBytes(m Manifest) []byte { return pyjson.Marshal(contentValue(m), pyjson.Canonical) }

// Marshal — публикуемые байты: канонический манифест с подписями, отсортированными по key_id.
func Marshal(m Manifest) []byte {
	v := contentValue(m)
	sigs := append([]Signature(nil), m.Signatures...)
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].KeyID < sigs[j].KeyID })
	items := make([]*pyjson.Value, 0, len(sigs))
	for _, s := range sigs {
		items = append(items, pyjson.NewObject(pyjson.M("key_id", strVal(s.KeyID)), pyjson.M("issuer", strVal(s.Issuer)),
			pyjson.M("sig", strVal(s.Sig))))
	}
	v.Set("signatures", pyjson.NewArray(items...))
	return pyjson.Marshal(v, pyjson.Canonical)
}

func sigMessage(content []byte, keyID, issuer string) []byte {
	return []byte(Schema + "\x00" + string(content) + "\x00" + keyID + "\x00" + issuer)
}

// Sign возвращает копию манифеста с ещё одной подписью ключа s от имени issuer'а. Повтор key_id — ошибка.
func Sign(m Manifest, s audit.Signer, issuer string) (Manifest, error) {
	if !issuerRe.MatchString(issuer) {
		return Manifest{}, fmt.Errorf("некорректный issuer %q", issuer)
	}
	for _, x := range m.Signatures {
		if x.KeyID == s.KeyID() {
			return Manifest{}, fmt.Errorf("ключ %s уже подписал bundle", x.KeyID)
		}
	}
	sig, err := s.Sign(sigMessage(ContentBytes(m), s.KeyID(), issuer))
	if err != nil {
		return Manifest{}, err
	}
	out := m
	out.Signatures = append(append([]Signature(nil), m.Signatures...),
		Signature{KeyID: s.KeyID(), Issuer: issuer, Sig: base64.StdEncoding.EncodeToString(sig)})
	return out, nil
}

// Key — открытый ключ подписи bundle с привязкой к issuer'у.
type Key struct {
	Pub    ed25519.PublicKey
	Issuer string
}

// Keyring — ключи подписи bundle по audit.KeyID. Отдельный от keyring аудита и kill switch.
type Keyring map[string]Key

// KeySpec — запись о ключе: файл открытого ключа (PEM PKIX) и issuer.
type KeySpec struct {
	Path   string `json:"path"`
	Issuer string `json:"issuer"`
}

// LoadKeyring читает открытые ключи. Нужен хотя бы один; повторы key_id и issuer — ошибка.
func LoadKeyring(specs []KeySpec) (Keyring, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("policy bundle: нет ключей подписи")
	}
	k := Keyring{}
	issuers := map[string]bool{}
	for _, s := range specs {
		if !issuerRe.MatchString(s.Issuer) {
			return nil, fmt.Errorf("policy bundle: ключ %s: некорректный issuer %q", s.Path, s.Issuer)
		}
		pub, err := audit.LoadPublicKey(s.Path)
		if err != nil {
			return nil, fmt.Errorf("policy bundle: %w", err)
		}
		id := audit.KeyID(pub)
		if _, dup := k[id]; dup {
			return nil, fmt.Errorf("policy bundle: ключ %s повторяется (%s)", id, s.Path)
		}
		if issuers[s.Issuer] {
			return nil, fmt.Errorf("policy bundle: issuer %q повторяется", s.Issuer)
		}
		issuers[s.Issuer] = true
		k[id] = Key{Pub: pub, Issuer: s.Issuer}
	}
	return k, nil
}

// Signer — валидная подпись разобранного bundle.
type Signer struct{ KeyID, Issuer string }

// Verified — разобранный bundle с проверенными подписями и одобрениями.
type Verified struct {
	Manifest Manifest
	IssuedAt time.Time
	SHA256   string // sha256 опубликованных байт (Marshal)
	Signers  []Signer
}

// Verify разбирает и проверяет bundle: размер, дубли ключей, строгий разбор, структуру, подписи (каждая должна быть
// известной и валидной: запятнанный bundle отвергается целиком), одобрения (не меньше двух разных людей, не автор,
// не меньше двух групп). Соответствие содержимому — Verified.Matches.
func Verify(b []byte, keys Keyring) (*Verified, error) {
	if len(b) > MaxBytes {
		return nil, &Error{Class: "oversize"}
	}
	if _, err := pyjson.Parse(b); err != nil {
		return nil, invalid("%v", err)
	}
	var m Manifest
	if err := strictjson.Decode(b, &m); err != nil {
		return nil, invalid("%v", err)
	}
	if m.Files == nil || m.Digests == nil || m.Approvals.Approvers == nil || m.Signatures == nil {
		return nil, invalid("files, digests, approvals.approvers и signatures обязательны (не null)")
	}
	if len(m.Signatures) == 0 {
		return nil, &Error{Class: "unsigned"}
	}
	v := &Verified{Manifest: m}
	if err := checkStructure(m, v); err != nil {
		return nil, err
	}
	content := ContentBytes(m)
	for _, s := range m.Signatures {
		k, ok := keys[s.KeyID]
		if !ok {
			return nil, &Error{Class: "unknown_key", Msg: "ключ " + s.KeyID}
		}
		sig, derr := base64.StdEncoding.Strict().DecodeString(s.Sig)
		if k.Issuer != s.Issuer || derr != nil || len(sig) != ed25519.SignatureSize ||
			!ed25519.Verify(k.Pub, sigMessage(content, s.KeyID, s.Issuer), sig) {
			return nil, &Error{Class: "bad_signature", Msg: "ключ " + s.KeyID}
		}
		v.Signers = append(v.Signers, Signer{KeyID: s.KeyID, Issuer: s.Issuer})
	}
	if err := checkApprovals(m.Approvals); err != nil {
		return nil, err
	}
	v.SHA256 = sha256Hex(Marshal(m))
	return v, nil
}

func checkStructure(m Manifest, v *Verified) error {
	if len(m.Signatures) > maxSignatures {
		return invalid("подписей больше %d", maxSignatures)
	}
	seen := map[string]bool{}
	for _, s := range m.Signatures {
		if seen[s.KeyID] {
			return invalid("ключ %s подписал дважды", s.KeyID)
		}
		seen[s.KeyID] = true
		if s.KeyID == "" || !issuerRe.MatchString(s.Issuer) {
			return invalid("подпись: некорректные key_id или issuer")
		}
	}
	if m.Schema != Schema {
		return invalid("schema %q", m.Schema)
	}
	if m.Sequence < 1 {
		return invalid("sequence: ожидается число не меньше 1")
	}
	if !repoRe.MatchString(m.Repository) {
		return invalid("repository: ожидается owner/name")
	}
	if !hex40Re.MatchString(m.Commit) {
		return invalid("commit: ожидается 40 hex")
	}
	switch {
	case m.Sequence == 1 && m.PrevCommit != nil:
		return invalid("prev_commit при sequence 1 должен быть null")
	case m.Sequence > 1 && (m.PrevCommit == nil || !hex40Re.MatchString(*m.PrevCommit)):
		return invalid("prev_commit: ожидается 40 hex при sequence > 1")
	}
	t, err := time.Parse(time.RFC3339Nano, m.IssuedAt)
	if err != nil || t.Location() != time.UTC || !strings.HasSuffix(m.IssuedAt, "Z") {
		return invalid("issued_at: ожидается RFC 3339 UTC с суффиксом Z")
	}
	v.IssuedAt = t
	if len(m.Files) == 0 || len(m.Files) > maxFiles {
		return invalid("files: от 1 до %d записей", maxFiles)
	}
	for i, f := range m.Files {
		if !pathRe.MatchString(f.Path) || f.Path == "." || strings.Contains(f.Path, "..") {
			return invalid("files: некорректный путь %q", f.Path)
		}
		if !hex64Re.MatchString(f.SHA256) {
			return invalid("files[%s]: sha256 — 64 hex", f.Path)
		}
		if i > 0 && m.Files[i-1].Path >= f.Path {
			return invalid("files: пути должны быть отсортированы и без повторов (%q)", f.Path)
		}
	}
	if len(m.Digests) != 3 {
		return invalid("digests: ожидаются ровно %s, %s, %s", DigestPolicy, DigestCatalog, DigestLLM)
	}
	for _, k := range []string{DigestPolicy, DigestCatalog, DigestLLM} {
		if !digestRe.MatchString(m.Digests[k]) {
			return invalid("digests[%s]: ожидается sha256:<64 hex>", k)
		}
	}
	a := m.Approvals
	if a.PR < 1 || !loginRe.MatchString(a.Author) || !hex40Re.MatchString(a.HeadSHA) {
		return invalid("approvals: некорректные pr, author или head_sha")
	}
	if len(a.Approvers) > maxApprovers {
		return invalid("approvals.approvers: больше %d", maxApprovers)
	}
	for _, x := range a.Approvers {
		if !loginRe.MatchString(x.Login) || !groupRe.MatchString(x.Group) || x.ReviewID < 1 {
			return invalid("approvals.approvers: некорректная запись %q", x.Login)
		}
	}
	return nil
}

// checkApprovals: не меньше двух разных людей (логины без учёта регистра), никто не автор, не меньше двух групп.
func checkApprovals(a Approvals) error {
	bad := func(format string, args ...any) error {
		return &Error{Class: "approvals", Msg: fmt.Sprintf(format, args...)}
	}
	logins, groups := map[string]bool{}, map[string]bool{}
	for _, x := range a.Approvers {
		l := strings.ToLower(x.Login)
		switch {
		case l == strings.ToLower(a.Author):
			return bad("одобривший %s — автор PR", x.Login)
		case logins[l]:
			return bad("одобривший %s указан дважды", x.Login)
		}
		logins[l] = true
		groups[x.Group] = true
	}
	if len(logins) < minApprovers {
		return bad("одобрений %d, нужно не меньше %d", len(logins), minApprovers)
	}
	if len(groups) < minGroups {
		return bad("групп %d, нужно не меньше %d", len(groups), minGroups)
	}
	return nil
}

// Matches сверяет bundle с содержимым c (встроенным в бинарь или взятым с диска). Расхождение — ошибка mismatch
// с первыми отличиями.
func (v *Verified) Matches(c Content) error {
	have := Content{Files: v.Manifest.Files, PolicyDigest: v.Manifest.Digests[DigestPolicy],
		CatalogDigest: v.Manifest.Digests[DigestCatalog], LLMAssetsDigest: v.Manifest.Digests[DigestLLM]}
	diffs := c.Diff(have)
	if len(diffs) == 0 {
		return nil
	}
	more := ""
	if len(diffs) > maxDiffs {
		more = fmt.Sprintf(" (и ещё %d)", len(diffs)-maxDiffs)
		diffs = diffs[:maxDiffs]
	}
	return &Error{Class: "mismatch", Msg: "содержимое не совпадает с подписанным: " + strings.Join(diffs, "; ") + more}
}
