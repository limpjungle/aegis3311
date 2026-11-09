package bundle_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/bundle"
	"github.com/limpjungle/aegis3311/internal/bundle/bundletest"
	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/foureyes"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/policy"
)

func TestEmbeddedDigestsMatchAgent(t *testing.T) {
	c, err := bundle.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policyengine.Load(context.Background(), policy.FS)
	if err != nil {
		t.Fatal(err)
	}
	if c.PolicyDigest != eng.Digest() {
		t.Errorf("policy_bundle_digest %s != Engine.Digest %s", c.PolicyDigest, eng.Digest())
	}
	if want := catalog.MustLoadEmbedded().Digest(); c.CatalogDigest != want {
		t.Errorf("catalog_digest %s != Catalog.Digest %s", c.CatalogDigest, want)
	}
	if c.LLMAssetsDigest == "" || len(c.Files) == 0 {
		t.Error("llm_assets_digest или файлы пусты")
	}
}

func TestFromDirEqualsEmbedded(t *testing.T) {
	emb, err := bundle.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := bundle.FromDir("../..")
	if err != nil {
		t.Fatal(err)
	}
	if d := emb.Diff(dir); len(d) != 0 {
		t.Errorf("файлы на диске отличаются от встроенных: %v", d)
	}
	if len(emb.Files) != len(dir.Files) {
		t.Errorf("файлов %d и %d", len(emb.Files), len(dir.Files))
	}
}

// Каждый файл bundle защищён правилом four-eyes.json: иначе его можно изменить без четырёх глаз.
func TestBundleFilesAreProtected(t *testing.T) {
	raw, err := os.ReadFile("../../.github/four-eyes.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := foureyes.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	emb, _ := bundle.Embedded()
	for _, f := range emb.Files {
		if _, ok := rules.Match(f.Path); !ok {
			t.Errorf("файл bundle %s не защищён four-eyes.json", f.Path)
		}
	}
}

type fixture struct {
	keyring bundle.Keyring
	spec    bundle.KeySpec
	signed  bundle.Manifest
	raw     []byte
	dir     string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	s, spec := bundletest.Key(t, dir, "k1")
	kr, err := bundle.LoadKeyring([]bundle.KeySpec{spec})
	if err != nil {
		t.Fatal(err)
	}
	m, err := bundle.Sign(bundletest.Manifest(t), s, bundletest.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{keyring: kr, spec: spec, signed: m, raw: bundle.Marshal(m), dir: dir}
}

func wantClass(t *testing.T, err error, class string) {
	t.Helper()
	var be *bundle.Error
	if !errors.As(err, &be) || be.Class != class {
		t.Fatalf("ошибка %v, ожидался класс %s", err, class)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	f := newFixture(t)
	v, err := bundle.Verify(f.raw, f.keyring)
	if err != nil {
		t.Fatal(err)
	}
	emb, _ := bundle.Embedded()
	if err := v.Matches(emb); err != nil {
		t.Fatal(err)
	}
	if len(v.Signers) != 1 || v.Manifest.Sequence != 1 {
		t.Errorf("signers %v sequence %d", v.Signers, v.Manifest.Sequence)
	}
	// Канонизация стабильна: повторная сериализация даёт те же байты, подписи не влияют на подписываемое.
	if !bytes.Equal(bundle.Marshal(v.Manifest), f.raw) {
		t.Error("Marshal(Verify(b)) != b")
	}
	if !bytes.Equal(bundle.ContentBytes(v.Manifest), bundle.ContentBytes(bundletest.Manifest(t))) {
		t.Error("ContentBytes зависит от подписей")
	}
	if bytes.Contains(bundle.ContentBytes(f.signed), []byte("signatures")) {
		t.Error("ContentBytes содержит подписи")
	}
}

func TestSignRejectsDuplicateKey(t *testing.T) {
	dir := t.TempDir()
	s, _ := bundletest.Key(t, dir, "k")
	m, _ := bundle.Sign(bundletest.Manifest(t), s, bundletest.Issuer)
	if _, err := bundle.Sign(m, s, bundletest.Issuer); err == nil {
		t.Error("повторная подпись тем же ключом должна быть отказом")
	}
}

func TestVerifyRejectsUnsigned(t *testing.T) {
	f := newFixture(t)
	_, err := bundle.Verify(bundle.Marshal(bundletest.Manifest(t)), f.keyring)
	wantClass(t, err, "unsigned")
}

func TestVerifyUnknownKey(t *testing.T) {
	f := newFixture(t)
	other, err := bundle.LoadKeyring(func() []bundle.KeySpec { _, sp := bundletest.Key(t, t.TempDir(), "x"); return []bundle.KeySpec{sp} }())
	if err != nil {
		t.Fatal(err)
	}
	_, err = bundle.Verify(f.raw, other)
	wantClass(t, err, "unknown_key")
}

func TestVerifyTampering(t *testing.T) {
	f := newFixture(t)
	for name, mut := range map[string]func(*bundle.Manifest){
		"файл":      func(m *bundle.Manifest) { m.Files[0].SHA256 = strings.Repeat("a", 64) },
		"одобрение": func(m *bundle.Manifest) { m.Approvals.Approvers[0].Login = "mallory" },
		"sequence":  func(m *bundle.Manifest) { m.Sequence = 5; p := strings.Repeat("b", 40); m.PrevCommit = &p },
		"дайджест":  func(m *bundle.Manifest) { m.Digests[bundle.DigestPolicy] = "sha256:" + strings.Repeat("c", 64) },
		"commit":    func(m *bundle.Manifest) { m.Commit = strings.Repeat("d", 40) },
	} {
		t.Run(name, func(t *testing.T) {
			m := f.signed
			m.Files = append([]bundle.File(nil), m.Files...)
			m.Approvals.Approvers = append([]bundle.Approver(nil), m.Approvals.Approvers...)
			m.Digests = map[string]string{}
			for k, v := range f.signed.Digests {
				m.Digests[k] = v
			}
			mut(&m)
			_, err := bundle.Verify(bundle.Marshal(m), f.keyring)
			wantClass(t, err, "bad_signature")
		})
	}
}

func TestVerifyTaintedBundleRejected(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	s2, spec2 := bundletest.Key(t, dir, "k2")
	spec2.Issuer = "ci/second"
	kr, err := bundle.LoadKeyring([]bundle.KeySpec{f.spec, spec2})
	if err != nil {
		t.Fatal(err)
	}
	// Валидная подпись + испорченная подпись второго ключа: bundle отвергается целиком.
	bad := f.signed
	bad.Signatures = append(append([]bundle.Signature(nil), f.signed.Signatures...),
		bundle.Signature{KeyID: s2.KeyID(), Issuer: "ci/second", Sig: f.signed.Signatures[0].Sig})
	_, err = bundle.Verify(bundle.Marshal(bad), kr)
	wantClass(t, err, "bad_signature")
	// Валидная подпись + подпись неизвестного ключа.
	_, err = bundle.Verify(bundle.Marshal(bad), f.keyring)
	wantClass(t, err, "unknown_key")
	// Обе валидны — принимается.
	two, err := bundle.Sign(f.signed, s2, "ci/second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundle.Verify(bundle.Marshal(two), kr); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyForeignIssuer(t *testing.T) {
	f := newFixture(t)
	// Подпись тем же ключом, но под другим issuer'ом: в keyring ключ привязан к issuer'у.
	m, err := bundle.Sign(bundletest.Manifest(t), bundletest.Signer(t, f.dir, "k1"), "ci/other-issuer")
	if err != nil {
		t.Fatal(err)
	}
	_, err = bundle.Verify(bundle.Marshal(m), f.keyring)
	wantClass(t, err, "bad_signature")
}

// RT-11 в автотестах: одно одобрение, автор среди одобривших, одна группа, повтор логина в другом регистре.
func TestVerifyApprovals(t *testing.T) {
	dir := t.TempDir()
	s, spec := bundletest.Key(t, dir, "k")
	kr, _ := bundle.LoadKeyring([]bundle.KeySpec{spec})
	ap := func(login, group string, id int64) bundle.Approver {
		return bundle.Approver{Login: login, Group: group, ReviewID: id}
	}
	cases := map[string][]bundle.Approver{
		"одно одобрение":          {ap("bob", "policy-owners", 1)},
		"автор среди одобривших":  {ap("bob", "policy-owners", 1), ap("alice", "security", 2)},
		"автор в другом регистре": {ap("bob", "policy-owners", 1), ap("ALICE", "security", 2)},
		"одна группа":             {ap("bob", "security", 1), ap("carol", "security", 2)},
		"повтор логина":           {ap("bob", "policy-owners", 1), ap("BOB", "security", 2)},
		"нет одобрений":           {},
	}
	for name, approvers := range cases {
		t.Run(name, func(t *testing.T) {
			m := bundletest.Manifest(t)
			m.Approvals.Approvers = approvers
			m, err := bundle.Sign(m, s, bundletest.Issuer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = bundle.Verify(bundle.Marshal(m), kr)
			wantClass(t, err, "approvals")
		})
	}
}

func TestVerifyMalformed(t *testing.T) {
	f := newFixture(t)
	s := string(f.raw)
	_, err := bundle.Verify([]byte(strings.Replace(s, `{"approvals"`, `{"extra":1,"approvals"`, 1)), f.keyring)
	wantClass(t, err, "invalid")
	_, err = bundle.Verify([]byte(strings.Replace(s, `"files":[`, `"files":null,"x":[`, 1)), f.keyring)
	wantClass(t, err, "invalid")
	_, err = bundle.Verify([]byte(`{"schema":"aegisops/policy-bundle/v1","files":null,"digests":null,"signatures":null}`), f.keyring)
	wantClass(t, err, "invalid")
	_, err = bundle.Verify(append(bytes.Repeat([]byte(" "), bundle.MaxBytes), f.raw...), f.keyring)
	wantClass(t, err, "oversize")
	_, err = bundle.Verify([]byte(`{"schema":"x","schema":"y"}`), f.keyring)
	wantClass(t, err, "invalid") // дубль ключа
	_, err = bundle.Verify([]byte(`not json`), f.keyring)
	wantClass(t, err, "invalid")
}

func TestVerifyStructure(t *testing.T) {
	s, spec := bundletest.Key(t, t.TempDir(), "k")
	kr, _ := bundle.LoadKeyring([]bundle.KeySpec{spec})
	prev := strings.Repeat("e", 40)
	for name, mut := range map[string]func(*bundle.Manifest){
		"схема":               func(m *bundle.Manifest) { m.Schema = "x" },
		"sequence 0":          func(m *bundle.Manifest) { m.Sequence = 0 },
		"prev при sequence 1": func(m *bundle.Manifest) { m.PrevCommit = &prev },
		"нет prev при seq 2":  func(m *bundle.Manifest) { m.Sequence = 2 },
		"короткий commit":     func(m *bundle.Manifest) { m.Commit = "abc" },
		"время не UTC":        func(m *bundle.Manifest) { m.IssuedAt = "2026-01-02T03:04:05+03:00" },
		"файлы не по порядку": func(m *bundle.Manifest) { m.Files[0], m.Files[1] = m.Files[1], m.Files[0] },
		"повтор файла":        func(m *bundle.Manifest) { m.Files[1] = m.Files[0] },
		"путь с ..":           func(m *bundle.Manifest) { m.Files[0].Path = "../x" },
		"head_sha":            func(m *bundle.Manifest) { m.Approvals.HeadSHA = "zz" },
		"лишний дайджест":     func(m *bundle.Manifest) { m.Digests["x"] = m.Digests[bundle.DigestPolicy] },
		"плохой дайджест":     func(m *bundle.Manifest) { m.Digests[bundle.DigestCatalog] = "md5:1" },
	} {
		t.Run(name, func(t *testing.T) {
			m := bundletest.Manifest(t)
			m.Files = append([]bundle.File(nil), m.Files...)
			m.Digests = map[string]string{}
			for k, v := range bundletest.Manifest(t).Digests {
				m.Digests[k] = v
			}
			mut(&m)
			m, err := bundle.Sign(m, s, bundletest.Issuer)
			if err != nil {
				t.Fatal(err)
			}
			_, err = bundle.Verify(bundle.Marshal(m), kr)
			wantClass(t, err, "invalid")
		})
	}
}

func TestMatchesMismatch(t *testing.T) {
	f := newFixture(t)
	v, err := bundle.Verify(f.raw, f.keyring)
	if err != nil {
		t.Fatal(err)
	}
	emb, _ := bundle.Embedded()
	changed := emb
	changed.Files = append([]bundle.File(nil), emb.Files...)
	changed.Files[0].SHA256 = strings.Repeat("0", 64)
	err = v.Matches(changed)
	wantClass(t, err, "mismatch")
	if !strings.Contains(err.Error(), changed.Files[0].Path) {
		t.Errorf("ошибка не называет файл: %v", err)
	}
	changed = emb
	changed.PolicyDigest = "sha256:" + strings.Repeat("1", 64)
	wantClass(t, v.Matches(changed), "mismatch")
	// Лишний и отсутствующий файлы.
	changed = emb
	changed.Files = append(append([]bundle.File(nil), emb.Files...), bundle.File{Path: "policy/aegis/x/new.rego", SHA256: strings.Repeat("2", 64)})
	wantClass(t, v.Matches(changed), "mismatch")
	changed.Files = emb.Files[1:]
	wantClass(t, v.Matches(changed), "mismatch")
}

func TestLoadKeyring(t *testing.T) {
	if _, err := bundle.LoadKeyring(nil); err == nil {
		t.Error("пустой список ключей должен быть ошибкой")
	}
	dir := t.TempDir()
	_, a := bundletest.Key(t, dir, "a")
	_, b := bundletest.Key(t, dir, "b")
	if _, err := bundle.LoadKeyring([]bundle.KeySpec{a, b}); err == nil {
		t.Error("повтор issuer должен быть ошибкой")
	}
	b.Issuer = "ci/b"
	if _, err := bundle.LoadKeyring([]bundle.KeySpec{a, b}); err != nil {
		t.Error(err)
	}
	if _, err := bundle.LoadKeyring([]bundle.KeySpec{a, {Path: a.Path, Issuer: "ci/c"}}); err == nil {
		t.Error("повтор ключа должен быть ошибкой")
	}
	if _, err := bundle.LoadKeyring([]bundle.KeySpec{{Path: a.Path, Issuer: "bad issuer"}}); err == nil {
		t.Error("некорректный issuer должен быть ошибкой")
	}
}
