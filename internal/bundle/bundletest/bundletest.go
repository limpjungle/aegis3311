// Package bundletest — тестовый подписанный policy bundle для тестов потребителей (intake): временный ключ,
// манифест от встроенного содержимого с двумя фиктивными одобрившими из разных групп.
package bundletest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/bundle"
)

// Issuer — issuer тестового ключа подписи.
const Issuer = "ci/policy-signing"

// Commit — коммит тестового bundle.
const Commit = "0123456789abcdef0123456789abcdef01234567"

// Manifest — неподписанный манифест от встроенного содержимого: sequence 1, одобрили bob (policy-owners) и carol (security).
func Manifest(t testing.TB) bundle.Manifest {
	t.Helper()
	c, err := bundle.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return bundle.Manifest{Schema: bundle.Schema, Sequence: 1, Repository: "example/aegis", Commit: Commit,
		IssuedAt: "2026-01-02T03:04:05Z", Files: c.Files, Digests: c.Digests(),
		Approvals: bundle.Approvals{PR: 7, Author: "alice", HeadSHA: "89abcdef0123456789abcdef0123456789abcdef",
			Approvers: []bundle.Approver{{Login: "bob", Group: "policy-owners", ReviewID: 11}, {Login: "carol", Group: "security", ReviewID: 12}}},
		Signatures: []bundle.Signature{}}
}

// Key создаёт пару ключей в dir и возвращает подписанта и запись для keyring.
func Key(t testing.TB, dir, name string) (*audit.Ed25519Signer, bundle.KeySpec) {
	t.Helper()
	priv, pub := filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	if _, err := audit.GenerateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	s, err := audit.LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, bundle.KeySpec{Path: pub, Issuer: Issuer}
}

// Write создаёт ключ и подписанный bundle от встроенного содержимого; возвращает путь к bundle и keyring-спецификацию.
func Write(t testing.TB, dir string) (bundlePath string, keys []bundle.KeySpec) {
	t.Helper()
	s, spec := Key(t, dir, "policy-ci")
	m, err := bundle.Sign(Manifest(t), s, Issuer)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath = filepath.Join(dir, "policy-bundle.json")
	if err := os.WriteFile(bundlePath, bundle.Marshal(m), 0o600); err != nil {
		t.Fatal(err)
	}
	return bundlePath, []bundle.KeySpec{spec}
}

// Signer читает приватный ключ, созданный Key.
func Signer(t testing.TB, dir, name string) *audit.Ed25519Signer {
	t.Helper()
	s, err := audit.LoadPrivateKey(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
