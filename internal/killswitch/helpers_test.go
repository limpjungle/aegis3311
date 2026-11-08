package killswitch

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// tkeys — набор тестовых ключей: oncall a, b, c и renewer r1, r2.
type tkeys struct {
	ring    Keyring
	signers map[string]*audit.Ed25519Signer
}

func newTKeys(t testing.TB) *tkeys {
	t.Helper()
	dir := t.TempDir()
	tk := &tkeys{signers: map[string]*audit.Ed25519Signer{}}
	var specs []KeySpec
	for _, n := range []struct {
		name string
		role Role
	}{{"a", RoleOncall}, {"b", RoleOncall}, {"c", RoleOncall}, {"r1", RoleRenewer}, {"r2", RoleRenewer}} {
		priv, pub := filepath.Join(dir, n.name+".pem"), filepath.Join(dir, n.name+".pub.pem")
		if _, err := audit.GenerateKey(priv, pub); err != nil {
			t.Fatal(err)
		}
		sg, err := audit.LoadPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		tk.signers[n.name] = sg
		specs = append(specs, KeySpec{Path: pub, Issuer: "i-" + n.name, Role: n.role})
	}
	ring, err := LoadKeyring(specs)
	if err != nil {
		t.Fatal(err)
	}
	tk.ring = ring
	return tk
}

// doc подписывает документ ключами names.
func (tk *tkeys) doc(t testing.TB, global bool, clusters, actions []string, issuedAt time.Time, ttl time.Duration, names ...string) []byte {
	t.Helper()
	d := Document{Schema: DocSchema, Global: global, Clusters: append([]string{}, clusters...), Actions: append([]string{}, actions...),
		IssuedAt: issuedAt.UTC().Format("2006-01-02T15:04:05.000Z"), TTL: ttl.String(), Issuer: "test", Signatures: []Signature{}}
	for _, n := range names {
		sig, err := SignatureFor(d, tk.signers[n], "i-"+n)
		if err != nil {
			t.Fatal(err)
		}
		if d, err = AddSignature(d, sig); err != nil {
			t.Fatal(err)
		}
	}
	return Marshal(d)
}

func (tk *tkeys) parse(t testing.TB, raw []byte) *Verified {
	t.Helper()
	v, err := Parse(raw, tk.ring, ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return &v
}

var t0 = time.Date(2026, 11, 8, 10, 0, 0, 0, time.UTC)
