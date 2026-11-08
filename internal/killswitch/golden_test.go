package killswitch

import (
	"crypto/ed25519"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// Золотой тест формата: фиксированный seed, фиксированные канонические байты и подпись. Ed25519 детерминирован,
// поэтому любое изменение сообщения подписи, канонизации или key_id ломает тест (и ломает совместимость с развёрнутыми intake).
func goldenSigner() *audit.Ed25519Signer {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	return audit.NewEd25519Signer(ed25519.NewKeyFromSeed(seed))
}

const (
	goldenKeyID   = "ed25519:56475aa75463474c"
	goldenContent = `{"actions":["workload.restart"],"clusters":["prod-eu-1"],"global":true,"issued_at":"2026-11-08T10:00:00.000Z","issuer":"oncall-ivanov","schema":"aegisops/kill-switch/v1","ttl":"6h0m0s"}`
	goldenSig     = "9aHji2AJmRPVS6DukWmSf0B48GIfTsXFO6F6rq3VTSCi+nPFKNQggmnMATFAOCsIYjGmnTzZOwytP5Mrx1y5AA=="
)

func TestGoldenDocument(t *testing.T) {
	sg := goldenSigner()
	d := Document{Schema: DocSchema, Global: true, Clusters: []string{"prod-eu-1"}, Actions: []string{"workload.restart"},
		IssuedAt: "2026-11-08T10:00:00.000Z", TTL: "6h0m0s", Issuer: "oncall-ivanov", Signatures: []Signature{}}
	if sg.KeyID() != goldenKeyID {
		t.Errorf("key_id %q", sg.KeyID())
	}
	c, _ := Content(d)
	if string(c) != goldenContent {
		t.Errorf("content:\n%s", c)
	}
	sig, err := SignatureFor(d, sg, "oncall-ivanov")
	if err != nil {
		t.Fatal(err)
	}
	if sig.Sig != goldenSig {
		t.Errorf("sig %q", sig.Sig)
	}
	// сообщение подписи по плану
	if m := string(sigMessage(c, sg.KeyID(), "oncall-ivanov")); m != "aegisops/kill-switch/v1\x00"+string(c)+"\x00"+sg.KeyID()+"\x00oncall-ivanov" {
		t.Errorf("сообщение подписи: %q", m)
	}
}

// Золотой документ парсится и засчитывается с keyring из этого seed (+ второй ключ).
func TestGoldenDocumentParses(t *testing.T) {
	tk := newTKeys(t)
	sg := goldenSigner()
	tk.ring[sg.KeyID()] = Key{Pub: sg.Public(), Issuer: "oncall-ivanov", Role: RoleOncall}
	d := Document{Schema: DocSchema, Global: true, Clusters: []string{"prod-eu-1"}, Actions: []string{"workload.restart"},
		IssuedAt: "2026-11-08T10:00:00.000Z", TTL: "6h0m0s", Issuer: "oncall-ivanov", Signatures: []Signature{{KeyID: sg.KeyID(), Issuer: "oncall-ivanov", Sig: goldenSig}}}
	v, err := Parse(Marshal(d), tk.ring, ParseOptions{})
	if err != nil || len(v.Valid) != 1 || v.Tainted {
		t.Fatalf("%v %+v", err, v)
	}
}
