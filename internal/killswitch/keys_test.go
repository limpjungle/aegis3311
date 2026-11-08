package killswitch

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
)

func genPub(t *testing.T, dir, name string) string {
	t.Helper()
	priv, pub := filepath.Join(dir, name+".pem"), filepath.Join(dir, name+".pub.pem")
	if _, err := audit.GenerateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestLoadKeyringRulesFull(t *testing.T) {
	dir := t.TempDir()
	o1, o2, o3 := genPub(t, dir, "o1"), genPub(t, dir, "o2"), genPub(t, dir, "o3")
	r1, r2 := genPub(t, dir, "r1"), genPub(t, dir, "r2")
	on := func(p, iss string) KeySpec { return KeySpec{Path: p, Issuer: iss, Role: RoleOncall} }
	rn := func(p, iss string) KeySpec { return KeySpec{Path: p, Issuer: iss, Role: RoleRenewer} }
	cases := []struct {
		name  string
		specs []KeySpec
		err   string // "" — успех
	}{
		{"два oncall без renewer", []KeySpec{on(o1, "a"), on(o2, "b")}, ""},
		{"два oncall и два renewer", []KeySpec{on(o1, "a"), on(o2, "b"), rn(r1, "r1"), rn(r2, "r2")}, ""},
		{"пусто", nil, "oncall"},
		{"один oncall", []KeySpec{on(o1, "a")}, "oncall"},
		{"один oncall и два renewer", []KeySpec{on(o1, "a"), rn(r1, "r1"), rn(r2, "r2")}, "oncall"},
		{"ровно один renewer", []KeySpec{on(o1, "a"), on(o2, "b"), rn(r1, "r1")}, "renewer"},
		{"повтор key_id", []KeySpec{on(o1, "a"), on(o1, "b")}, "повторяется"},
		{"повтор key_id в разных ролях", []KeySpec{on(o1, "a"), on(o2, "b"), rn(o1, "c"), rn(r2, "d")}, "повторяется"},
		{"повтор issuer", []KeySpec{on(o1, "a"), on(o2, "a")}, "issuer"},
		{"повтор issuer oncall и renewer", []KeySpec{on(o1, "a"), on(o2, "b"), rn(r1, "a"), rn(r2, "r2")}, "issuer"},
		{"неизвестная роль", []KeySpec{on(o1, "a"), on(o2, "b"), {Path: o3, Issuer: "c", Role: "admin"}}, "роль"},
		{"пустая роль", []KeySpec{on(o1, "a"), on(o2, "b"), {Path: o3, Issuer: "c"}}, "роль"},
		{"issuer с пробелом", []KeySpec{on(o1, "a b"), on(o2, "b")}, "issuer"},
		{"пустой issuer", []KeySpec{on(o1, ""), on(o2, "b")}, "issuer"},
		{"issuer с NUL", []KeySpec{on(o1, "a\x00b"), on(o2, "b")}, "issuer"},
	}
	for _, c := range cases {
		k, err := LoadKeyring(c.specs)
		switch {
		case c.err == "" && err != nil:
			t.Errorf("%s: %v", c.name, err)
		case c.err != "" && err == nil:
			t.Errorf("%s: ошибка ожидалась, keyring принят (%d ключей)", c.name, len(k))
		case c.err != "" && !strings.Contains(err.Error(), c.err):
			t.Errorf("%s: ошибка %q не содержит %q", c.name, err, c.err)
		}
	}
	// содержимое: key_id, issuer, роль
	k, err := LoadKeyring([]KeySpec{on(o1, "a"), on(o2, "b")})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := audit.LoadPublicKey(o1)
	if got := k[audit.KeyID(pub)]; got.Issuer != "a" || got.Role != RoleOncall || !got.Pub.Equal(pub) {
		t.Errorf("запись keyring: %+v", got)
	}
}
