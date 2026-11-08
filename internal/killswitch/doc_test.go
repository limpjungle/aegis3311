package killswitch

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseThresholds(t *testing.T) {
	tk := newTKeys(t)
	cases := []struct {
		name    string
		raw     []byte
		stop    bool
		confirm string
		tainted bool
	}{
		{"stop одной подписью", tk.doc(t, true, nil, nil, t0, time.Hour, "a"), true, "none", false},
		{"run одной oncall", tk.doc(t, false, nil, nil, t0, time.Hour, "a"), false, "none", false},
		{"run двумя oncall", tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"), false, "oncall", false},
		{"oncall и renewer", tk.doc(t, false, nil, nil, t0, time.Hour, "a", "r1"), false, "renewer", false},
		{"два renewer", tk.doc(t, false, nil, nil, t0, time.Hour, "r1", "r2"), false, "renewer", false},
		{"actions двумя oncall", tk.doc(t, false, nil, []string{"workload.restart"}, t0, time.Hour, "a", "b"), false, "oncall", false},
	}
	for _, c := range cases {
		v, err := Parse(c.raw, tk.ring, ParseOptions{})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if v.Doc.Global != c.stop || v.Confirmation("c1") != c.confirm || v.Tainted != c.tainted {
			t.Errorf("%s: global=%v confirm=%s tainted=%v", c.name, v.Doc.Global, v.Confirmation("c1"), v.Tainted)
		}
	}
}

func TestParseOrderIndependentBytes(t *testing.T) {
	tk := newTKeys(t)
	ab := tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b")
	ba := tk.doc(t, false, nil, nil, t0, time.Hour, "b", "a")
	if !bytes.Equal(ab, ba) {
		t.Error("порядок подписей меняет байты")
	}
	// пробелы и перестановка ключей в сыром JSON не ломают разбор и не меняют sha
	spaced := bytes.ReplaceAll(ab, []byte(`,"`), []byte(", \n\""))
	v1, v2 := tk.parse(t, ab), tk.parse(t, spaced)
	if v1.SHA256 != v2.SHA256 || v1.ContentSHA256 != v2.ContentSHA256 {
		t.Error("sha зависит от форматирования")
	}
}

func TestParseTaintedAndClasses(t *testing.T) {
	tk := newTKeys(t)
	good := tk.doc(t, true, nil, nil, t0, time.Hour, "a")
	// подмена global после подписи
	forged := bytes.Replace(good, []byte(`"global":true`), []byte(`"global":false`), 1)
	assertClass := func(name string, raw []byte, class string) {
		t.Helper()
		_, err := Parse(raw, tk.ring, ParseOptions{})
		var de *DocError
		if !errors.As(err, &de) || de.Class != class {
			t.Errorf("%s: %v, ожидается %s", name, err, class)
		}
	}
	assertClass("подмена", forged, "bad_signature")
	assertClass("unsigned", tk.doc(t, true, nil, nil, t0, time.Hour), "unsigned")
	assertClass("ttl 30s", tk.doc(t, true, nil, nil, t0, 30*time.Second, "a"), "invalid")
	assertClass("ttl 25h", tk.doc(t, true, nil, nil, t0, 25*time.Hour, "a"), "invalid")
	assertClass("null-массив", []byte(strings.Replace(string(good), `"actions":[]`, `"actions":null`, 1)), "invalid")
	assertClass("oversize", bytes.Repeat([]byte(" "), MaxDocBytes+1), "oversize")
	assertClass("не-UTC", []byte(strings.Replace(string(good), `.000Z`, `.000+03:00`, 1)), "invalid")
	other := newTKeys(t) // чужие ключи
	assertClass("все незнакомые", other.doc(t, true, nil, nil, t0, time.Hour, "a"), "unknown_key")

	// одна валидная + одна подпись чужого ключа → запятнан, stop сохраняется, подтверждения нет
	d := tk.parse(t, good).Doc
	sig, _ := SignatureFor(d, other.signers["a"], "i-a")
	d2, _ := AddSignature(d, sig)
	v, err := Parse(Marshal(d2), tk.ring, ParseOptions{})
	if err != nil || !v.Tainted || !v.Doc.Global || v.Confirmation("x") != "none" {
		t.Errorf("запятнанный: %+v %v", v, err)
	}
	// issuer подписи не совпадает с keyring
	bad, _ := SignatureFor(d, tk.signers["b"], "i-evil")
	d3, _ := AddSignature(d, bad)
	v, err = Parse(Marshal(d3), tk.ring, ParseOptions{})
	if err != nil || !v.Tainted || len(v.Valid) != 1 {
		t.Errorf("чужой issuer: %+v %v", v, err)
	}
	// один ключ дважды
	dup := d
	dup.Signatures = append(dup.Signatures, dup.Signatures[0])
	assertClass("повтор ключа", Marshal(dup), "invalid")
}

func TestKnownAction(t *testing.T) {
	tk := newTKeys(t)
	raw := tk.doc(t, false, nil, []string{"no.such"}, t0, time.Hour, "a")
	if _, err := Parse(raw, tk.ring, ParseOptions{KnownAction: func(string) bool { return false }}); err == nil {
		t.Error("неизвестное действие принято")
	}
}

func TestLoadKeyringRules(t *testing.T) {
	tk := newTKeys(t)
	_ = tk
	if _, err := LoadKeyring([]KeySpec{{Path: "/nonexistent", Issuer: "x", Role: RoleOncall}}); err == nil {
		t.Error("ключ без файла принят")
	}
}
