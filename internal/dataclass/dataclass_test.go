package dataclass

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/limpjungle/aegis3311/internal/pyjson"
)

func TestClassOrderAndRaise(t *testing.T) {
	all := []Class{Public, Internal, Confidential, Restricted}
	for i, a := range all {
		for j, b := range all {
			if got := Raise(a, b); got < a || got < b {
				t.Errorf("Raise(%v,%v)=%v ниже аргумента", a, b, got)
			}
			if (Max(a, b) == a) != (i >= j) {
				t.Errorf("Max(%v,%v)", a, b)
			}
		}
		txt, err := a.MarshalText()
		var back Class
		if err != nil || back.UnmarshalText(txt) != nil || back != a {
			t.Errorf("round-trip %v", a)
		}
		if p, err := ParseClass(a.String()); err != nil || p != a {
			t.Errorf("ParseClass(%q)", a)
		}
	}
	for _, s := range []string{"", "Internal", "secret"} {
		if _, err := ParseClass(s); err == nil {
			t.Errorf("ParseClass(%q) принят", s)
		}
	}
	if Class(0).String() != "invalid" {
		t.Error("класс 0")
	}
	if _, err := Class(0).MarshalText(); err == nil {
		t.Error("MarshalText(0) принят")
	}
}

func TestRegistry(t *testing.T) {
	r := MVPRegistry()
	want := map[string]Class{"metrics.prometheus": Internal, "alerts.alertmanager": Internal, "logs.loki": Confidential, "logs.clickhouse": Confidential,
		"traces.tempo": Confidential, "payload.ebpf": Restricted, "payload.http_body": Restricted, "db.pg_stat_activity": Restricted,
		"db.pg_slow_log": Restricted, "db.pg_stat_statements": Confidential, "code.source": Confidential, "code.pr": Confidential,
		"tickets": Confidential, "postmortems": Confidential, "manifests.k8s": Internal, "k8s.events": Internal, "k8s.deploys": Internal,
		"k8s.rollout_status": Internal, "platform.topology": Internal, "platform.action_catalog": Internal, "db.aggregates": Internal, "kb.runbooks": Internal}
	for id, c := range want {
		if s, ok := r.Lookup(id); !ok || s.Class != c {
			t.Errorf("%s: %v %v", id, s.Class, ok)
		}
	}
	if s, ok := r.Lookup("nope"); ok || s.Class != Restricted {
		t.Errorf("неизвестный источник: %+v %v", s, ok)
	}
	for _, bad := range [][]Source{
		{{ID: "a", Class: Internal}, {ID: "a", Class: Internal}}, {{ID: "", Class: Internal}}, {{ID: "A", Class: Internal}}, {{ID: "a"}},
		{{ID: "a", Class: Confidential, ExternalConfidential: true}}, {{ID: "a", Class: Internal, ExternalConfidential: true}},
	} {
		if _, err := NewRegistry(bad); err == nil {
			t.Errorf("принят %+v", bad)
		}
	}
}

func TestExternalAllowed(t *testing.T) {
	for _, pd := range []bool{false, true} {
		for _, ec := range []bool{false, true} {
			s := Source{MayContainPersonalDataRU: pd, ExternalConfidential: ec}
			for _, c := range []Class{Public, Internal, Confidential, Restricted} {
				want := (c == Public || c == Internal) && !pd
				if got := ExternalAllowed(s, c); got != want {
					t.Errorf("pd=%v ec=%v %v: %v", pd, ec, c, got)
				}
			}
		}
	}
}

func TestEscalate(t *testing.T) {
	cases := []struct {
		name string
		rep  MaskReport
		want Class
		why  string
	}{
		{"пусто", MaskReport{}, Internal, ""},
		{"failed", MaskReport{Failed: true}, Restricted, "masker_failure"},
		{"removed<0", MaskReport{Removed: -1}, Restricted, "masker_failure"},
		{"count<0", MaskReport{Findings: []Finding{{CategorySecret, -1}}}, Restricted, "masker_failure"},
		{"pd", MaskReport{Findings: []Finding{{CategoryPersonal, 2}}}, Restricted, "personal_data"},
		{"pd count 0", MaskReport{Findings: []Finding{{CategoryPersonal, 0}}}, Internal, ""},
		{"secret", MaskReport{Findings: []Finding{{CategorySecret, 3}}, Removed: 3}, Internal, ""},
		{"unknown", MaskReport{Findings: []Finding{{"x", 1}}}, Restricted, "unknown_category"},
	}
	for _, c := range cases {
		got, why := Escalate(Internal, c.rep)
		if got != c.want || why != c.why {
			t.Errorf("%s: %v %q", c.name, got, why)
		}
		if g, _ := Escalate(Confidential, c.rep); g < Confidential {
			t.Errorf("%s: ниже base", c.name)
		}
	}
}

func parse(t *testing.T, s string) *pyjson.Value {
	t.Helper()
	v, err := pyjson.Parse([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestFilterSeries(t *testing.T) {
	p := MVPLabelPolicy()
	in := parse(t, `{"name":"m","labels":{"service":"cart-svc","user":"x","pod":"Bad Pod","limit_mb":512,"source":"self_reported","cluster":"c1"},"values":[1,2]}`)
	before := pyjson.Marshal(in, pyjson.Canonical)
	out, dropped, err := p.FilterSeries(in)
	if err != nil || dropped != 3 {
		t.Fatalf("%v %d", err, dropped)
	}
	if got := string(pyjson.Marshal(out, pyjson.PyDefault)); got != `{"name": "m", "labels": {"service": "cart-svc", "source": "self_reported", "cluster": "c1"}, "values": [1, 2]}` {
		t.Errorf("результат: %s", got)
	}
	if !bytes.Equal(before, pyjson.Marshal(in, pyjson.Canonical)) {
		t.Error("вход изменён")
	}
	if _, _, err := p.FilterSeries(parse(t, `{"labels":[]}`)); err == nil {
		t.Error("labels не объект принят")
	}
	if _, _, err := p.FilterSeries(parse(t, `[]`)); err == nil {
		t.Error("серия не объект принята")
	}
	if o, d, err := p.FilterSeries(parse(t, `{"name":"m"}`)); err != nil || d != 0 || o.Get("labels") != nil {
		t.Error("серия без labels")
	}
}

// На сериях probe-v3 фильтр не удаляет ни одной метки.
func TestFilterSeriesProbeV3(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "eval", "golden-synthetic", "data", "probe-v3.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	p, n := MVPLabelPolicy(), 0
	for _, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		c, err := pyjson.Parse(ln)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range c.Get("input").Get("metrics").Items {
			n++
			if _, d, err := p.FilterSeries(s); err != nil || d != 0 {
				t.Fatalf("%s: dropped=%d err=%v", c.Get("id").S, d, err)
			}
		}
	}
	if n == 0 {
		t.Fatal("серий нет")
	}
}
