package intake

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

type fakeAnchor struct{ st audit.AnchorStatus }

func (f fakeAnchor) Status() audit.AnchorStatus { return f.st }

func sample(body, name string) (string, bool) {
	for _, l := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(l, name+" "); ok {
			return v, true
		}
	}
	return "", false
}

var anchorSeries = []string{
	"aegis_intake_audit_anchor_enabled", "aegis_intake_audit_anchor_seq", "aegis_intake_audit_anchor_lag_seconds",
	"aegis_intake_audit_anchor_last_success_timestamp_seconds", "aegis_intake_audit_anchor_errors_total",
}

func TestAnchorSeriesPresentWhenDisabled(t *testing.T) {
	m, _ := testMetrics(t, nil)
	for _, n := range []string{"", "x"} { // и с chain, и без наблюдателей
		if n == "x" {
			m = NewMetrics("c", nil, nil, nil, nil, nil)
		}
		b, err := m.Render()
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range anchorSeries {
			v, ok := sample(string(b), s)
			if !ok {
				t.Errorf("нет ряда %s при выключенном anchor", s)
			} else if v != "0" {
				t.Errorf("%s = %s, ожидалось 0", s, v)
			}
			if !strings.Contains(string(b), "# TYPE "+s+" ") || !strings.Contains(string(b), "# HELP "+s+" ") {
				t.Errorf("нет HELP/TYPE %s", s)
			}
		}
	}
}

func TestAnchorSeriesValues(t *testing.T) {
	m, _ := testMetrics(t, nil)
	m.Anchor = fakeAnchor{audit.AnchorStatus{AnchoredSeq: 40, HeadSeq: 42, LastSuccess: time.Unix(1_700_000_050, 0),
		Errors: 3, Lag: 90 * time.Second, Lagging: false, LastError: "http_503"}}
	b, err := m.Render()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"aegis_intake_audit_anchor_enabled": "1", "aegis_intake_audit_anchor_seq": "40", "aegis_intake_audit_anchor_lag_seconds": "90",
		"aegis_intake_audit_anchor_last_success_timestamp_seconds": "1700000050", "aegis_intake_audit_anchor_errors_total": "3",
	}
	for n, w := range want {
		v, ok := sample(string(b), n)
		got, err := strconv.ParseFloat(v, 64)
		wf, _ := strconv.ParseFloat(w, 64)
		if !ok || err != nil || got != wf {
			t.Errorf("%s = %q (есть=%v), ожидалось %s", n, v, ok, w)
		}
	}
	if strings.Contains(string(b), "http_503") {
		t.Error("текст ошибки не должен попадать в метрики")
	}
	if !strings.Contains(string(b), "# TYPE aegis_intake_audit_anchor_errors_total counter") {
		t.Error("errors_total должен быть counter")
	}
}
