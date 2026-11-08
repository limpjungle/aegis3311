package intake

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestTrackerOpenCloseNoReopen(t *testing.T) {
	st, _ := OpenState("")
	known := func(ns, s string) bool { return ns == "shop" && s == "geo-svc" }
	tr := NewTracker("staging", known, 2, 10, st, nil)
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	a := Alert{Fingerprint: "0123456789abcdef", Name: "X", Severity: "critical", Namespace: "shop", Service: "geo-svc", StartsAt: t0.Add(-5 * time.Minute)}
	other := Alert{Fingerprint: "fedcba9876543210", Namespace: "shop", Service: "unknown", StartsAt: t0}
	op, cl, err := tr.Observe(t0, []Alert{a, other})
	if err != nil || len(op) != 1 || len(cl) != 0 || tr.Ignored != 1 {
		t.Fatalf("open: %v %v %v %d", err, op, cl, tr.Ignored)
	}
	id := op[0].ID
	if id != IncidentID(Key{"staging", "shop", "geo-svc"}, a.StartsAt) {
		t.Errorf("ID %s", id)
	}
	// тот же алерт — тот же инцидент; ещё один алерт присоединяется
	b := a
	b.Fingerprint = "aaaaaaaaaaaaaaaa"
	b.StartsAt = t0
	if op, _, _ = tr.Observe(t0.Add(time.Minute), []Alert{a, b}); len(op) != 0 {
		t.Fatal("повторное открытие")
	}
	if inc, _ := st.Get(id); len(inc.Alerts) != 2 {
		t.Errorf("алерты: %v", inc.Alerts)
	}
	// один пустой опрос — ещё не закрытие; два — закрытие
	if _, cl, _ = tr.Observe(t0.Add(2*time.Minute), nil); len(cl) != 0 {
		t.Fatal("закрытие после одного опроса")
	}
	if _, cl, _ = tr.Observe(t0.Add(3*time.Minute), nil); len(cl) != 1 || cl[0].Status != StatusClosing {
		t.Fatalf("закрытие: %v", cl)
	}
	st.Do(func(d *Data) { delete(d.Incidents, id); d.Closed[id] = t0 })
	if op, _, _ = tr.Observe(t0.Add(4*time.Minute), []Alert{a}); len(op) != 0 {
		t.Fatal("закрытый ID открыт снова")
	}
}

func TestStatePersistAndCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	st, err := OpenState(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(p); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("второй владелец: %v", err)
	}
	st.Do(func(d *Data) { d.Incidents["x"] = &Incident{ID: "x", Status: StatusOpen} })
	st.Close()
	st, err = OpenState(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get("x"); !ok {
		t.Fatal("инцидент не сохранился")
	}
	st.Close()
	os.WriteFile(p, []byte(`{"schema":"bad"}`), 0o600)
	if _, err := OpenState(p); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("повреждённый файл: %v", err)
	}
}

// fpN — детерминированный 16-символьный fingerprint.
func fpN(n int) string { return fmt.Sprintf("%016x", n) }

func TestTrimAlerts(t *testing.T) {
	base := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	// mk: fingerprint i получает время base+i секунд (больше i — свежее)
	mk := func(ids ...int) map[string]time.Time {
		m := map[string]time.Time{}
		for _, i := range ids {
			m[fpN(i)] = base.Add(time.Duration(i) * time.Second)
		}
		return m
	}
	keys := func(m map[string]time.Time) []string {
		var ks []string
		for k := range m {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		return ks
	}
	cases := []struct {
		name    string
		m       map[string]time.Time
		keep    string
		limit   int
		removed int
		want    []string
	}{
		{"не больше лимита", mk(1, 2, 3), fpN(1), 3, 0, []string{fpN(1), fpN(2), fpN(3)}},
		{"keep и самые свежие", mk(1, 2, 3, 4, 5), fpN(1), 3, 2, []string{fpN(1), fpN(4), fpN(5)}},
		{"keep отсутствует", mk(1, 2, 3, 4), fpN(99), 2, 2, []string{fpN(3), fpN(4)}},
		{"keep пустой", mk(1, 2, 3), "", 1, 2, []string{fpN(3)}},
		{"keep самый старый сохраняется", mk(1, 2, 3, 4), fpN(1), 2, 2, []string{fpN(1), fpN(4)}},
		{"limit=1 оставляет keep", mk(1, 2, 3), fpN(2), 1, 2, []string{fpN(2)}},
		{"limit=1 без keep — самый свежий", mk(1, 2, 3), fpN(99), 1, 2, []string{fpN(3)}},
		{"пустая карта", map[string]time.Time{}, fpN(1), 1, 0, nil},
		{"nil-карта", nil, fpN(1), 1, 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := trimAlerts(c.m, c.keep, c.limit)
			if got != c.removed {
				t.Errorf("удалено %d, ожидалось %d", got, c.removed)
			}
			if ks := keys(c.m); !reflect.DeepEqual(ks, c.want) {
				t.Errorf("остались %v, ожидалось %v", ks, c.want)
			}
		})
	}
	t.Run("равное время — меньшие fingerprint", func(t *testing.T) {
		m := map[string]time.Time{}
		for i := 1; i <= 6; i++ {
			m[fpN(i)] = base
		}
		if n := trimAlerts(m, fpN(6), 3); n != 3 {
			t.Errorf("удалено %d", n)
		}
		if ks := keys(m); !reflect.DeepEqual(ks, []string{fpN(1), fpN(2), fpN(6)}) {
			t.Errorf("остались %v", ks)
		}
	})
	t.Run("результат не зависит от порядка обхода карты", func(t *testing.T) {
		for r := 0; r < 20; r++ {
			m := map[string]time.Time{}
			for i := 1; i <= 10; i++ {
				m[fpN(i)] = base.Add(time.Duration(i%3) * time.Second)
			}
			trimAlerts(m, fpN(7), 4)
			// keep=7 (1 с); свежие (2 с): 2,5,8 -> меньшие 2,5,8 берутся по 3 места
			if ks := keys(m); !reflect.DeepEqual(ks, []string{fpN(2), fpN(5), fpN(7), fpN(8)}) {
				t.Fatalf("остались %v", ks)
			}
		}
	})
}

func newBoundedTracker(t *testing.T) (*Tracker, *State) {
	t.Helper()
	st, _ := OpenState("")
	known := func(ns, s string) bool { return ns == "shop" && s == "geo-svc" }
	return NewTracker("staging", known, 2, 10, st, nil), st
}

func boundedAlert(fp string, startsAt time.Time) Alert {
	return Alert{Fingerprint: fp, Name: "X", Severity: "critical", Namespace: "shop", Service: "geo-svc", StartsAt: startsAt}
}

// Флаппинг: каждый опрос приносит новые fingerprint'ы одного ключа; карта не растёт выше потолка.
func TestTrackerAlertsBounded(t *testing.T) {
	tr, st := newBoundedTracker(t)
	var logs bytes.Buffer
	tr.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	first := boundedAlert(fpN(0), t0)
	op, _, err := tr.Observe(t0, []Alert{first})
	if err != nil || len(op) != 1 {
		t.Fatalf("открытие: %v %v", err, op)
	}
	id, firstAt := op[0].ID, op[0].FirstAlertAt
	const polls, perPoll = 200, 3
	n := 0
	for p := 1; p <= polls; p++ {
		now := t0.Add(time.Duration(p) * time.Minute)
		var as []Alert
		for j := 0; j < perPoll; j++ {
			n++
			as = append(as, boundedAlert(fpN(1000+n), t0.Add(time.Duration(p)*time.Minute)))
		}
		op, cl, err := tr.Observe(now, as)
		if err != nil || len(op) != 0 || len(cl) != 0 {
			t.Fatalf("опрос %d: %v %v %v", p, err, op, cl)
		}
		if inc, _ := st.Get(id); len(inc.Alerts) > MaxIncidentAlerts {
			t.Fatalf("опрос %d: %d fingerprint'ов", p, len(inc.Alerts))
		}
	}
	inc, _ := st.Get(id)
	if len(inc.Alerts) != MaxIncidentAlerts {
		t.Fatalf("fingerprint'ов %d, ожидалось %d", len(inc.Alerts), MaxIncidentAlerts)
	}
	if _, ok := inc.Alerts[fpN(0)]; !ok {
		t.Error("первый алерт вытеснен")
	}
	// остальные 63 — самые свежие: последние 63 из выданных (n-62..n)
	for i := n - 62; i <= n; i++ {
		if _, ok := inc.Alerts[fpN(1000+i)]; !ok {
			t.Errorf("свежий fingerprint %d отсутствует", i)
		}
	}
	if !strings.Contains(logs.String(), "intake_incident_alerts_trimmed") || !strings.Contains(logs.String(), id) {
		t.Errorf("нет Debug-лога о вытеснении: %q", logs.String())
	}
	if inc.ID != id || !inc.FirstAlertAt.Equal(firstAt) || inc.Status != StatusOpen {
		t.Errorf("ID/FirstAlertAt/статус изменились: %+v", inc)
	}
	// пока ключ горит — не закрывается (даже если горят только новые fingerprint'ы)
	if _, cl, _ := tr.Observe(t0.Add(time.Hour*24), []Alert{boundedAlert(fpN(5000), t0)}); len(cl) != 0 {
		t.Error("закрытие при горящем ключе")
	}
	// пустые опросы -> закрытие по AbsentPolls
	now := t0.Add(time.Hour * 25)
	if _, cl, _ := tr.Observe(now, nil); len(cl) != 0 {
		t.Fatal("закрытие после одного пустого опроса")
	}
	_, cl, _ := tr.Observe(now.Add(time.Minute), nil)
	if len(cl) != 1 || cl[0].ID != id || cl[0].Status != StatusClosing {
		t.Fatalf("закрытие: %v", cl)
	}
}

// Один опрос с 100 алертами: остаётся первый (по StartsAt) и 63 с наименьшими fingerprint (время одинаково).
func TestTrackerSinglePollManyAlerts(t *testing.T) {
	tr, st := newBoundedTracker(t)
	t0 := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	var as []Alert
	// первый по StartsAt — с самым БОЛЬШИМ fingerprint, чтобы проверить приоритет keep
	as = append(as, boundedAlert(fpN(9999), t0.Add(-time.Hour)))
	for i := 1; i <= 99; i++ {
		as = append(as, boundedAlert(fpN(i), t0))
	}
	op, _, err := tr.Observe(t0, as)
	if err != nil || len(op) != 1 {
		t.Fatalf("%v %v", err, op)
	}
	inc, _ := st.Get(op[0].ID)
	if len(inc.Alerts) != MaxIncidentAlerts {
		t.Fatalf("fingerprint'ов %d", len(inc.Alerts))
	}
	if _, ok := inc.Alerts[fpN(9999)]; !ok {
		t.Error("первый алерт не включён")
	}
	for i := 1; i <= 63; i++ {
		if _, ok := inc.Alerts[fpN(i)]; !ok {
			t.Errorf("fingerprint %d отсутствует", i)
		}
	}
	if !inc.FirstAlertAt.Equal(t0.Add(-time.Hour)) {
		t.Errorf("FirstAlertAt %s", inc.FirstAlertAt)
	}
}
