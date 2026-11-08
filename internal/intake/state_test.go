package intake

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStateMissingIsEmptyAndFileMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	st, err := OpenState(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	st.View(func(d *Data) {
		if len(d.Incidents) != 0 || len(d.Closed) != 0 || d.Schema != StateSchema {
			t.Errorf("пустое состояние: %+v", d)
		}
	})
	if err := st.Do(func(d *Data) { d.Incidents["x"] = &Incident{ID: "x", Status: StatusOpen} }); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("файл состояния: %v %v", fi, err)
	}
	if _, err := os.Stat(p + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Error("остался временный файл")
	}
}

func TestStateCorruptVariants(t *testing.T) {
	inc := func(id, status string) string {
		return `{"schema":"` + StateSchema + `","incidents":{"` + id + `":{"id":"` + id + `","status":"` + status + `"}},"closed":{}}`
	}
	cases := map[string]string{
		"пустой файл":        ``,
		"мусор":              `not json`,
		"обрезанный":         `{"schema":"` + StateSchema + `","incidents":{"a":`,
		"чужая схема":        `{"schema":"aegisops/intake-state/v0","incidents":{},"closed":{}}`,
		"без схемы":          `{"incidents":{},"closed":{}}`,
		"неизвестное поле":   `{"schema":"` + StateSchema + `","incidents":{},"closed":{},"x":1}`,
		"дубли ключей":       `{"schema":"` + StateSchema + `","schema":"` + StateSchema + `","incidents":{},"closed":{}}`,
		"неизвестный статус": inc("a", "weird"),
		"id не совпадает":    `{"schema":"` + StateSchema + `","incidents":{"a":{"id":"b","status":"open"}},"closed":{}}`,
		"null-инцидент":      `{"schema":"` + StateSchema + `","incidents":{"a":null},"closed":{}}`,
		"хвост после JSON":   `{"schema":"` + StateSchema + `","incidents":{},"closed":{}} {}`,
	}
	for name, body := range cases {
		p := filepath.Join(t.TempDir(), "s.json")
		os.WriteFile(p, []byte(body), 0o600)
		st, err := OpenState(p)
		if !errors.Is(err, ErrStateCorrupt) {
			t.Errorf("%s: ошибка %v", name, err)
			if st != nil {
				st.Close()
			}
			continue
		}
		// после отказа блокировка снята
		st2, err := OpenState(p)
		if errors.Is(err, ErrStateLocked) {
			t.Errorf("%s: блокировка не снята после отказа", name)
		}
		if st2 != nil {
			st2.Close()
		}
	}
	// корректные статусы читаются
	for _, s := range []string{StatusOpen, StatusRecorded, StatusClosing} {
		p := filepath.Join(t.TempDir(), "s.json")
		os.WriteFile(p, []byte(inc("a", s)), 0o600)
		st, err := OpenState(p)
		if err != nil {
			t.Errorf("статус %s: %v", s, err)
			continue
		}
		if got, ok := st.Get("a"); !ok || got.Status != s || got.Alerts == nil {
			t.Errorf("статус %s: %+v", s, got)
		}
		st.Close()
	}
}

func TestStateLockReleasedOnClose(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	st, _ := OpenState(p)
	if _, err := OpenState(p); !errors.Is(err, ErrStateLocked) {
		t.Fatalf("второй владелец: %v", err)
	}
	st.Close()
	st.Close() // повторное закрытие безопасно
	st2, err := OpenState(p)
	if err != nil {
		t.Fatalf("после Close: %v", err)
	}
	st2.Close()
}

// Сценарии краха: состояние на диске после Do переживает «рестарт», все поля инцидента сохраняются.
func TestStateRoundTripFields(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.json")
	st, _ := OpenState(p)
	now := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	in := Incident{ID: "inc-1", Key: Key{"staging", "shop", "geo-svc"}, FirstAlertAt: now, OpenedAt: now.Add(time.Minute), LastFiringAt: now.Add(2 * time.Minute),
		AbsentPolls: 3, Alerts: map[string]time.Time{"0123456789abcdef": now}, Alert: Alert{Name: "A", Severity: "info", StartsAt: now}, Status: StatusClosing, Attempts: 2}
	st.Do(func(d *Data) { d.Incidents[in.ID] = &in; d.Closed["inc-0"] = now })
	st.Close()
	st, err := OpenState(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, ok := st.Get("inc-1")
	if !ok || got.Key != in.Key || !got.FirstAlertAt.Equal(now) || got.AbsentPolls != 3 || got.Attempts != 2 || got.Status != StatusClosing ||
		len(got.Alerts) != 1 || got.Alert.Name != "A" {
		t.Errorf("поля не сохранились: %+v", got)
	}
	st.View(func(d *Data) {
		if _, ok := d.Closed["inc-0"]; !ok {
			t.Error("Closed не сохранён")
		}
	})
	// Get возвращает копию: правка копии не меняет состояние
	got.Alerts["ffffffffffffffff"] = now
	if again, _ := st.Get("inc-1"); len(again.Alerts) != 1 {
		t.Error("Get отдал внутреннюю map")
	}
}

// Ошибка записи состояния возвращается (фатальна для вызывающего).
func TestStateSaveErrorReported(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "s.json")
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	st, err := OpenState(p)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	os.Chmod(filepath.Join(dir, "sub"), 0o500)
	defer os.Chmod(filepath.Join(dir, "sub"), 0o700)
	if os.Geteuid() == 0 {
		t.Skip("root обходит права каталога")
	}
	if err := st.Do(func(d *Data) { d.Closed["x"] = time.Now() }); err == nil || strings.Contains(err.Error(), "<nil>") {
		t.Errorf("ошибка записи не возвращена: %v", err)
	}
}

// Старый файл v1 со 100 fingerprint'ами: при загрузке обрезается до потолка (первый алерт сохраняется),
// на диске — после следующего Do; схема не меняется.
func TestStateLoadTrimsAlerts(t *testing.T) {
	now := time.Date(2026, 1, 2, 10, 0, 0, 0, time.UTC)
	first := fmt.Sprintf("%016x", 9999) // самый старый и с самым большим fingerprint
	var sb strings.Builder
	fmt.Fprintf(&sb, `{"schema":"%s","incidents":{"inc-1":{"id":"inc-1","status":"open","alert":{"fingerprint":%q},"alerts":{`, StateSchema, first)
	fmt.Fprintf(&sb, `%q:%q`, first, now.Add(-time.Hour).Format(time.RFC3339))
	for i := 1; i <= 99; i++ {
		fmt.Fprintf(&sb, `,%q:%q`, fmt.Sprintf("%016x", i), now.Add(time.Duration(i)*time.Second).Format(time.RFC3339))
	}
	sb.WriteString(`}}},"closed":{}}`)
	p := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := OpenState(p)
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	defer st.Close()
	inc, ok := st.Get("inc-1")
	if !ok || len(inc.Alerts) != MaxIncidentAlerts {
		t.Fatalf("после загрузки %d fingerprint'ов", len(inc.Alerts))
	}
	if _, ok := inc.Alerts[first]; !ok {
		t.Error("первый алерт вытеснен")
	}
	for i := 37; i <= 99; i++ { // 63 самых свежих
		if _, ok := inc.Alerts[fmt.Sprintf("%016x", i)]; !ok {
			t.Errorf("свежий fingerprint %d отсутствует", i)
		}
	}
	if err := st.Do(func(d *Data) {}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var d Data
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	if d.Schema != StateSchema || len(d.Incidents["inc-1"].Alerts) != MaxIncidentAlerts {
		t.Errorf("на диске: схема %q, %d fingerprint'ов", d.Schema, len(d.Incidents["inc-1"].Alerts))
	}
}
