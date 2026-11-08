package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// release двумя дежурными опубликован в оба канала.
func (r *rig) publishRelease() {
	r.t.Helper()
	rel := filepath.Join(r.dir, "rel-"+r.clk.now().Format("150405")+".json")
	if _, _, code := r.run("release", "-key", r.key("ivanov"), "-out", rel); code != 0 {
		r.t.Fatal("release")
	}
	if _, e, code := r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-publish"); code != 0 {
		r.t.Fatalf("cosign -publish: %s", e)
	}
}

type checkOut struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
	State   struct {
		Stopped bool   `json:"stopped"`
		Reason  string `json:"reason"`
	} `json:"state"`
	ConfirmationIssuedAt string `json:"confirmation_issued_at"`
	ConfirmedUntil       string `json:"confirmed_until"`
	Channels             []struct {
		Channel string `json:"channel"`
		Error   string `json:"error"`
	} `json:"channels"`
}

func (r *rig) check(args ...string) (checkOut, string, int) {
	r.t.Helper()
	out, errs, code := r.run(append([]string{"check", "-cluster", "prod-eu-1"}, args...)...)
	var c checkOut
	if strings.Contains(strings.Join(args, " "), "prom") || strings.Contains(strings.Join(args, " "), "-out") {
		return c, out + errs, code
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		r.t.Fatalf("check: вывод не JSON: %v\n%s\n%s", err, out, errs)
	}
	return c, errs, code
}

func TestCheckStatuses(t *testing.T) {
	r := newRig(t)

	// каналы пусты: критично
	c, _, code := r.check()
	if c.Status != "critical" || code != 1 || c.State.Reason != "no_confirmation" {
		t.Fatalf("пусто: %+v код %d", c, code)
	}
	// свежее подтверждение: ok, код 0
	r.publishRelease()
	c, _, code = r.check()
	if c.Status != "ok" || code != 0 || c.ConfirmationIssuedAt == "" || c.ConfirmedUntil == "" || len(c.Reasons) != 0 {
		t.Fatalf("ok: %+v код %d", c, code)
	}
	// старое подтверждение (> slot+15m = 75m), но ещё действует: warning
	r.clk.add(80 * time.Minute)
	c, _, code = r.check()
	if c.Status != "warning" || code != 1 || !strings.Contains(strings.Join(c.Reasons, ";"), "confirmation_age") {
		t.Fatalf("warning по возрасту: %+v код %d", c, code)
	}
	// -warn-age переопределяет
	if c, _, code = r.check("-warn-age", "3h"); c.Status != "ok" || code != 0 {
		t.Errorf("-warn-age 3h: %+v код %d", c, code)
	}
	// до конца подтверждения < ttl/3 (2h): critical
	r.clk.add(3*time.Hour + 20*time.Minute) // возраст 4h40m, осталось 1h20m
	c, _, code = r.check()
	if c.Status != "critical" || code != 1 || !strings.Contains(strings.Join(c.Reasons, ";"), "confirmation_expiring") {
		t.Fatalf("critical по остатку: %+v код %d", c, code)
	}
	if c, _, code = r.check("-warn-age", "10h", "-crit-left", "10m"); c.Status != "ok" || code != 0 {
		t.Errorf("пороги переопределены: %+v код %d", c, code)
	}
	// подтверждение истекло: critical no_confirmation
	r.clk.add(2 * time.Hour)
	if c, _, code = r.check(); c.Status != "critical" || code != 1 || c.State.Reason != "no_confirmation" {
		t.Errorf("истекло: %+v код %d", c, code)
	}
}

func TestCheckWarningChannel403AndStopped(t *testing.T) {
	r := newRig(t)
	r.publishRelease()
	r.cloud.mu.Lock()
	r.cloud.failS3 = true // oob отвечает 403
	r.cloud.mu.Unlock()
	c, _, code := r.check()
	if c.Status != "warning" || code != 1 {
		t.Fatalf("канал 403: %+v код %d", c, code)
	}
	found := false
	for _, ch := range c.Channels {
		if ch.Channel == "oob" && ch.Error == "http_403" {
			found = true
		}
	}
	if !found || !strings.Contains(strings.Join(c.Reasons, ";"), "channel oob: http_403") {
		t.Errorf("ошибка канала не отражена: %+v", c)
	}
	r.cloud.mu.Lock()
	r.cloud.failS3 = false
	r.cloud.mu.Unlock()

	// остановка документом: stopped, код 0
	r.clk.add(time.Second)
	if _, _, code := r.run("stop", "-key", r.key("ivanov"), "-cluster", "prod-eu-1"); code != 0 {
		t.Fatal("stop")
	}
	c, _, code = r.check()
	if c.Status != "stopped" || code != 0 || !c.State.Stopped || c.State.Reason != "cluster" {
		t.Fatalf("stopped: %+v код %d", c, code)
	}
	// stop чужого кластера не останавливает нашу цель, а каналы совпадают: ok
	c, _, code = r.run2("check", "-cluster", "other-cluster")
	if c.State.Stopped && c.State.Reason == "cluster" {
		t.Errorf("stop чужого кластера: %+v", c)
	}
	// stopped + ошибка канала = warning (выше stopped)
	r.cloud.mu.Lock()
	r.cloud.failS3 = true
	r.cloud.mu.Unlock()
	if c, _, code = r.check(); c.Status != "warning" || code != 1 {
		t.Errorf("stopped+канал 403: %+v код %d", c, code)
	}
}

func (r *rig) run2(args ...string) (checkOut, string, int) {
	out, errs, code := r.run(args...)
	var c checkOut
	json.Unmarshal([]byte(out), &c)
	return c, errs, code
}

func TestCheckUsageErrors(t *testing.T) {
	r := newRig(t)
	for _, args := range [][]string{
		{"check", "-format", "xml"}, {"check", "-warn-age", "abc"}, {"check", "-warn-age", "-5m"}, {"check", "-crit-left", "0s"},
		{"check", "-cluster", "Bad_Cluster"}, {"check", "-cluster", "a", "-cluster", "b"}, {"check", "-channels", "x"},
		{"check", "-global"},
		// флаги check в других командах
		{"status", "-format", "prom"}, {"status", "-warn-age", "1h"}, {"status", "-crit-left", "1h"},
		{"stop", "-key", r.key("ivanov"), "-global", "-format", "json"}, {"renew", "-key", r.key("renewer-a"), "-warn-age", "1h"},
	} {
		if _, _, code := r.run(args...); code != 2 {
			t.Errorf("%v: код %d, ожидался 2", args, code)
		}
	}
}

var promLine = regexp.MustCompile(`^([a-z_]+)(\{[^}]*\})? (\S+)$`)

func TestCheckProm(t *testing.T) {
	r := newRig(t)
	r.publishRelease()
	out, errs, code := r.run("check", "-cluster", "prod-eu-1", "-format", "prom")
	if code != 0 {
		t.Fatalf("код %d: %s %s", code, out, errs)
	}
	sums := map[string]int{}
	families := map[string]bool{}
	for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if strings.HasPrefix(ln, "# HELP ") {
			continue
		}
		if strings.HasPrefix(ln, "# TYPE ") {
			families[strings.Fields(ln)[2]] = true
			continue
		}
		m := promLine.FindStringSubmatch(ln)
		if m == nil {
			t.Fatalf("строка не по формату: %q", ln)
		}
		if !strings.Contains(m[2], `cluster="prod-eu-1"`) {
			t.Errorf("нет cluster у ряда: %q", ln)
		}
		if m[1] == "aegis_killswitch_check_status" || m[1] == "aegis_killswitch_reason" {
			if m[3] == "1" {
				sums[m[1]]++
			}
			if m[3] != "0" && m[3] != "1" {
				t.Errorf("one-hot значение %q", ln)
			}
		}
	}
	for _, f := range []string{"aegis_killswitch_check_timestamp_seconds", "aegis_killswitch_check_status", "aegis_killswitch_stopped", "aegis_killswitch_reason",
		"aegis_killswitch_confirmation_issued_timestamp_seconds", "aegis_killswitch_confirmed_until_timestamp_seconds",
		"aegis_killswitch_channel_ok", "aegis_killswitch_channel_doc_issued_timestamp_seconds"} {
		if !families[f] {
			t.Errorf("нет семейства %s", f)
		}
	}
	if sums["aegis_killswitch_check_status"] != 1 || sums["aegis_killswitch_reason"] != 1 {
		t.Errorf("one-hot суммы: %v", sums)
	}
	for _, want := range []string{`aegis_killswitch_check_status{cluster="prod-eu-1",status="ok"} 1`, `aegis_killswitch_stopped{cluster="prod-eu-1"} 0`,
		`aegis_killswitch_reason{cluster="prod-eu-1",reason="none"} 1`, `aegis_killswitch_channel_ok{cluster="prod-eu-1",channel="configmap"} 1`,
		`aegis_killswitch_channel_ok{cluster="prod-eu-1",channel="oob"} 1`,
		`aegis_killswitch_check_timestamp_seconds{cluster="prod-eu-1"} `} {
		if !strings.Contains(out, want) {
			t.Errorf("нет %q в:\n%s", want, out)
		}
	}
	// метрики не содержат issuer'ов и sha
	for _, bad := range []string{"ivanov", "petrov", "sha256"} {
		if strings.Contains(out, bad) {
			t.Errorf("в prom-выводе %q", bad)
		}
	}
	// stopped: reason=cluster, check_status=stopped
	r.clk.add(time.Second)
	r.run("stop", "-key", r.key("ivanov"), "-cluster", "prod-eu-1")
	out, _, code = r.run("check", "-cluster", "prod-eu-1", "-format", "prom")
	if code != 0 || !strings.Contains(out, `aegis_killswitch_check_status{cluster="prod-eu-1",status="stopped"} 1`) ||
		!strings.Contains(out, `aegis_killswitch_reason{cluster="prod-eu-1",reason="cluster"} 1`) || !strings.Contains(out, `aegis_killswitch_stopped{cluster="prod-eu-1"} 1`) {
		t.Errorf("stopped prom (код %d):\n%s", code, out)
	}
	// пустые каналы: critical, нулевые метки времени, код 1
	r2 := newRig(t)
	out, _, code = r2.run("check", "-cluster", "prod-eu-1", "-format", "prom")
	if code != 1 || !strings.Contains(out, `status="critical"} 1`) || !strings.Contains(out, `aegis_killswitch_confirmed_until_timestamp_seconds{cluster="prod-eu-1"} 0`) {
		t.Errorf("critical prom (код %d):\n%s", code, out)
	}
}

func TestCheckOutAtomic(t *testing.T) {
	r := newRig(t)
	r.publishRelease()
	dir := filepath.Join(r.dir, "textfile")
	target := filepath.Join(dir, "aegis_killswitch.prom")
	_, errs, code := r.run("check", "-cluster", "prod-eu-1", "-format", "prom", "-out", target)
	if code != 0 {
		t.Fatalf("код %d %s", code, errs)
	}
	b, err := os.ReadFile(target)
	if err != nil || !strings.Contains(string(b), "aegis_killswitch_check_status") {
		t.Fatalf("файл: %v %q", err, b)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o644 {
		t.Errorf("права %v", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("в каталоге лишние файлы: %v", ents)
	}
	// перезапись: старое содержимое заменено целиком, временных файлов нет; в stdout ничего
	r.clk.add(10 * time.Minute)
	out, _, code := r.run("check", "-cluster", "prod-eu-1", "-format", "prom", "-out", target)
	if code != 0 || out != "" {
		t.Errorf("повтор: код %d stdout %q", code, out)
	}
	b2, _ := os.ReadFile(target)
	if string(b) == string(b2) {
		t.Error("файл не обновлён")
	}
	ents, _ = os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("временные файлы остались: %v", ents)
	}
	// warning/critical: файл всё равно пишется (метрики нужны именно при сбое), код 1
	r.clk.add(10 * time.Hour)
	_, _, code = r.run("check", "-cluster", "prod-eu-1", "-format", "prom", "-out", target)
	b3, _ := os.ReadFile(target)
	if code != 1 || !strings.Contains(string(b3), `status="critical"} 1`) {
		t.Errorf("critical с -out: код %d\n%s", code, b3)
	}
	// каталог — файл: ошибка, не паника, код 2
	blocker := filepath.Join(r.dir, "blocker")
	os.WriteFile(blocker, []byte("x"), 0o600)
	if _, _, code := r.run("check", "-cluster", "prod-eu-1", "-out", filepath.Join(blocker, "x.prom")); code != 2 {
		t.Errorf("-out в неверный путь: код %d", code)
	}
	// JSON в файл
	jf := filepath.Join(r.dir, "check.json")
	r.run("check", "-cluster", "prod-eu-1", "-out", jf)
	var c checkOut
	if b, _ := os.ReadFile(jf); json.Unmarshal(b, &c) != nil || c.Status == "" {
		t.Errorf("json -out: %s", b)
	}
}

func TestPublishReleaseOverFutureStop(t *testing.T) {
	r := newRig(t)
	rel := filepath.Join(r.dir, "rel.json")
	signed := filepath.Join(r.dir, "rel-signed.json")
	if _, _, code := r.run("release", "-key", r.key("ivanov"), "-out", rel); code != 0 {
		t.Fatal("release")
	}
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-out", signed); code != 0 {
		t.Fatal("cosign")
	}
	base := r.clk.now()
	// stop из будущего (часы подписавшего впереди на 10 минут)
	r.clk.add(10 * time.Minute)
	if _, _, code := r.run("stop", "-key", r.key("sidorov"), "-global"); code != 0 {
		t.Fatal("stop")
	}
	r.clk.add(-10*time.Minute + time.Second)
	if r.clk.now().Before(base) {
		t.Fatal("часы")
	}
	_, errs, code := r.run("publish", "-in", signed)
	if code != 0 {
		t.Fatalf("release поверх stop из будущего: код %d\n%s", code, errs)
	}
	if !strings.Contains(errs, "из будущего") {
		t.Errorf("нет предупреждения: %q", errs)
	}
	st, _, _ := r.run("status", "-cluster", "prod-eu-1")
	if !strings.Contains(st, `"stopped": false`) {
		t.Errorf("после публикации цель остановлена:\n%s", st)
	}
	if r.cloud.cm != r.cloud.oob() || !strings.Contains(r.cloud.cm, `"global":false`) {
		t.Errorf("каналы не заменены release")
	}
}

func TestPublishReleaseOverStopWithinSkewRefused(t *testing.T) {
	r := newRig(t)
	rel := filepath.Join(r.dir, "rel.json")
	signed := filepath.Join(r.dir, "rel-signed.json")
	r.run("release", "-key", r.key("ivanov"), "-out", rel)
	if _, _, code := r.run("cosign", "-key", r.key("petrov"), "-in", rel, "-out", signed); code != 0 {
		t.Fatal("cosign")
	}
	r.clk.add(time.Minute) // stop в now+1m относительно момента публикации
	r.run("stop", "-key", r.key("sidorov"), "-global")
	r.clk.add(-time.Minute + time.Second)
	_, _, code := r.run("publish", "-in", signed)
	if code != 1 {
		t.Errorf("stop в пределах skew должен блокировать: код %d", code)
	}
	if !strings.Contains(r.cloud.cm, `"global":true`) {
		t.Errorf("stop затёрт")
	}
	// ровно на границе: stop в now+2m (не After(now+maxSkew)) — всё ещё блокирует
	r2 := newRig(t)
	rel2, signed2 := filepath.Join(r2.dir, "rel.json"), filepath.Join(r2.dir, "rel-signed.json")
	r2.run("release", "-key", r2.key("ivanov"), "-out", rel2)
	r2.run("cosign", "-key", r2.key("petrov"), "-in", rel2, "-out", signed2)
	r2.clk.add(2 * time.Minute)
	r2.run("stop", "-key", r2.key("sidorov"), "-global")
	r2.clk.add(-2 * time.Minute)
	if _, _, code := r2.run("publish", "-in", signed2); code != 1 {
		t.Errorf("stop ровно на границе skew: код %d", code)
	}
}
