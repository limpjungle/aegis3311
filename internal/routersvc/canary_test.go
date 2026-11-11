package routersvc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/openrouter"
)

const svcMarker = "canary-svc-marker-0007"

func (f *fixture) canaryFile(content string) string {
	f.t.Helper()
	p := filepath.Join(f.dir, "markers.txt")
	must(f.t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func TestCanaryConfigValidate(t *testing.T) {
	f := newFixture(t)
	good := f.canaryFile(svcMarker + "\n")
	f.cfg.Canary = &CanaryConfig{MarkersFile: good}
	if err := f.cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	f.cfg.Canary = nil
	if err := f.cfg.Validate(); err != nil {
		t.Fatalf("без canary: %v", err)
	}
	for name, p := range map[string]string{"относительный": "markers.txt", "точка": "./markers.txt", "пустой": "", "вверх": "../markers.txt"} {
		f.cfg.Canary = &CanaryConfig{MarkersFile: p}
		if err := f.cfg.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestCanaryConfigLoad(t *testing.T) {
	ok := `{"router_id":"r-1","state_path":"/tmp/x/state","audit":{"chain":"/tmp/x/chain","chain_id":"c-1"},"canary":{"markers_file":"/etc/aegis/canary/markers.txt"}}`
	c, err := LoadConfig(writeCfg(t, ok))
	if err != nil || c.Canary == nil || c.Canary.MarkersFile != "/etc/aegis/canary/markers.txt" {
		t.Fatalf("%v %+v", err, c.Canary)
	}
	if c, err := LoadConfig(writeCfg(t, okCfg)); err != nil || c.Canary != nil {
		t.Fatalf("без блока: %v %+v", err, c.Canary)
	}
	for name, s := range map[string]string{
		"относительный путь": strings.Replace(ok, "/etc/aegis/canary/markers.txt", "markers.txt", 1),
		"пустой путь":        strings.Replace(ok, "/etc/aegis/canary/markers.txt", "", 1),
		"неизвестное поле":   strings.Replace(ok, `"markers_file"`, `"markers":"/a","markers_file"`, 1),
		"пустой блок":        strings.Replace(ok, `{"markers_file":"/etc/aegis/canary/markers.txt"}`, `{}`, 1),
		"не объект":          strings.Replace(ok, `{"markers_file":"/etc/aegis/canary/markers.txt"}`, `"/a"`, 1),
	} {
		if _, err := LoadConfig(writeCfg(t, s)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestOpenCanaryBrokenFile(t *testing.T) {
	cases := map[string]func(f *fixture) string{
		"нет файла":       func(f *fixture) string { return filepath.Join(f.dir, "нет-такого.txt") },
		"пустой":          func(f *fixture) string { return f.canaryFile("") },
		"только комменты": func(f *fixture) string { return f.canaryFile("# a\n") },
		"битый маркер":    func(f *fixture) string { return f.canaryFile("не маркер\n") },
		"каталог":         func(f *fixture) string { return f.dir },
		"большой":         func(f *fixture) string { return f.canaryFile(strings.Repeat("#", 70<<10)) },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.Canary = &CanaryConfig{MarkersFile: mk(f)}
			rt, err := f.open(true)
			if err == nil {
				rt.Close()
				t.Fatal("Open успешен")
			}
			var ce *ConfigError
			if !errors.As(err, &ce) || Classify(err) != ClassUsage {
				t.Errorf("не ConfigError/usage: %T %v", err, err)
			}
			if !strings.Contains(err.Error(), "canary.markers_file") {
				t.Errorf("нет имени поля: %v", err)
			}
			if n := dirNames(t, f.dir+"/data"); len(n) != 0 {
				t.Errorf("созданы файлы: %v", n)
			}
		})
	}
}

func TestOpenCanaryRelativePath(t *testing.T) {
	f := newFixture(t)
	f.canaryFile(svcMarker + "\n")
	f.cfg.Canary = &CanaryConfig{MarkersFile: "markers.txt"}
	if _, err := f.open(true); err == nil || Classify(err) != ClassUsage {
		t.Fatalf("относительный путь: %v", err)
	}
	if n := dirNames(t, f.dir+"/data"); len(n) != 0 {
		t.Errorf("созданы файлы: %v", n)
	}
}

func TestOpenCanaryLogs(t *testing.T) {
	t.Run("без блока: предупреждение", func(t *testing.T) {
		f := newFixture(t)
		rt := f.mustOpen(true)
		defer rt.Close()
		out := f.log.String()
		if !strings.Contains(out, `"msg":"egress_canary_disabled"`) || !strings.Contains(out, `"level":"WARN"`) {
			t.Errorf("нет WARN egress_canary_disabled: %s", out)
		}
		if !strings.Contains(out, `"canary_markers":0`) {
			t.Errorf("llmrouter_opened без canary_markers=0: %s", out)
		}
		if got := rt.Router.State().CanaryMarkers; got != 0 {
			t.Errorf("CanaryMarkers=%d", got)
		}
	})
	t.Run("с файлом: нет предупреждения, маркеры не в логе", func(t *testing.T) {
		f := newFixture(t)
		f.cfg.Canary = &CanaryConfig{MarkersFile: f.canaryFile("# c\n" + svcMarker + "\ncanary-svc-marker-0008\n")}
		rt := f.mustOpen(true)
		defer rt.Close()
		out := f.log.String()
		if strings.Contains(out, "egress_canary_disabled") {
			t.Errorf("лишнее предупреждение: %s", out)
		}
		if !strings.Contains(out, `"canary_markers":2`) {
			t.Errorf("нет canary_markers=2: %s", out)
		}
		if strings.Contains(strings.ToLower(out), "canary-svc-marker") {
			t.Errorf("маркер в логе: %s", out)
		}
		if got := rt.Router.State().CanaryMarkers; got != 2 {
			t.Errorf("CanaryMarkers=%d", got)
		}
	})
}

// Интеграция: настоящий HTTP-транспорт на httptest-сервер. С маркером в теле сервер не получает ни одного запроса,
// без маркера — ровно один. Реальный маскировщик, настоящая цепочка аудита.
func TestCanaryIntegrationHTTP(t *testing.T) {
	var hits atomic.Int64
	var seen atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		buf := make([]byte, 1<<20)
		n, _ := r.Body.Read(buf)
		seen.Store(string(buf[:n]))
		c := reply("Inceptron", 100, 50)
		w.WriteHeader(c.Status)
		w.Write(c.Body)
	}))
	defer srv.Close()

	open := func(t *testing.T, withCanary bool) (*fixture, *Runtime) {
		f := newFixture(t)
		if withCanary {
			f.cfg.Canary = &CanaryConfig{MarkersFile: f.canaryFile(svcMarker + "\n")}
		}
		d := f.deps()
		d.Transport = openrouter.NewHTTPTransport()
		d.ClientOptions = append(d.ClientOptions, openrouter.WithURL(srv.URL))
		rt, err := Open(f.cfg, f.secrets(), OpenOptions{Create: true}, d)
		must(t, err)
		t.Cleanup(func() { rt.Close() })
		return f, rt
	}
	reqWith := func(text string) []byte {
		return []byte(fmt.Sprintf(`{"incident_id":"inc-1","service":"geo-svc","environment":"staging","mode":"hybrid","sections":[{"key":"alert","list":false,"fragments":[{"id":"a","source":"alerts.alertmanager","kind":"generic","required":true,"relevance":100,"value":{"summary":%q}}]}]}`, text))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("с маркером: 0 запросов, halt, аудит", func(t *testing.T) {
		hits.Store(0)
		f, rt := open(t, true)
		req, _, err := ParseRequest(reqWith("Ошибка\n" + strings.ToUpper(svcMarker) + "\nконец"))
		must(t, err)
		res, err := rt.Router.Route(ctx, req)
		if err != nil || res.Outcome != "not_sent" || res.Reason != "egress_canary" || !res.DegradeL1 {
			t.Fatalf("%v %+v", err, res)
		}
		if hits.Load() != 0 {
			t.Fatalf("сервер получил %d запросов", hits.Load())
		}
		st := rt.Status()
		if !st.Halted || st.HaltReason != "egress_canary" {
			t.Fatalf("%+v", st)
		}
		evs, _ := f.verifyChain()
		var found bool
		for _, e := range evs {
			if e.Kind == "router_halted" && e.Ev.Reason == "egress_canary" {
				found = true
			}
		}
		if !found {
			t.Errorf("в цепочке нет router_halted/egress_canary: %v", kinds(evs))
		}
		if strings.Contains(strings.ToLower(string(fileBytes(t, f.cfg.Audit.Chain))), svcMarker) ||
			strings.Contains(strings.ToLower(f.log.String()), svcMarker) {
			t.Error("маркер в цепочке аудита или журнале")
		}
		// halt переживает перезапуск.
		rt.Close()
		rt2, err := Open(f.cfg, f.secrets(), OpenOptions{}, f.deps())
		must(t, err)
		defer rt2.Close()
		if s := rt2.Status(); !s.Halted || s.HaltReason != "egress_canary" {
			t.Errorf("после рестарта: %+v", s)
		}
	})
	t.Run("без маркера: ровно 1 запрос", func(t *testing.T) {
		hits.Store(0)
		_, rt := open(t, true)
		req, _, err := ParseRequest(reqWith("обычный текст canary-svc-marker-000"))
		must(t, err)
		res, err := rt.Router.Route(ctx, req)
		if err != nil || res.Outcome != "sent" {
			t.Fatalf("%v %+v", err, res)
		}
		if hits.Load() != 1 {
			t.Fatalf("сервер получил %d запросов", hits.Load())
		}
	})
	t.Run("без блока canary маркер не проверяется", func(t *testing.T) {
		hits.Store(0)
		_, rt := open(t, false)
		req, _, err := ParseRequest(reqWith(svcMarker))
		must(t, err)
		res, err := rt.Router.Route(ctx, req)
		if err != nil || res.Outcome != "sent" || hits.Load() != 1 {
			t.Fatalf("%v %+v hits=%d", err, res, hits.Load())
		}
	})
}
