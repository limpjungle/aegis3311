package routersvc

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/masker"
)

func writeCfg(t *testing.T, s string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.json")
	must(t, os.WriteFile(p, []byte(s), 0o600))
	return p
}

const okCfg = `{"router_id":"r-1","state_path":"/tmp/x/state","audit":{"chain":"/tmp/x/chain","chain_id":"c-1"}}`

func TestConfigOK(t *testing.T) {
	c, err := LoadConfig(writeCfg(t, okCfg))
	if err != nil {
		t.Fatal(err)
	}
	b, fo, nets, err := c.Effective()
	if err != nil {
		t.Fatal(err)
	}
	// Пустые секции — значения по умолчанию.
	if b != llmrouter.DefaultBudgets() || fo != llmrouter.DefaultFailover() || !reflect.DeepEqual(nets, masker.DefaultInternalNets()) {
		t.Fatalf("дефолты: %+v %+v %v", b, fo, nets)
	}
}

func TestConfigOverrides(t *testing.T) {
	s := `{"router_id":"r-1","state_path":"/tmp/x/state","audit":{"chain":"/tmp/x/chain","chain_id":"c-1"},
"budgets":{"incident_tokens":5,"service_day_tokens":7},"failover":{"fail_threshold":2,"hysteresis":"1m","health_interval":"5s"},"internal_nets":["10.1.0.0/16"]}`
	c, err := LoadConfig(writeCfg(t, s))
	if err != nil {
		t.Fatal(err)
	}
	b, fo, nets, _ := c.Effective()
	if b.IncidentTokens != 5 || b.ServiceDayTokens != 7 || fo.FailThreshold != 2 || fo.Hysteresis != time.Minute || fo.HealthInterval != 5*time.Second {
		t.Fatalf("%+v %+v", b, fo)
	}
	if len(nets) != 1 || nets[0].String() != "10.1.0.0/16" {
		t.Fatalf("%v", nets)
	}
}

func TestConfigInvalid(t *testing.T) {
	base := func(repl ...string) string { return strings.NewReplacer(repl...).Replace(okCfg) }
	cases := map[string]string{
		"неизвестное поле":       `{"router_id":"r-1","state_path":"/a","audit":{"chain":"/b","chain_id":"c"},"extra":1}`,
		"неизвестное в audit":    `{"router_id":"r-1","state_path":"/a","audit":{"chain":"/b","chain_id":"c","zzz":1}}`,
		"дубль ключа":            `{"router_id":"r-1","router_id":"r-2","state_path":"/a","audit":{"chain":"/b","chain_id":"c"}}`,
		"относительный state":    base(`"/tmp/x/state"`, `"state"`),
		"относительная цепочка":  base(`"/tmp/x/chain"`, `"chain"`),
		"state == chain":         base(`"/tmp/x/chain"`, `"/tmp/x/state"`),
		"state == chain (clean)": base(`"/tmp/x/chain"`, `"/tmp/x/../x/state"`),
		"пустой state":           base(`"/tmp/x/state"`, `""`),
		"router_id с пробелом":   base(`"r-1"`, `"r 1"`),
		"пустой router_id":       base(`"r-1"`, `""`),
		"chain_id с /":           base(`"c-1"`, `"c/1"`),
		"пустой chain_id":        base(`"c-1"`, `""`),
		"отрицательный бюджет":   base(`}}`, `}},"budgets":{"incident_tokens":-1}`),
		"отрицательный порог":    base(`}}`, `}},"failover":{"fail_threshold":-1}`),
		"длительность 10x":       base(`}}`, `}},"failover":{"hysteresis":"10x"}`),
		"отрицательная длит.":    base(`}}`, `}},"failover":{"health_interval":"-5s"}`),
		"нулевая длит.":          base(`}}`, `}},"failover":{"health_interval":"0s"}`),
		"плохой CIDR":            base(`}}`, `}},"internal_nets":["10.0.0.0/33"]`),
		"CIDR без маски":         base(`}}`, `}},"internal_nets":["nonsense"]`),
		"пустой путь ключа":      base(`"chain_id":"c-1"`, `"chain_id":"c-1","public_keys":[""]`),
		"не JSON":                `router_id`,
	}
	for name, s := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeCfg(t, s)); err == nil {
				t.Fatalf("принято: %s", s)
			}
		})
	}
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "нет")); err == nil {
		t.Error("нет файла")
	}
}

func TestConfigSizeLimit(t *testing.T) {
	big := okCfg[:len(okCfg)-1] + `,"internal_nets":["` + strings.Repeat("1", 1<<20) + `"]}`
	if _, err := LoadConfig(writeCfg(t, big)); err == nil || !strings.Contains(err.Error(), "больше") {
		t.Fatalf("лимит 1 MiB: %v", err)
	}
}

func TestValidIDEdge(t *testing.T) {
	for s, want := range map[string]bool{"alice": true, "a.b:c/d@e-f_": true, "a.b:c/d@e-f": true, "": false, "-a": false, "a b": false, strings.Repeat("a", 256): true, strings.Repeat("a", 257): false} {
		if ValidID(s) != want {
			t.Errorf("ValidID(%q) != %v", s, want)
		}
	}
}

// ошибки валидации не должны требовать файловой системы: Validate на несуществующих путях успешен.
func TestValidateNoFS(t *testing.T) {
	c := Config{RouterID: "r", StatePath: "/nonexistent/a", Audit: AuditConfig{Chain: "/nonexistent/b", ChainID: "c"}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.Failover.Hysteresis = fmt.Sprint(time.Hour)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
