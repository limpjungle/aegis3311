package intake

import (
	"encoding/json"
	"strings"
	"testing"
)

// miniConfig — минимальная валидная конфигурация (без сервисов с БД).
func miniConfig() map[string]any {
	return map[string]any{
		"intake_id": "intake-1", "router_config": "/etc/aegis/llmrouter.json", "state_path": "/var/lib/aegis/intake.json",
		"snapshot_dir": "/var/lib/aegis/snaps", "environment": "staging",
		"alertmanager": map[string]any{"url": "https://am.example:9093"},
		"prometheus":   map[string]any{"url": "https://prom.example:9090"},
		"kubernetes":   map[string]any{"api_url": "https://k8s.example"},
		"kill_switch": map[string]any{"cluster": "prod-eu-1",
			"keys": []any{map[string]any{"path": "/etc/aegis/ks/a.pub.pem", "issuer": "oncall-a", "role": "oncall"},
				map[string]any{"path": "/etc/aegis/ks/b.pub.pem", "issuer": "oncall-b", "role": "oncall"}},
			"oob": map[string]any{"endpoint": "https://storage.example", "region": "r1", "bucket": "b", "key": "kill-switch.json", "path_style": true}},
		"services": []any{map[string]any{"namespace": "shop", "service": "geo-svc", "workload": map[string]any{"kind": "Deployment", "name": "geo-svc"}}},
		"metrics":  []any{map[string]any{"name": "m1", "unit": "ms", "query": `up{namespace="$namespace"}`}},
	}
}

func parse(t *testing.T, m map[string]any) (Config, error) {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return ParseConfig(b)
}

func svc0(m map[string]any) map[string]any { return m["services"].([]any)[0].(map[string]any) }
func met0(m map[string]any) map[string]any { return m["metrics"].([]any)[0].(map[string]any) }

func TestConfigDefaults(t *testing.T) {
	c, err := parse(t, miniConfig())
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.Durations()
	if err != nil || d.Poll.String() != "15s" || d.Settle.String() != "2m0s" || d.CloseAfter.String() != "15m0s" || d.Collect.String() != "30s" ||
		d.Request.String() != "5s" || d.SnapshotRetention.String() != "2160h0m0s" {
		t.Errorf("умолчания: %+v %v", d, err)
	}
	if c.Workers != 2 || c.MaxOpenIncidents != 256 || c.MaxRoutedPerHour != 6 || c.Services[0].LLMMode != "hybrid" ||
		c.Metrics[0].Applies != "always" || c.Metrics[0].MaxSeries != 12 {
		t.Errorf("умолчания: %+v", c)
	}
}

func TestConfigRejects(t *testing.T) {
	withDB := func(m map[string]any) { svc0(m)["database"], svc0(m)["pg_cluster"] = "geo", "pg1" }
	bad := map[string]func(m map[string]any){
		"неизвестное поле верхнего уровня": func(m map[string]any) { m["token"] = "x" },
		"пустой intake_id":            func(m map[string]any) { m["intake_id"] = "" },
		"intake_id с пробелом":        func(m map[string]any) { m["intake_id"] = "a b" },
		"environment":                 func(m map[string]any) { m["environment"] = "prod" },
		"относительный state_path":    func(m map[string]any) { m["state_path"] = "state.json" },
		"пустой snapshot_dir":         func(m map[string]any) { m["snapshot_dir"] = "" },
		"относительный router_config": func(m map[string]any) { m["router_config"] = "r.json" },
		"poll_interval мусор":         func(m map[string]any) { m["poll_interval"] = "fast" },
		"poll_interval ноль":          func(m map[string]any) { m["poll_interval"] = "0s" },
		"settle отрицательный":        func(m map[string]any) { m["settle"] = "-1m" },
		"workers 17":                  func(m map[string]any) { m["workers"] = 17 },
		"workers отрицательные":       func(m map[string]any) { m["workers"] = -1 },
		"max_open 5000":               func(m map[string]any) { m["max_open_incidents"] = 5000 },
		"url со схемой ftp":           func(m map[string]any) { m["alertmanager"].(map[string]any)["url"] = "ftp://am" },
		"url с учётными данными":      func(m map[string]any) { m["prometheus"].(map[string]any)["url"] = "https://u:p@prom" },
		"url с query":                 func(m map[string]any) { m["kubernetes"].(map[string]any)["api_url"] = "https://k8s?x=1" },
		"пустой url":                  func(m map[string]any) { m["alertmanager"].(map[string]any)["url"] = "" },
		"пустой matcher":              func(m map[string]any) { m["alertmanager"].(map[string]any)["matchers"] = []any{" "} },
		"заголовок Authorization": func(m map[string]any) {
			m["prometheus"].(map[string]any)["headers"] = map[string]any{"authorization": "Bearer x"}
		},
		"заголовок с переводом строки":   func(m map[string]any) { m["prometheus"].(map[string]any)["headers"] = map[string]any{"X-A": "a\nb"} },
		"пустой реестр":                  func(m map[string]any) { m["services"] = []any{} },
		"имя сервиса не DNS":             func(m map[string]any) { svc0(m)["service"] = "Geo_Svc" },
		"namespace не DNS":               func(m map[string]any) { svc0(m)["namespace"] = `shop"} or vector(1) #` },
		"имя workload не DNS":            func(m map[string]any) { svc0(m)["workload"].(map[string]any)["name"] = "w w" },
		"workload.kind":                  func(m map[string]any) { svc0(m)["workload"].(map[string]any)["kind"] = "StatefulSet" },
		"autoscaler.kind":                func(m map[string]any) { svc0(m)["autoscaler"] = map[string]any{"kind": "VPA", "name": "x"} },
		"autoscaler.name":                func(m map[string]any) { svc0(m)["autoscaler"] = map[string]any{"kind": "ScaledObject", "name": "X Y"} },
		"declared_min отрицательный":     func(m map[string]any) { svc0(m)["declared_min"] = -1 },
		"database не DNS":                func(m map[string]any) { svc0(m)["database"], svc0(m)["pg_cluster"] = `g"eo`, "pg1" },
		"pg_cluster не DNS":              func(m map[string]any) { svc0(m)["database"], svc0(m)["pg_cluster"] = "geo", `p"g` },
		"pg_cluster без database не DNS": func(m map[string]any) { svc0(m)["pg_cluster"] = `p"g` },
		"insufficient_data_policy":       func(m map[string]any) { svc0(m)["insufficient_data_policy"] = "yolo" },
		"bake мусор":                     func(m map[string]any) { svc0(m)["bake"] = "долго" },
		"bake ноль":                      func(m map[string]any) { svc0(m)["bake"] = "0s" },
		"llm_mode":                       func(m map[string]any) { svc0(m)["llm_mode"] = "auto" },
		"сервис не уникален":             func(m map[string]any) { m["services"] = append(m["services"].([]any), svc0(m)) },
		"то же имя в другом namespace": func(m map[string]any) {
			s2 := map[string]any{"namespace": "other", "service": "geo-svc", "workload": map[string]any{"kind": "Deployment", "name": "x"}}
			m["services"] = append(m["services"].([]any), s2)
		},
		"нет метрик":                 func(m map[string]any) { m["metrics"] = []any{} },
		"метрика: пустой запрос":     func(m map[string]any) { met0(m)["query"] = "" },
		"метрика: пустая единица":    func(m map[string]any) { met0(m)["unit"] = "" },
		"метрика: имя с заглавными":  func(m map[string]any) { met0(m)["name"] = "Latency" },
		"метрика повторяется":        func(m map[string]any) { m["metrics"] = append(m["metrics"].([]any), met0(m)) },
		"метрика applies":            func(m map[string]any) { met0(m)["applies"] = "sometimes" },
		"max_series 13":              func(m map[string]any) { met0(m)["max_series"] = 13 },
		"max_series отрицательный":   func(m map[string]any) { met0(m)["max_series"] = -1 },
		"series_labels не метка":     func(m map[string]any) { met0(m)["series_labels"] = []any{"Pod Name"} },
		"подстановка $alert":         func(m map[string]any) { met0(m)["query"] = `up{x="$alert_name"}` },
		"подстановка $description":   func(m map[string]any) { met0(m)["query"] = `up{x="$description"}` },
		"static_labels: ключ":        func(m map[string]any) { met0(m)["static_labels"] = map[string]any{"Bad Key": "v"} },
		"static_labels: подстановка": func(m map[string]any) { met0(m)["static_labels"] = map[string]any{"k": "$labels"} },
		"db_queries: неизвестный":    func(m map[string]any) { m["db_queries"] = map[string]any{"drop_table": "1"} },
		"db_queries: подстановка":    func(m map[string]any) { m["db_queries"] = map[string]any{"pool_size": "x{a=\"$podname\"}"} },
		"БД есть, db_queries нет":    func(m map[string]any) { withDB(m) },
	}
	for name, f := range bad {
		m := miniConfig()
		f(m)
		if _, err := parse(t, m); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
	// дубли ключей JSON
	if _, err := ParseConfig([]byte(`{"intake_id":"a","intake_id":"b"}`)); err == nil {
		t.Error("дубли ключей приняты")
	}
	if _, err := ParseConfig([]byte(`{} {}`)); err == nil {
		t.Error("хвост после JSON принят")
	}
}

func TestConfigValidBoundaries(t *testing.T) {
	m := miniConfig()
	met0(m)["max_series"] = 12
	met0(m)["static_labels"] = map[string]any{"service": "$service", "ns": "$namespace"}
	met0(m)["query"] = `sum(x{n="$namespace",s="$service",d="$database",c="$pg_cluster"}) by ($namespace_label)`
	if _, err := parse(t, m); err == nil {
		t.Error("$namespace_label — не подстановка реестра, должен быть отказ")
	}
	met0(m)["query"] = `sum(x{n="$namespace",s="$service",d="$database",c="$pg_cluster"})`
	svc0(m)["autoscaler"] = map[string]any{"kind": "ScaledObject", "name": "geo"}
	svc0(m)["bake"] = "60m"
	svc0(m)["llm_mode"] = "off"
	if _, err := parse(t, m); err != nil {
		t.Errorf("валидная конфигурация: %v", err)
	}
	for _, env := range []string{"staging", "prod-cloud-hybrid", "prod-baremetal"} {
		m := miniConfig()
		m["environment"] = env
		if _, err := parse(t, m); err != nil {
			t.Errorf("environment %s: %v", env, err)
		}
	}
	// db_queries полный набор для сервиса с БД
	m = miniConfig()
	svc0(m)["database"], svc0(m)["pg_cluster"] = "geo", "pg1"
	q := map[string]any{}
	for _, k := range DBQueryKeys {
		q[k] = "vector(1) # $database $pg_cluster"
	}
	m["db_queries"] = q
	if _, err := parse(t, m); err != nil {
		t.Errorf("с БД: %v", err)
	}
	delete(q, "maxwait_s")
	if _, err := parse(t, m); err == nil {
		t.Error("неполный db_queries принят")
	}
}

// Подстановка в PromQL — только из реестра: ни алерт, ни его метки в запрос не попадают; неизвестные $-слова остаются как есть.
func TestExpandRegistryOnly(t *testing.T) {
	s := ServiceConfig{Namespace: "shop", Service: "geo-svc", Database: "geo", PgCluster: "pg1"}
	got := s.Expand(`x{n="$namespace",s="$service",d="$database",c="$pg_cluster"} $other`)
	if got != `x{n="shop",s="geo-svc",d="geo",c="pg1"} $other` {
		t.Errorf("Expand: %q", got)
	}
	// значения реестра не содержат символов, ломающих PromQL
	for _, v := range []string{s.Namespace, s.Service, s.Database, s.PgCluster} {
		if strings.ContainsAny(v, `"{}\ `) {
			t.Errorf("значение реестра %q небезопасно", v)
		}
	}
	// Lookup — точное совпадение пары
	c, _ := parse(t, miniConfig())
	if _, ok := c.Lookup("shop", "geo-svc"); !ok {
		t.Error("пара не найдена")
	}
	for _, p := range [][2]string{{"shop", "geo"}, {"Shop", "geo-svc"}, {"", ""}, {"other", "geo-svc"}} {
		if _, ok := c.Lookup(p[0], p[1]); ok {
			t.Errorf("найдена %v", p)
		}
	}
}

func ks0(m map[string]any) map[string]any { return m["kill_switch"].(map[string]any) }

func TestConfigKillSwitch(t *testing.T) {
	c, err := parse(t, miniConfig())
	if err != nil {
		t.Fatal(err)
	}
	k := c.KillSwitch
	if k.PollInterval != "10s" || k.MaxSkew != "2m" || k.ConfigMap.Namespace != "aegisops-control" || k.ConfigMap.Name != "kill-switch" {
		t.Errorf("умолчания: %+v", k)
	}
	if p, s, err := k.Durations(); err != nil || p.String() != "10s" || s.String() != "2m0s" {
		t.Errorf("Durations: %v %v %v", p, s, err)
	}
	renewers := func(m map[string]any, n int) {
		ks := ks0(m)["keys"].([]any)
		for i := 0; i < n; i++ {
			ks = append(ks, map[string]any{"path": "/etc/aegis/ks/r" + string(rune('0'+i)) + ".pem", "issuer": "renewer-" + string(rune('0'+i)), "role": "renewer"})
		}
		ks0(m)["keys"] = ks
	}
	bad := map[string]func(m map[string]any){
		"нет секции":         func(m map[string]any) { delete(m, "kill_switch") },
		"меньше двух oncall": func(m map[string]any) { ks0(m)["keys"] = ks0(m)["keys"].([]any)[:1] },
		"один renewer":       func(m map[string]any) { renewers(m, 1) },
		"неизвестная роль":   func(m map[string]any) { ks0(m)["keys"].([]any)[0].(map[string]any)["role"] = "admin" },
		"относительный путь": func(m map[string]any) { ks0(m)["keys"].([]any)[0].(map[string]any)["path"] = "a.pem" },
		"http endpoint":      func(m map[string]any) { ks0(m)["oob"].(map[string]any)["endpoint"] = "http://s3.example" },
		"endpoint с путём":   func(m map[string]any) { ks0(m)["oob"].(map[string]any)["endpoint"] = "https://s3.example/b" },
		"пустой bucket":      func(m map[string]any) { ks0(m)["oob"].(map[string]any)["bucket"] = "" },
		"key с /":            func(m map[string]any) { ks0(m)["oob"].(map[string]any)["key"] = "/k.json" },
		"cluster не DNS":     func(m map[string]any) { ks0(m)["cluster"] = "Prod EU" },
		"poll 0.5s":          func(m map[string]any) { ks0(m)["poll_interval"] = "500ms" },
		"skew 1h":            func(m map[string]any) { ks0(m)["max_skew"] = "1h" },
		"неизвестное поле":   func(m map[string]any) { ks0(m)["x"] = 1 },
	}
	for name, mut := range bad {
		m := miniConfig()
		mut(m)
		if _, err := parse(t, m); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	m := miniConfig()
	renewers(m, 2)
	if _, err := parse(t, m); err != nil {
		t.Errorf("два renewer: %v", err)
	}
}
