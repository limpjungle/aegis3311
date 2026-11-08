package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// routerEvent собирает событие router-event/v1 для команды append. Поля — как в TestCLI.
func routerEvent(t *testing.T, id, kind, reason string, extra map[string]any) []byte {
	t.Helper()
	ev := map[string]any{"schema": "aegisops/router-event/v1", "event_id": id, "recorded_at": "2026-11-07T12:00:00Z",
		"kind": kind, "endpoint": "", "role": "", "from": "", "to": "", "reason": reason,
		"consecutive_failures": 0, "stable_for_s": 0, "model": "z-ai/glm-5.3-flash-20260826",
		"initiator": map[string]any{"kind": "system", "id": "llm-router-1"}}
	for k, v := range extra {
		ev[k] = v
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestCLIRouterStateEvents: цепочка с якорем state_created и причинами router_halted хранилища состояния проходит
// verify; неверные формы отвергаются (код 1), цепочка не меняется.
func TestCLIRouterStateEvents(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil {
		t.Fatalf("keygen: %v", err)
	}
	appendEv := func(b []byte) error {
		out.Reset()
		return run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(b), &out)
	}
	anchor := routerEvent(t, "re-00000000000000000000000000000001", "state_created", "store_created",
		map[string]any{"from": "inceptron-fp8", "to": "wafer-nvfp4"})
	if err := appendEv(anchor); err != nil {
		t.Fatalf("якорь state_created: %v", err)
	}
	if err := appendEv(routerEvent(t, "re-00000000000000000000000000000002", "router_halted", "state_store", nil)); err != nil {
		t.Fatalf("router_halted(state_store): %v", err)
	}
	if err := appendEv(routerEvent(t, "re-00000000000000000000000000000003", "router_halted", "state_lost", nil)); err != nil {
		t.Fatalf("router_halted(state_lost): %v", err)
	}

	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1"}, nil, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var res struct {
		RouterEvents int `json:"router_events"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.RouterEvents != 3 {
		t.Fatalf("verify: %s (ожидается 3 события роутера)", out.String())
	}

	bad := map[string][]byte{
		"якорь с endpoint": routerEvent(t, "re-00000000000000000000000000000004", "state_created", "store_created",
			map[string]any{"from": "a", "to": "b", "endpoint": "inceptron-fp8", "role": "primary"}),
		"якорь без профилей": routerEvent(t, "re-00000000000000000000000000000005", "state_created", "store_created", nil),
		"якорь с чужой причиной": routerEvent(t, "re-00000000000000000000000000000006", "state_created", "x",
			map[string]any{"from": "a", "to": "b"}),
		"router_halted с неизвестной причиной": routerEvent(t, "re-00000000000000000000000000000007", "router_halted", "state_gone", nil),
	}
	for name, b := range bad {
		if c := code(appendEv(b)); c != 1 {
			t.Errorf("%s: код %d, ожидается 1", name, c)
		}
	}
	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1"}, nil, &out); err != nil {
		t.Fatalf("после отказов цепочка не проходит проверку: %v", err)
	}
	var after struct {
		RouterEvents int `json:"router_events"`
	}
	if err := json.Unmarshal(out.Bytes(), &after); err != nil || after.RouterEvents != 3 {
		t.Errorf("после отказов число событий изменилось: %s", out.String())
	}
}
