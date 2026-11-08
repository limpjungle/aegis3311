package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// intakeRecord — запись без обращения к модели с блоком intake (форма, которую пишет aegis-intake).
func intakeRecord(t *testing.T, id, outcome, reason string) []byte {
	t.Helper()
	var rec map[string]any
	if err := json.Unmarshal(record(t, id), &rec); err != nil {
		t.Fatal(err)
	}
	rec["incident"] = map[string]any{"id": "inc-20260107T100000Z-0123456789ab", "class": "", "service": "geo-svc", "environment": "staging"}
	rec["verdict"], rec["autonomy_level"] = nil, "L0"
	rec["intake"] = map[string]any{"source": "alerts.alertmanager", "first_alert_at": "2026-11-07T11:50:00Z",
		"collected_at": "2026-11-07T11:52:00Z", "alerts": []string{"0123456789abcdef"},
		"sources": []map[string]any{{"source": "platform.topology", "status": "unavailable", "items": 0, "error": "timeout"}},
		"outcome": outcome, "reason": reason}
	b, _ := json.Marshal(rec)
	return b
}

// Запись с блоком intake проходит append и verify CLI; неверный блок отвергается кодом 1 и цепочку не меняет.
func TestCLIIntakeRecord(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	app := func(b []byte) error {
		out.Reset()
		return run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(b), &out)
	}
	if err := app(intakeRecord(t, "rec-00000000000000000000000000000001", "not_routed", "source_unavailable")); err != nil {
		t.Fatalf("append с intake: %v", err)
	}
	if c := code(app(intakeRecord(t, "rec-00000000000000000000000000000002", "not_routed", ""))); c != 1 {
		t.Errorf("not_routed без причины: код %d, ожидается 1", c)
	}
	if c := code(app(intakeRecord(t, "rec-00000000000000000000000000000003", "routed", ""))); c != 1 {
		t.Errorf("routed без llm: код %d, ожидается 1", c)
	}
	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1"}, nil, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var res struct {
		Records uint64 `json:"records"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.Records != 1 {
		t.Fatalf("verify: %s (ожидается 1 запись)", out.String())
	}
}
