package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// TestCLIKillSwitchEvent: событие kill switch добавляется командой append и считается verify отдельным счётчиком;
// несогласованное событие отвергается (код 1).
func TestCLIKillSwitchEvent(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	ev := map[string]any{"schema": "aegisops/killswitch-event/v1", "event_id": "ks-00000000000000000000000000000001", "recorded_at": "2026-11-08T10:00:00Z",
		"kind": "kill_switch_released", "from": "none", "target_cluster": "prod-eu-1",
		"state":    map[string]any{"stopped": false, "reason": "", "global": false, "cluster": false, "actions": []string{}, "liveness_confirmed": true, "evaluated_at": "2026-11-08T10:00:00Z"},
		"triggers": []string{"sha256:" + string(bytes.Repeat([]byte("a"), 64))}, "issued_at": "2026-11-08T09:59:59Z", "signers": []string{"oncall-a", "oncall-b"},
		"applied_at": "2026-11-08T10:00:00Z", "latency_ms": 1000, "stop_watermark": "", "release_watermark": "2026-11-08T09:59:59Z",
		"channels": []map[string]any{{"channel": "oob", "status": "fresh", "cached": false, "error": "", "effect": "run", "confirmation": "oncall",
			"signers": []string{"oncall-a", "oncall-b"}, "issued_at": "2026-11-08T09:59:59Z", "doc_sha256": "sha256:" + string(bytes.Repeat([]byte("a"), 64))}},
		"initiator": map[string]any{"kind": "system", "id": "intake-1"}}
	b, _ := json.Marshal(ev)
	if err := run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(b), &out); err != nil {
		t.Fatalf("append: %v", err)
	}
	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1"}, nil, &out); err != nil {
		t.Fatal(err)
	}
	var res struct {
		KillSwitch uint64 `json:"kill_switch_events"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil || res.KillSwitch != 1 {
		t.Fatalf("verify: %s", out.String())
	}
	ev["event_id"], ev["kind"] = "ks-00000000000000000000000000000002", "kill_switch_engaged"
	b, _ = json.Marshal(ev)
	if err := run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(b), &out); exitCodeOf(err) != 1 {
		t.Errorf("несогласованное событие: %v", err)
	}
}

func exitCodeOf(err error) int {
	if ee, ok := err.(exitError); ok {
		return ee.code
	}
	return -1
}
