package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

// Текущая сборка (уровень 4) принимает router_halted(egress_canary): verify и verify -integrity-only проходят,
// непонятых записей нет.
func TestCLIEgressCanaryHalt(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl")
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	ev := routerEvent(t, "re-00000000000000000000000000000001", "router_halted", "egress_canary", nil)
	if err := run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(ev), &out); err != nil {
		t.Fatalf("append router_halted(egress_canary): %v", err)
	}
	for _, extra := range [][]string{nil, {"-integrity-only"}} {
		out.Reset()
		args := append([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1"}, extra...)
		if err := run(args, nil, &out); err != nil {
			t.Fatalf("%v: %v", extra, err)
		}
		var res struct {
			RouterEvents int `json:"router_events"`
			Unverified   int `json:"unverified_records"`
			Format       int `json:"chain_format"`
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if extra == nil && res.RouterEvents != 1 {
			t.Errorf("router_events=%d: %s", res.RouterEvents, out.String())
		}
		if res.Unverified != 0 || res.Format != 4 && extra != nil {
			t.Errorf("%v: unverified=%d format=%d: %s", extra, res.Unverified, res.Format, out.String())
		}
	}
}
