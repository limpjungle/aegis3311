package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func record(t *testing.T, id string) []byte {
	t.Helper()
	v, err := os.ReadFile("../../internal/pep/testdata/cases/cap_lease_missing.verdict.json")
	if err != nil {
		t.Fatal(err)
	}
	var verdict map[string]any
	json.Unmarshal(v, &verdict)
	rec := map[string]any{
		"schema": "aegisops/decision-record/v1", "record_id": id, "recorded_at": "2026-11-07T12:00:00Z", "mode": "shadow",
		"incident":  map[string]any{"id": "inc-1", "class": "RB-001", "service": "geo-svc", "environment": "prod"},
		"initiator": map[string]any{"kind": "agent", "id": "agent-1"},
		"model":     nil, "prompt": nil, "retrieved_docs": []string{}, "answer": nil,
		"verdict": json.RawMessage(v), "autonomy_level": verdict["effective_level"],
		"lease": nil, "post_check": nil, "trace_ref": "",
	}
	b, _ := json.Marshal(rec)
	return b
}

func code(err error) int {
	if err == nil {
		return 0
	}
	var ee exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return -1
}

func TestCLI(t *testing.T) {
	d := t.TempDir()
	priv, pub, chain, anchor := filepath.Join(d, "k.pem"), filepath.Join(d, "k.pub"), filepath.Join(d, "c.jsonl"), filepath.Join(d, "anchor")
	os.Mkdir(anchor, 0o755)
	var out bytes.Buffer
	if err := run([]string{"keygen", "-priv", priv, "-pub", pub}, nil, &out); err != nil || !strings.Contains(out.String(), "ed25519:") {
		t.Fatalf("keygen: %v %s", err, out.String())
	}
	for i, id := range []string{"dr-1", "dr-2", "dr-3"} {
		out.Reset()
		if err := run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(record(t, id)), &out); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if err := run([]string{"checkpoint", "-chain", chain, "-id", "agent-1", "-key", priv, "-anchor", anchor}, nil, &out); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	out.Reset()
	if err := run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1", "-anchor", anchor}, nil, &out); err != nil {
		t.Fatalf("verify: %v", err)
	}
	var res struct {
		Seq         int `json:"seq"`
		Checkpoints int `json:"checkpoints_checked"`
	}
	json.Unmarshal(out.Bytes(), &res)
	if res.Seq != 3 || res.Checkpoints != 1 {
		t.Fatalf("verify: %s", out.String())
	}
	// Невалидная запись и лишнее поле — код 1, цепочка не меняется.
	bad := bytes.Replace(record(t, "dr-4"), []byte(`"lease":null`), []byte(`"lease":{"id":"l-1","fencing_token":3}`), 1)
	if c := code(run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(bad), &out)); c != 1 {
		t.Fatalf("lease в shadow: код %d", c)
	}
	extra := bytes.Replace(record(t, "dr-5"), []byte(`{"answer"`), []byte(`{"x":1,"answer"`), 1)
	if c := code(run([]string{"append", "-chain", chain, "-id", "agent-1", "-key", priv}, bytes.NewReader(extra), &out)); c != 1 {
		t.Fatalf("лишнее поле: код %d", c)
	}
	// Усечение цепочки ловится checkpoint'ом.
	b, _ := os.ReadFile(chain)
	ls := bytes.SplitAfter(b, []byte("\n"))
	os.WriteFile(chain, bytes.Join(ls[:2], nil), 0o640)
	if c := code(run([]string{"verify", "-chain", chain, "-pub", pub, "-id", "agent-1", "-anchor", anchor}, nil, &out)); c != 1 {
		t.Fatalf("усечение: код %d", c)
	}
	if c := code(run([]string{"verify", "-chain", chain}, nil, &out)); c != 2 {
		t.Fatalf("без -pub: код %d", c)
	}
	if c := code(run([]string{"nope"}, nil, &out)); c != 2 {
		t.Fatalf("неизвестная команда: код %d", c)
	}
}
