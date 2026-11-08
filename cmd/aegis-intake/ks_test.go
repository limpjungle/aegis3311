package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/killswitch"
	"github.com/limpjungle/aegis3311/internal/routersvc"
)

// lastKS — фейковые каналы kill switch последнего fakeStack (как amGone: тесты e2e управляют стеком через глобальную переменную).
var lastKS *fakeKS

// fakeKS — документ kill switch, отдаваемый фейковым kube (ConfigMap) и фейковым S3 (проверяется формат SigV4).
type fakeKS struct {
	mu      sync.Mutex
	cm, oob []byte // nil — 404
	signers []*audit.Ed25519Signer
	issuers []string
	keyDefs []map[string]any
	s3Seen  int
}

func newFakeKS(t *testing.T, dir string) *fakeKS {
	k := &fakeKS{}
	for _, n := range []string{"oncall-ivanov", "oncall-petrov"} {
		priv, pub := filepath.Join(dir, n+".pem"), filepath.Join(dir, n+".pub.pem")
		if _, err := audit.GenerateKey(priv, pub); err != nil {
			t.Fatal(err)
		}
		sg, err := audit.LoadPrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		k.signers, k.issuers = append(k.signers, sg), append(k.issuers, n)
		k.keyDefs = append(k.keyDefs, map[string]any{"path": pub, "issuer": n, "role": "oncall"})
	}
	return k
}

// doc подписывает документ ключами с индексами idx.
func (k *fakeKS) doc(t *testing.T, global bool, clusters []string, issuedAt time.Time, ttl time.Duration, idx ...int) []byte {
	t.Helper()
	d := killswitch.Document{Schema: killswitch.DocSchema, Global: global, Clusters: append([]string{}, clusters...), Actions: []string{},
		IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano), TTL: ttl.String(), Issuer: "test", Signatures: []killswitch.Signature{}}
	for _, i := range idx {
		sig, err := killswitch.SignatureFor(d, k.signers[i], k.issuers[i])
		if err != nil {
			t.Fatal(err)
		}
		if d, err = killswitch.AddSignature(d, sig); err != nil {
			t.Fatal(err)
		}
	}
	return killswitch.Marshal(d)
}

// set публикует документ в оба канала.
func (k *fakeKS) set(doc []byte) { k.mu.Lock(); k.cm, k.oob = doc, doc; k.mu.Unlock() }

// setRun публикует run двумя дежурными с issued_at = сейчас.
func (k *fakeKS) setRun(t *testing.T) {
	k.set(k.doc(t, false, nil, time.Now(), time.Hour, 0, 1))
}

func (k *fakeKS) configMap(w http.ResponseWriter, r *http.Request) {
	k.mu.Lock()
	doc := k.cm
	k.mu.Unlock()
	if doc == nil {
		w.WriteHeader(404)
		return
	}
	jsonH(map[string]any{"data": map[string]string{killswitch.ConfigMapKey: string(doc)}})(w, r)
}

func (k *fakeKS) s3(w http.ResponseWriter, r *http.Request) {
	a := r.Header.Get("Authorization")
	if r.Method != "GET" || !strings.HasPrefix(a, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") || !strings.Contains(a, "SignedHeaders=host;x-amz-content-sha256;x-amz-date,") ||
		r.Header.Get("x-amz-date") == "" || r.URL.Path != "/ks-bucket/kill-switch.json" {
		w.WriteHeader(403)
		return
	}
	k.mu.Lock()
	doc := k.oob
	k.s3Seen++
	k.mu.Unlock()
	if doc == nil {
		w.WriteHeader(404)
		return
	}
	w.Write(doc)
}

// serveS3 поднимает фейковый S3 и возвращает адрес и файл CA.
func (k *fakeKS) serveS3(t *testing.T, dir string) (url, caFile string) {
	s := httptest.NewTLSServer(http.HandlerFunc(k.s3))
	t.Cleanup(s.Close)
	caFile = filepath.Join(dir, "s3-ca.pem")
	os.WriteFile(caFile, pemCert(s.Certificate().Raw), 0o600)
	return s.URL, caFile
}

func (k *fakeKS) config(s3URL, ca string) map[string]any {
	return map[string]any{"cluster": "prod-eu-1", "keys": k.keyDefs, "poll_interval": "1s", "max_skew": "2m",
		"oob": map[string]any{"endpoint": s3URL, "region": "ru-central1", "bucket": "ks-bucket", "key": "kill-switch.json", "path_style": true, "ca_file": ca}}
}

var _ = fmt.Sprint

func (s *stack) killSwitchEvents(t *testing.T) []audit.KillSwitchEvent {
	t.Helper()
	b, err := os.ReadFile(s.chain)
	if err != nil {
		return nil
	}
	var evs []audit.KillSwitchEvent
	if _, err := audit.Verify(bytes.NewReader(b), s.keys, audit.VerifyOptions{ChainID: "chain-test",
		OnKillSwitchEvent: func(_ uint64, ev *audit.KillSwitchEvent) { evs = append(evs, *ev) }}); err != nil {
		t.Fatalf("цепочка не проходит проверку: %v", err)
	}
	return evs
}

// Старт с остановкой (одна подпись — global): запись об инциденте с llm.mode=off и состоянием, модель не вызвана, событие engaged.
func TestServeStartStopped(t *testing.T) {
	s := newStack(t)
	lastKS.set(lastKS.doc(t, true, nil, time.Now(), time.Hour, 0))
	r := s.start(t, nil)
	waitFor(t, "запись", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	if err := r.stop(t); err != nil {
		t.Fatalf("serve: %v\n%s", err, r.errb.String())
	}
	rec := s.records(t)[0]
	if rec.LLM == nil || rec.LLM.Mode != "off" || rec.Model != nil || rec.KillSwitch == nil || rec.KillSwitch.State.Reason != "global" || len(rec.Intake.Sources) == 0 {
		t.Errorf("запись: llm=%+v ks=%+v", rec.LLM, rec.KillSwitch)
	}
	if s.tr.posts != 0 {
		t.Errorf("запросов в модель %d", s.tr.posts)
	}
	evs := s.killSwitchEvents(t)
	if len(evs) == 0 || evs[0].Kind != "kill_switch_engaged" || evs[0].From != "none" || evs[0].LatencyMs == nil || *evs[0].LatencyMs < 0 {
		t.Errorf("события: %+v", evs)
	}
}

// Run с одной подписью при старте не подтверждает: no_confirmation, модель не вызвана.
func TestServeStartRunOneSignature(t *testing.T) {
	s := newStack(t)
	lastKS.set(lastKS.doc(t, false, nil, time.Now(), time.Hour, 0))
	r := s.start(t, nil)
	waitFor(t, "запись", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	r.stop(t)
	if rec := s.records(t)[0]; rec.LLM.Mode != "off" || rec.KillSwitch.State.Reason != "no_confirmation" || s.tr.posts != 0 {
		t.Errorf("запись: %+v %+v posts=%d", rec.LLM, rec.KillSwitch, s.tr.posts)
	}
}

// Подмена документа на stop (одна подпись) во время работы: событие engaged с latency_ms, журнал kill_switch_engaged.
func TestServeStopWhileRunning(t *testing.T) {
	s := newStack(t)
	r := s.start(t, nil)
	waitFor(t, "запись", 5*time.Second, func() bool { return len(s.records(t)) == 1 })
	lastKS.set(lastKS.doc(t, false, []string{"prod-eu-1"}, time.Now(), time.Hour, 1))
	waitFor(t, "событие engaged", 8*time.Second, func() bool {
		for _, ev := range s.killSwitchEvents(t) {
			if ev.Kind == "kill_switch_engaged" {
				return true
			}
		}
		return false
	})
	r.stop(t)
	evs := s.killSwitchEvents(t)
	last := evs[len(evs)-1]
	if last.State.Reason != "cluster" || last.From != "running" || last.LatencyMs == nil || *last.LatencyMs < 0 || len(last.Triggers) != 1 {
		t.Errorf("событие: %+v", last)
	}
	if !strings.Contains(r.errb.String(), "kill_switch_engaged") || !strings.Contains(r.errb.String(), "latency_ms") {
		t.Errorf("журнал без kill_switch_engaged/latency_ms:\n%s", r.errb.String())
	}
}

// Ключ подписи аудита среди ключей kill switch → код 2.
func TestServeAuditKeyInKillSwitchKeys(t *testing.T) {
	s := newStack(t)
	ks := s.cfg["kill_switch"].(map[string]any)
	auditPub := strings.TrimSuffix(s.getenv(routersvc.AuditKeyEnv), ".pem") + ".pub"
	ks["keys"].([]any)[0].(map[string]any)["path"] = auditPub
	b, _ := json.Marshal(s.cfg)
	os.WriteFile(s.cfgPath, b, 0o600)
	var o, e bytes.Buffer
	err := run(context.Background(), []string{"serve", "-config", s.cfgPath}, s.env(&o, &e))
	if exitCode(err) != 2 || !strings.Contains(err.Error(), "ключ подписи аудита") {
		t.Errorf("код %d: %v", exitCode(err), err)
	}
}
