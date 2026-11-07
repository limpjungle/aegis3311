package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/strictjson"
)

func newSigner(t testing.TB) (*Ed25519Signer, Keyring) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewEd25519Signer(priv)
	k := Keyring{}
	k.Add(s.Public())
	return s, k
}

// loadVerdict берёт настоящий golden-вердикт PEP.
func loadVerdict(t testing.TB, name string) *pep.Verdict {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "pep", "testdata", "cases", name+".verdict.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v pep.Verdict
	if err := strictjson.Decode(b, &v); err != nil {
		t.Fatal(err)
	}
	return &v
}

func h(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func shadowRecord(t testing.TB, verdict string) *DecisionRecord {
	t.Helper()
	v := loadVerdict(t, verdict)
	return &DecisionRecord{
		Schema:     RecordSchema,
		RecordID:   NewRecordID(),
		RecordedAt: Timestamp(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)),
		Mode:       ModeShadow,
		Incident:   IncidentRef{ID: "inc-42", Class: "RB-001", Service: "geo-svc", Environment: "staging"},
		Initiator:  Actor{Kind: "agent", ID: "agent-staging-1"},
		LLM: &LLMInfo{Mode: "hybrid", Outcome: "sent", DataClass: "internal", Backend: "openrouter", Jurisdiction: "US",
			Sources: []string{"metrics.prometheus"}, Masker: "test/1", ExcludedFragments: []FragmentRef{}, DroppedFragments: []FragmentRef{},
			EstInputTokens: 5300},
		Model: &ModelInfo{Profile: "inceptron-fp8", Slug: "z-ai/glm-5.3-flash-20260826", Reported: "z-ai/glm-5.3-flash",
			Provider: "Inceptron", EndpointTag: "inceptron/fp8", EndpointRole: "primary", Quantization: "fp8",
			RequestFlags: ProviderFlags{ZDR: true, DataCollection: "deny"}},
		Prompt: &PromptInfo{SystemSHA256: h('a'), InputSHA256: h('b'), RequestSHA256: h('d'), AnswerSchema: "answer.schema-v2.json",
			AnswerSchemaSHA256: h('e'), InputTokens: 5300},
		RetrievedDocs: []string{"runbook/RB-001@3f2c"},
		Answer:        &AnswerInfo{Status: "ok", SHA256: h('c'), Body: json.RawMessage(`{"incident_class":"RB-001"}`)},
		Verdict:       v,
		AutonomyLevel: v.EffectiveLevel,
	}
}

func writeChain(t *testing.T, n int) (path string, s *Ed25519Signer, k Keyring, w *Writer) {
	return writeChainTB(t, n)
}

func writeChainF(f *testing.F) (string, *Ed25519Signer, Keyring, *Writer) { return writeChainTB(f, 3) }

func writeChainTB(t testing.TB, n int) (path string, s *Ed25519Signer, k Keyring, w *Writer) {
	t.Helper()
	s, k = newSigner(t)
	path = filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"allow_scale_out_staging", "cap_lease_missing", "deny_restart_foreign_pod", "downgrade_scale_in_prod", "noop_requested_l0"}
	for i := 0; i < n; i++ {
		if _, err := w.Append(shadowRecord(t, names[i%len(names)])); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	return path, s, k, w
}

func verifyFile(t *testing.T, path string, k Keyring, opts VerifyOptions) (Head, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	return Verify(f, k, opts)
}

func lines(t *testing.T, path string) [][]byte {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ls := bytes.SplitAfter(b, []byte("\n"))
	return ls[:len(ls)-1]
}

func writeLines(t *testing.T, ls [][]byte) string {
	p := filepath.Join(t.TempDir(), "mut.jsonl")
	if err := os.WriteFile(p, bytes.Join(ls, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAppendVerifyReopen(t *testing.T) {
	path, s, k, w := writeChain(t, 5)
	head := w.Head()
	if head.Seq != 5 {
		t.Fatalf("seq %d", head.Seq)
	}
	got, err := verifyFile(t, path, k, VerifyOptions{ChainID: "agent-staging-1"})
	if err != nil || got != head {
		t.Fatalf("verify: %v, head %+v, want %+v", err, got, head)
	}
	// Второй писатель на тот же файл не допускается.
	if _, err := OpenWriter(path, "agent-staging-1", s, k); err == nil {
		t.Fatal("второй писатель открыл занятый файл")
	}
	w.Close()
	if _, err := w.Append(shadowRecord(t, "noop_requested_l0")); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("append после Close: %v", err)
	}
	w2, err := OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	e, err := w2.Append(shadowRecord(t, "noop_requested_l0"))
	if err != nil || e.Seq != 6 || e.PrevHash != head.Hash {
		t.Fatalf("продолжение цепочки: %v %+v", err, e)
	}
	// Чужой chain_id для существующего файла — отказ.
	w2.Close()
	if _, err := OpenWriter(path, "agent-other", s, k); err == nil {
		t.Fatal("открыт файл чужой цепочки")
	}
}

func TestEmptyChain(t *testing.T) {
	head, err := Verify(strings.NewReader(""), Keyring{}, VerifyOptions{})
	if err != nil || head.Seq != 0 || head.Hash != GenesisHash {
		t.Fatalf("%+v %v", head, err)
	}
}

// Любая правка файла цепочки без ключа обнаруживается.
func TestTamperDetected(t *testing.T) {
	path, _, k, w := writeChain(t, 4)
	w.Close()
	orig := lines(t, path)
	mutate := func(i int, f func(e map[string]any)) [][]byte {
		var e map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(orig[i]), &e); err != nil {
			t.Fatal(err)
		}
		f(e)
		b, _ := json.Marshal(e)
		out := append([][]byte(nil), orig...)
		out[i] = append(b, '\n')
		return out
	}
	cases := map[string][][]byte{
		"удалена средняя строка": {orig[0], orig[2], orig[3]},
		"строки переставлены":    {orig[0], orig[2], orig[1], orig[3]},
		"дублирована строка":     {orig[0], orig[1], orig[1], orig[2]},
		"оборванный хвост":       {orig[0], orig[1], orig[2], orig[3][:len(orig[3])-10]},
		"нет перевода строки":    {orig[0], orig[1], orig[2], bytes.TrimSuffix(orig[3], []byte("\n"))},
		"мусорная строка":        {orig[0], []byte("{}\n"), orig[1]},
		"пустая строка":          {orig[0], []byte("\n"), orig[1]},
		"дубль ключа в записи":   {orig[0], append(bytes.Replace(bytes.TrimSpace(orig[1]), []byte(`{"schema"`), []byte(`{"seq":2,"schema"`), 1), '\n')},
		"изменён уровень в record": mutate(1, func(e map[string]any) {
			e["record"].(map[string]any)["autonomy_level"] = "L2"
		}),
		"изменён record и его sha": mutate(1, func(e map[string]any) {
			r := e["record"].(map[string]any)
			r["mode"] = "dry-run"
			b, _ := json.Marshal(r)
			e["record_sha256"] = sha256Prefixed(b)
		}),
		"пересчитан hash без подписи": mutate(2, func(e map[string]any) {
			r := e["record"].(map[string]any)
			r["trace_ref"] = "x"
			b, _ := json.Marshal(r)
			e["record_sha256"] = sha256Prefixed(b)
			e["hash"] = entryHash(e["chain_id"].(string), uint64(e["seq"].(float64)), e["prev_hash"].(string), e["record_sha256"].(string))
		}),
		"подпись от другой записи": mutate(2, func(e map[string]any) {
			var other map[string]any
			json.Unmarshal(orig[1], &other)
			e["sig"] = other["sig"]
		}),
		"неизвестный key_id": mutate(0, func(e map[string]any) { e["key_id"] = "ed25519:0000000000000000" }),
		"сменён chain_id":    mutate(3, func(e map[string]any) { e["chain_id"] = "agent-other" }),
		"лишнее поле":        mutate(0, func(e map[string]any) { e["note"] = "x" }),
	}
	for name, ls := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := verifyFile(t, writeLines(t, ls), k, VerifyOptions{}); err == nil {
				t.Fatal("подмена не обнаружена")
			} else {
				var ce *ChainError
				if !errors.As(err, &ce) {
					t.Fatalf("ошибка не ChainError: %v", err)
				}
			}
		})
	}
	// Оборванный хвост: дописывать нельзя.
	p := writeLines(t, cases["оборванный хвост"])
	s2, k2 := newSigner(t)
	for id, pub := range k {
		k2[id] = pub
	}
	if _, err := OpenWriter(p, "agent-staging-1", s2, k2); err == nil {
		t.Fatal("писатель открыл цепочку с оборванной записью")
	}
}

// Удаление хвоста цепочки корректно на уровне hash-chain, его ловит только checkpoint из WORM.
func TestCheckpointDetectsTruncationAndRewrite(t *testing.T) {
	path, s, k, w := writeChain(t, 4)
	cp, err := w.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	dir := t.TempDir()
	a := DirAnchor{Dir: dir}
	if err := a.Put(cp); err != nil {
		t.Fatal(err)
	}
	if err := a.Put(cp); err == nil {
		t.Fatal("checkpoint перезаписан")
	}
	cps, err := a.LoadCheckpoints("agent-staging-1")
	if err != nil || len(cps) != 1 {
		t.Fatalf("load: %v %d", err, len(cps))
	}
	if _, err := verifyFile(t, path, k, VerifyOptions{Checkpoints: cps}); err != nil {
		t.Fatalf("целая цепочка: %v", err)
	}
	orig := lines(t, path)
	truncated := writeLines(t, orig[:3])
	if _, err := verifyFile(t, truncated, k, VerifyOptions{}); err != nil {
		t.Fatalf("усечённая цепочка без checkpoint должна проходить: %v", err)
	}
	if _, err := verifyFile(t, truncated, k, VerifyOptions{Checkpoints: cps}); err == nil {
		t.Fatal("усечение не обнаружено")
	}
	// Злоумышленник с ключом переписал цепочку целиком: подписи верны, но голова не совпадает с checkpoint.
	rw := filepath.Join(t.TempDir(), "rw.jsonl")
	if err := os.WriteFile(rw, bytes.Join(orig[:3], nil), 0o600); err != nil {
		t.Fatal(err)
	}
	w2, err := OpenWriter(rw, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Append(shadowRecord(t, "deny_restart_foreign_pod")); err != nil {
		t.Fatal(err)
	}
	w2.Close()
	if _, err := verifyFile(t, rw, k, VerifyOptions{}); err != nil {
		t.Fatalf("переписанная цепочка сама по себе корректна: %v", err)
	}
	if _, err := verifyFile(t, rw, k, VerifyOptions{Checkpoints: cps}); err == nil {
		t.Fatal("переписывание не обнаружено checkpoint'ом")
	}
	// Подделанный checkpoint отвергается.
	bad := cp
	bad.Seq = 2
	if _, err := verifyFile(t, path, k, VerifyOptions{Checkpoints: []Checkpoint{bad}}); err == nil {
		t.Fatal("checkpoint с неверной подписью принят")
	}
	// Checkpoint чужой цепочки при заданном ChainID.
	if _, err := verifyFile(t, path, k, VerifyOptions{ChainID: "agent-other", Checkpoints: cps}); err == nil {
		t.Fatal("принят checkpoint чужой цепочки")
	}
}

// Повтор decision record'а (тот же record_id) отвергается даже при верных подписях.
func TestDuplicateRecordID(t *testing.T) {
	s, k := newSigner(t)
	path := filepath.Join(t.TempDir(), "c.jsonl")
	w, err := OpenWriter(path, "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r := shadowRecord(t, "noop_requested_l0")
	if _, err := w.Append(r); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Append(r); err != nil { // Writer не держит индекс ID — ловит Verify
		t.Fatal(err)
	}
	if _, err := verifyFile(t, path, k, VerifyOptions{}); err == nil || !strings.Contains(err.Error(), "record_id") {
		t.Fatalf("повтор record_id не обнаружен: %v", err)
	}
}

type failingSigner struct{ *Ed25519Signer }

func (failingSigner) Sign([]byte) ([]byte, error) { return nil, errors.New("KMS недоступен") }

func TestFailClosed(t *testing.T) {
	s, k := newSigner(t)
	path := filepath.Join(t.TempDir(), "c.jsonl")
	w, err := OpenWriter(path, "agent-staging-1", failingSigner{s}, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err := w.Append(shadowRecord(t, "noop_requested_l0")); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("ошибка подписи: %v", err)
	}
	if _, err := w.Checkpoint(); !errors.Is(err, ErrWriterFailed) {
		t.Fatalf("checkpoint после отказа: %v", err)
	}
	if b, _ := os.ReadFile(path); len(b) != 0 {
		t.Fatal("в файл записано без подписи")
	}
	// Ключ не из keyring — отказ при открытии.
	s2, _ := newSigner(t)
	if _, err := OpenWriter(filepath.Join(t.TempDir(), "d.jsonl"), "agent-staging-1", s2, k); err == nil {
		t.Fatal("писатель с ключом вне keyring")
	}
	// Невалидная запись не пишется и Writer не ломает.
	w2, err := OpenWriter(filepath.Join(t.TempDir(), "e.jsonl"), "agent-staging-1", s, k)
	if err != nil {
		t.Fatal(err)
	}
	defer w2.Close()
	r := shadowRecord(t, "noop_requested_l0")
	r.Mode = "yolo"
	if _, err := w2.Append(r); err == nil || errors.Is(err, ErrWriterFailed) {
		t.Fatalf("невалидная запись: %v", err)
	}
	if _, err := w2.Append(shadowRecord(t, "noop_requested_l0")); err != nil {
		t.Fatalf("после отклонённой записи: %v", err)
	}
}

func TestValidate(t *testing.T) {
	ok := shadowRecord(t, "downgrade_scale_in_prod")
	if err := ok.Validate(); err != nil {
		t.Fatalf("валидная запись: %v", err)
	}
	bad := map[string]func(r *DecisionRecord){
		"схема":               func(r *DecisionRecord) { r.Schema = "x" },
		"время не UTC":        func(r *DecisionRecord) { r.RecordedAt = "2026-11-07T15:00:00+03:00" },
		"режим":               func(r *DecisionRecord) { r.Mode = "" },
		"lease в shadow":      func(r *DecisionRecord) { r.Lease = &LeaseRef{ID: "l1", FencingToken: 1} },
		"post_check в shadow": func(r *DecisionRecord) { r.PostCheck = &PostCheck{Status: "passed"} },
		"уровень не равен вердикту": func(r *DecisionRecord) {
			r.AutonomyLevel = map[string]string{"L0": "L1", "L1": "L2", "L2": "L3", "L3": "L0"}[r.AutonomyLevel]
		},
		"без вердикта выше L0": func(r *DecisionRecord) { r.Verdict = nil; r.AutonomyLevel = "L1" },
		"ok без тела":          func(r *DecisionRecord) { r.Answer.Body = nil },
		"truncated с телом":    func(r *DecisionRecord) { r.Answer.Status = "truncated" },
		"плохой хеш промпта":   func(r *DecisionRecord) { r.Prompt.SystemSHA256 = "abc" },
		"model без prompt":     func(r *DecisionRecord) { r.Prompt = nil },
		"answer без model": func(r *DecisionRecord) {
			r.Model, r.Prompt = nil, nil
			r.LLM = &LLMInfo{Mode: "off", Reason: "mode_off", Outcome: "not_sent"}
		},
		"retrieved_docs nil":      func(r *DecisionRecord) { r.RetrievedDocs = nil },
		"ID документа с пробелом": func(r *DecisionRecord) { r.RetrievedDocs = []string{"a b"} },
		"dropped без truncated": func(r *DecisionRecord) {
			r.LLM.DroppedFragments = []FragmentRef{{ID: "f1", Source: "metrics.prometheus", Class: "internal", Reason: "context_ceiling"}}
		},
		"инициатор":                 func(r *DecisionRecord) { r.Initiator.Kind = "llm" },
		"live L2 без lease":         func(r *DecisionRecord) { r.Mode = ModeLive; r.Verdict.EffectiveLevel = "L2"; r.AutonomyLevel = "L2" },
		"lease с нулевым fencing":   func(r *DecisionRecord) { r.Mode = ModeLive; r.Lease = &LeaseRef{ID: "l1"} },
		"неизвестный post_check":    func(r *DecisionRecord) { r.Mode = ModeLive; r.PostCheck = &PostCheck{Status: "meh"} },
		"неизвестный статус ответа": func(r *DecisionRecord) { r.Answer.Status = "maybe" },
		"пустой сервис":             func(r *DecisionRecord) { r.Incident.Service = "" },
	}
	for name, f := range bad {
		r := shadowRecord(t, "downgrade_scale_in_prod")
		f(r)
		if err := r.Validate(); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
	// LLM выключен: без model, prompt и answer, L0 по вердикту.
	off := shadowRecord(t, "noop_requested_l0")
	off.Model, off.Prompt, off.Answer = nil, nil, nil
	off.LLM = &LLMInfo{Mode: "off", Outcome: "not_sent", Reason: "mode_off"}
	if err := off.Validate(); err != nil {
		t.Errorf("запись без LLM: %v", err)
	}
	// live L2 с lease допустим.
	live := shadowRecord(t, "downgrade_scale_in_prod")
	live.Mode = ModeLive
	live.Lease = &LeaseRef{ID: "lease-7", FencingToken: 12}
	live.PostCheck = &PostCheck{Status: "passed"}
	if err := live.Validate(); err != nil {
		t.Errorf("live с lease: %v", err)
	}
}

// Запись детерминирована: одинаковый record даёт одинаковый record_sha256 независимо от порядка заполнения map.
func TestRecordHashDeterministic(t *testing.T) {
	r := shadowRecord(t, "downgrade_scale_in_prod")
	n, c := int64(10), 0.25
	r.Answer.Usage = &Usage{PromptTokens: &n, CostReported: &c, ChargedTokens: 10, CostUSD: 0.5}
	r.Answer.SchemaErrors = []string{}
	a, _ := json.Marshal(r)
	var back DecisionRecord
	if err := strictjson.Decode(a, &back); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(&back)
	if !bytes.Equal(a, b) {
		t.Fatalf("повторная сериализация отличается:\n%s\n%s", a, b)
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "k.pem"), filepath.Join(dir, "k.pub.pem")
	p, err := GenerateKey(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(priv, pub); err == nil {
		t.Fatal("существующий ключ перезаписан")
	}
	if st, _ := os.Stat(priv); st.Mode().Perm() != 0o600 {
		t.Fatalf("права приватного ключа %v", st.Mode().Perm())
	}
	s, err := LoadPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := LoadPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Equal(p2) || s.KeyID() != KeyID(p2) {
		t.Fatal("ключи не совпадают")
	}
	if _, err := LoadPublicKey(priv); err == nil {
		t.Fatal("приватный ключ прочитан как открытый")
	}
	sig, _ := s.Sign([]byte("m"))
	if err := (Keyring{s.KeyID(): p2}).verify(s.KeyID(), []byte("m"), sig); err != nil {
		t.Fatal(err)
	}
}
