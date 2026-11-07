package llmrouter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/pyjson"
)

const goldenDir = "../../eval/golden-synthetic"

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// readJSONL разбирает каждую строку через pyjson.
func readJSONL(t testing.TB, path string) []*pyjson.Value {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*pyjson.Value
	for i, ln := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) == 0 {
			continue
		}
		v, err := pyjson.Parse(ln)
		if err != nil {
			t.Fatalf("%s:%d: %v", path, i+1, err)
		}
		out = append(out, v)
	}
	return out
}

// loadProbeV3 читает набор с диска, сверяя sha256 с manifest.
func loadProbeV3(t testing.TB) []*pyjson.Value {
	t.Helper()
	mb, err := os.ReadFile(filepath.Join(goldenDir, "data/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	man, err := pyjson.Parse(mb)
	if err != nil {
		t.Fatal(err)
	}
	e := man.Get("sets").Get("probe")
	file, want := e.Get("file").S, e.Get("sha256").S
	raw, err := os.ReadFile(filepath.Join(goldenDir, file))
	if err != nil {
		t.Fatal(err)
	}
	if got := sha(raw); got != want {
		t.Fatalf("%s: sha256 %.12s != manifest %.12s", file, got, want)
	}
	cases := readJSONL(t, filepath.Join(goldenDir, file))
	if len(cases) != 480 {
		t.Fatalf("кейсов %d, ожидается 480", len(cases))
	}
	return cases
}

type refFile struct {
	path string
	rows map[string]*pyjson.Value
	meta *pyjson.Value
}

func loadRefs(t testing.TB, profile string) refFile {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(goldenDir, "refs", profile, "probe-v3-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("эталон probe-v3 профиля %s: найдено %d файлов (%v), нужен ровно один", profile, len(paths), err)
	}
	rf := refFile{path: paths[0], rows: map[string]*pyjson.Value{}}
	for _, r := range readJSONL(t, paths[0]) {
		rf.rows[r.Get("id").S] = r
	}
	if len(rf.rows) != 480 {
		t.Fatalf("%s: строк %d, ожидается 480", paths[0], len(rf.rows))
	}
	mb, err := os.ReadFile(paths[0] + ".meta.json")
	if err != nil {
		t.Fatal(err)
	}
	if rf.meta, err = pyjson.Parse(mb); err != nil {
		t.Fatal(err)
	}
	return rf
}

type keyMap struct {
	source    string
	kind      FragmentKind
	required  bool
	relevance int
	list      bool
}

var probeKeys = map[string]keyMap{
	"alert":           {"alerts.alertmanager", KindGeneric, true, 100, false},
	"allowed_actions": {"platform.action_catalog", KindGeneric, true, 100, false},
	"service":         {"platform.topology", KindGeneric, true, 100, false},
	"rollout":         {"k8s.rollout_status", KindGeneric, false, 60, false},
	"db":              {"db.aggregates", KindGeneric, false, 60, false},
	"pdb":             {"manifests.k8s", KindGeneric, false, 20, false},
	"metrics":         {"metrics.prometheus", KindMetricSeries, false, 50, true},
	"k8s_events":      {"k8s.events", KindGeneric, false, 40, true},
	"deploys":         {"k8s.deploys", KindGeneric, false, 40, true},
}

// caseRequest раскладывает input кейса на секции и фрагменты (секции — по порядку ключей кейса).
func caseRequest(t testing.TB, c *pyjson.Value) (Request, int) {
	t.Helper()
	in := c.Get("input")
	id := c.Get("id").S
	req := Request{IncidentID: id, Service: in.Get("service").Get("name").S, Mode: ModeHybrid}
	n := 0
	for _, m := range in.Members {
		km, ok := probeKeys[m.Key]
		if !ok {
			t.Fatalf("%s: неизвестный ключ input %q: добавьте его в отображение секций", id, m.Key)
		}
		sec := Section{Key: m.Key, List: km.list}
		mk := func(suffix string, v *pyjson.Value) Fragment {
			n++
			return Fragment{ID: id + "/" + m.Key + suffix, Source: km.source, Kind: km.kind, Required: km.required, Relevance: km.relevance, Value: v}
		}
		if km.list {
			for i, it := range m.Value.Items {
				sec.Fragments = append(sec.Fragments, mk(fmt.Sprintf("/%d", i), it))
			}
		} else {
			sec.Fragments = []Fragment{mk("", m.Value)}
		}
		req.Sections = append(req.Sections, sec)
	}
	return req, n
}

var probeProfiles = []struct {
	name string
	role Role
}{{"inceptron-fp8", RolePrimary}, {"wafer-nvfp4", RoleFallback}}

func TestProbeV3MetaMatchesAssets(t *testing.T) {
	a := loadAssets(t)
	const hint = "; смена profiles.json, промпта или схемы требует новых эталонов probe-v3"
	for _, pp := range probeProfiles {
		rf := loadRefs(t, pp.name)
		h := rf.meta.Get("hashes")
		for k, got := range map[string]string{"prompt": a.SystemSHA256, "schema": a.SchemaSHA256, "config": a.ConfigSHA256} {
			if want := h.Get(k).S; want != got {
				t.Errorf("%s: hashes.%s эталона %.12s != ассет %.12s%s", pp.name, k, want, got, hint)
			}
		}
		prof := a.Primary
		if pp.role == RoleFallback {
			prof = a.Fallback
		}
		if prof.Name != pp.name {
			t.Errorf("роль %s: профиль %s, ожидается %s", pp.role, prof.Name, pp.name)
		}
		if got, want := pyjson.Marshal(rf.meta.Get("provider_request"), pyjson.Canonical), pyjson.Marshal(prof.Provider, pyjson.Canonical); !bytes.Equal(got, want) {
			t.Errorf("%s: provider_request эталона %s != профиль %s%s", pp.name, got, want, hint)
		}
		g := rf.meta.Get("generation")
		cfg := a.Config.Generation
		if !bytes.Equal(pyjson.Marshal(g.Get("temperature"), pyjson.Canonical), pyjson.Marshal(cfg.Temperature, pyjson.Canonical)) ||
			!bytes.Equal(pyjson.Marshal(g.Get("seed"), pyjson.Canonical), pyjson.Marshal(cfg.Seed, pyjson.Canonical)) ||
			g.Get("max_tokens").Int != fmt.Sprint(cfg.MaxTokens) {
			t.Errorf("%s: generation эталона не совпадает с конфигурацией%s", pp.name, hint)
		}
		if rf.meta.Get("model").S != a.Config.Model {
			t.Errorf("%s: model эталона %q != %q", pp.name, rf.meta.Get("model").S, a.Config.Model)
		}
	}
}

func TestProbeV3Reproducible(t *testing.T) {
	cases := loadProbeV3(t)
	ctx := context.Background()
	for _, pp := range probeProfiles {
		rf := loadRefs(t, pp.name)
		im := &identityMasker{}
		rg := newRig(t, im, &stubTransport{}, "", nil)
		var emptyEvents, noDB, noPDB, withDB int
		for _, c := range cases {
			req, nfrag := caseRequest(t, c)
			before := im.calls.Load()
			p, err := rg.r.Prepare(ctx, req, pp.role)
			if err != nil {
				t.Fatalf("%s %s: %v", pp.name, req.IncidentID, err)
			}
			ref := rf.rows[req.IncidentID]
			if ref == nil {
				t.Fatalf("%s: нет в эталоне %s", req.IncidentID, pp.name)
			}
			if p.NotSent != "" || len(p.Excluded) != 0 || len(p.Dropped) != 0 || p.LabelsDropped != 0 || p.DataClass.String() != "internal" {
				t.Fatalf("%s %s: NotSent=%q excluded=%d dropped=%d labels=%d class=%s", pp.name, req.IncidentID, p.NotSent, len(p.Excluded), len(p.Dropped), p.LabelsDropped, p.DataClass)
			}
			if got := im.calls.Load() - before; got != int64(nfrag) {
				t.Errorf("%s %s: маскировщик вызван %d раз, фрагментов %d", pp.name, req.IncidentID, got, nfrag)
			}
			wantSHA, wantEst := ref.Get("request_sha256").S, ref.Get("est_input_tokens").Int
			if p.RequestSHA256 != wantSHA || fmt.Sprint(p.EstInputTokens) != wantEst {
				t.Fatalf("%s %s: request_sha256 %s != эталон %s; est_input_tokens %d != %s; смена profiles.json, промпта или схемы требует новых эталонов",
					pp.name, req.IncidentID, p.RequestSHA256, wantSHA, p.EstInputTokens, wantEst)
			}
			body, err := pyjson.Parse(p.Body)
			if err != nil {
				t.Fatal(err)
			}
			in, err := pyjson.Parse([]byte(userContent(t, p.Body)))
			if err != nil {
				t.Fatal(err)
			}
			_ = body
			if ev := c.Get("input").Get("k8s_events"); ev != nil && len(ev.Items) == 0 {
				emptyEvents++
				if g := in.Get("k8s_events"); g == nil || g.Kind != pyjson.Array || len(g.Items) != 0 {
					t.Errorf("%s: пустой k8s_events должен дойти как []", req.IncidentID)
				}
			}
			if db := c.Get("input").Get("db"); db != nil && db.Kind == pyjson.Null {
				noDB++
				if g := in.Get("db"); g == nil || g.Kind != pyjson.Null {
					t.Errorf("%s: db: null должен дойти как null", req.IncidentID)
				}
			} else if db != nil {
				withDB++
			}
			if c.Get("input").Get("pdb") == nil {
				noPDB++
				if in.Get("pdb") != nil {
					t.Errorf("%s: ключа pdb нет в кейсе, но он появился в запросе", req.IncidentID)
				}
			}
		}
		if emptyEvents == 0 || noDB == 0 || noPDB == 0 || withDB == 0 {
			t.Errorf("%s: набор не покрыл особые случаи: %d %d %d %d", pp.name, emptyEvents, noDB, noPDB, withDB)
		}
	}
}

func userContent(t testing.TB, body []byte) string {
	t.Helper()
	b, err := pyjson.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	return b.Get("messages").Items[1].Get("content").S
}

// openRouterReply строит ответ OpenRouter по строке эталона.
func openRouterReply(ref *pyjson.Value) []byte {
	content := ref.Get("raw_content")
	var cs string
	if content.Kind == pyjson.String {
		cs = content.S
	} else {
		cs = string(pyjson.Marshal(ref.Get("answer"), pyjson.PyDefault))
	}
	u := ref.Get("usage")
	usage := pyjson.NewObject(pyjson.M("prompt_tokens", u.Get("prompt_tokens")), pyjson.M("completion_tokens", u.Get("completion_tokens")),
		pyjson.M("total_tokens", u.Get("total_tokens")),
		pyjson.M("completion_tokens_details", pyjson.NewObject(pyjson.M("reasoning_tokens", u.Get("reasoning_tokens")))),
		pyjson.M("cost", u.Get("cost_reported")))
	reply := pyjson.NewObject(
		pyjson.M("id", ref.Get("generation_id")), pyjson.M("model", ref.Get("model_reported")), pyjson.M("provider", ref.Get("provider_actual")),
		pyjson.M("choices", pyjson.NewArray(pyjson.NewObject(pyjson.M("finish_reason", ref.Get("finish_reason")),
			pyjson.M("message", pyjson.NewObject(pyjson.M("role", pyjson.NewString("assistant")), pyjson.M("content", pyjson.NewString(cs))))))),
		pyjson.M("usage", usage))
	return pyjson.Marshal(reply, pyjson.PyDefault)
}

func TestProbeV3ReplayHTTP(t *testing.T) {
	cases := loadProbeV3(t)
	refs := map[string]*pyjson.Value{} // sha тела → строка эталона
	byProfile := map[string]refFile{}
	for _, pp := range probeProfiles {
		rf := loadRefs(t, pp.name)
		byProfile[pp.name] = rf
		for _, row := range rf.rows {
			refs[row.Get("request_sha256").S] = row
		}
	}
	secret := runtimeSecret(t)
	var (
		mu      sync.Mutex
		failPri bool
		bad     []string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer "+secret ||
			r.Header.Get("Content-Type") != "application/json" {
			mu.Lock()
			bad = append(bad, "метод, путь или заголовки: "+r.Method+" "+r.URL.Path)
			mu.Unlock()
			w.WriteHeader(400)
			return
		}
		pb, err := pyjson.Parse(body)
		if err != nil {
			w.WriteHeader(400)
			return
		}
		mu.Lock()
		f := failPri
		mu.Unlock()
		if f && pb.Get("provider").Get("only").Items[0].S == "inceptron" {
			w.WriteHeader(503)
			return
		}
		ref := refs[sha(body)]
		if ref == nil {
			mu.Lock()
			bad = append(bad, "тело не найдено в эталонах: "+sha(body))
			mu.Unlock()
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(openRouterReply(ref))
	}))
	defer srv.Close()

	// Реальный аудит и ключ из файла.
	dir := t.TempDir()
	signer, keys := newAuditSigner(t)
	chain := filepath.Join(dir, "chain.jsonl")
	w, err := audit.OpenWriter(chain, "router-test", signer, keys)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "key")
	os.WriteFile(keyPath, []byte(secret+"\n"), 0o600)
	t.Setenv("OPENROUTER_API_KEY_FILE", keyPath)
	key, err := openrouter.LoadAPIKey(os.Getenv)
	if err != nil {
		t.Fatal(err)
	}
	a := loadAssets(t)
	clock := newFakeClock()
	newRouter := func() *Router {
		cl, err := openrouter.NewClient(&a.Config, key, openrouter.NewHTTPTransport(),
			openrouter.WithURL(srv.URL+"/api/v1/chat/completions"), openrouter.WithSleep(func(context.Context, time.Duration) error { return nil }))
		if err != nil {
			t.Fatal(err)
		}
		r, err := New(Options{Assets: a, Client: cl, Masker: &identityMasker{}, Events: w, Clock: clock,
			Budgets: BudgetConfig{IncidentTokens: 1 << 40, ServiceDayTokens: 1 << 40}, Failover: DefaultFailover(), RouterID: "llm-router-test"})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	ctx := context.Background()
	pass := func(r *Router, profile string, role Role) {
		rf := byProfile[profile]
		truncated := 0
		for i, c := range cases {
			req, _ := caseRequest(t, c)
			res, err := r.Route(ctx, req)
			if err != nil {
				t.Fatalf("%s %s: %v", profile, req.IncidentID, err)
			}
			ref := rf.rows[req.IncidentID]
			if res.Outcome != "sent" || res.Role != role || res.Parsed == nil || res.ErrorKind != "" {
				t.Fatalf("%s %s: outcome=%s role=%s err=%q parsed=%v", profile, req.IncidentID, res.Outcome, res.Role, res.ErrorKind, res.Parsed != nil)
			}
			ps := res.Parsed
			if ps.Status != ref.Get("status").S {
				t.Fatalf("%s %s: статус %s != %s", profile, req.IncidentID, ps.Status, ref.Get("status").S)
			}
			if ps.Status == "truncated" {
				truncated++
			}
			if ps.ProviderActual != ref.Get("provider_actual").S || ps.ModelReported != ref.Get("model_reported").S ||
				ps.FinishReason != ref.Get("finish_reason").S || ps.GenerationID != ref.Get("generation_id").S {
				t.Fatalf("%s %s: метаданные ответа не совпали", profile, req.IncidentID)
			}
			u := ref.Get("usage")
			if ps.Usage.PromptTokens == nil || fmt.Sprint(*ps.Usage.PromptTokens) != u.Get("prompt_tokens").Int ||
				fmt.Sprint(*ps.Usage.CompletionTokens) != u.Get("completion_tokens").Int || fmt.Sprint(*ps.Usage.ReasoningTokens) != u.Get("reasoning_tokens").Int {
				t.Fatalf("%s %s: usage не совпал", profile, req.IncidentID)
			}
			if ps.Status == "ok" && !bytes.Equal(pyjson.Marshal(ps.Answer, pyjson.Canonical), pyjson.Marshal(ref.Get("answer"), pyjson.Canonical)) {
				t.Fatalf("%s %s: ответ не совпал", profile, req.IncidentID)
			}
			rec := &audit.DecisionRecord{Schema: audit.RecordSchema, RecordID: audit.NewRecordID(), RecordedAt: audit.Timestamp(clock.Now()),
				Mode: audit.ModeShadow, Incident: audit.IncidentRef{ID: req.IncidentID, Service: req.Service, Environment: "staging"},
				Initiator: audit.Actor{Kind: "agent", ID: "agent-test"}, RetrievedDocs: []string{}, AutonomyLevel: "L0"}
			res.Apply(rec)
			if err := rec.Validate(); err != nil {
				t.Fatalf("%s %s: decision record: %v", profile, req.IncidentID, err)
			}
			if rec.Prompt.RequestSHA256 != "sha256:"+ref.Get("request_sha256").S || rec.Model.EndpointRole != string(role) {
				t.Fatalf("%s %s: request_sha256/role в записи", profile, req.IncidentID)
			}
			if _, err := w.Append(rec); err != nil {
				t.Fatalf("%s #%d: %v", profile, i, err)
			}
			r.CloseIncident(req.IncidentID)
		}
		if profile == "inceptron-fp8" && truncated != 1 {
			t.Errorf("truncated: %d, ожидается 1", truncated)
		}
	}
	pass(newRouter(), "inceptron-fp8", RolePrimary)

	// Проход 2: primary недоступен — три неудачи, endpoint down, повтор на Wafer.
	mu.Lock()
	failPri = true
	mu.Unlock()
	pass(newRouter(), "wafer-nvfp4", RoleFallback)

	mu.Lock()
	defer mu.Unlock()
	if len(bad) != 0 {
		t.Errorf("сервер получил неожиданные запросы (%d): %s", len(bad), strings.Join(bad[:min(3, len(bad))], "; "))
	}
	w.Close()
	var st audit.VerifyStats
	f, _ := os.Open(chain)
	defer f.Close()
	if _, err := audit.Verify(f, keys, audit.VerifyOptions{Stats: &st}); err != nil {
		t.Fatal(err)
	}
	if st.Records != 960 || st.RouterEvents != 2 {
		t.Errorf("цепочка: %+v, ожидается 960 записей и 2 события", st)
	}
}
