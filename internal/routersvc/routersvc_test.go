package routersvc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/openrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

func (f *fixture) identity(rt *Runtime) routerstate.Identity {
	return routerstate.Identity{RouterID: f.cfg.RouterID, Primary: rt.Assets.Primary.Name, Fallback: rt.Assets.Fallback.Name}
}

func TestOpenFirstStart(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	for _, p := range []string{f.cfg.StatePath, f.cfg.Audit.Chain} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("не создан: %v", err)
		}
	}
	st := rt.Status()
	if st.Halted || st.Active != rt.Assets.Primary.Name || st.RouterID != f.cfg.RouterID || st.ChainID != f.cfg.Audit.ChainID ||
		st.Masker == "" || st.LastHalt != nil || st.LastResume != nil {
		t.Fatalf("%+v", st)
	}
	if st.Endpoints[rt.Assets.Primary.Name] != "up" {
		t.Errorf("endpoints: %v", st.Endpoints)
	}
	if !strings.Contains(f.log.String(), `"llmrouter_opened"`) && !strings.Contains(f.log.String(), `llmrouter_opened`) {
		t.Errorf("нет llmrouter_opened: %s", f.log.String())
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil { // идемпотентно
		t.Fatalf("второй Close: %v", err)
	}
	evs, _ := f.verifyChain()
	if len(evs) == 0 || evs[0].Kind != "state_created" {
		t.Fatalf("цепочка: %v", kinds(evs))
	}
	// после Close оба ресурса свободны
	fs, err := routerstate.OpenFile(f.cfg.StatePath, f.identity(rt), routerstate.FileOptions{})
	if err != nil {
		t.Fatalf("store после Close: %v", err)
	}
	fs.Close()
	w, err := audit.OpenWriter(f.cfg.Audit.Chain, f.cfg.Audit.ChainID, f.secrets().Signer, f.keyring())
	if err != nil {
		t.Fatalf("цепочка после Close: %v", err)
	}
	w.Close()
}

func TestOpenReopenKeepsState(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	rt := f.mustOpen(false)
	defer rt.Close()
	if rt.Status().Halted {
		t.Fatalf("штатный перезапуск остановлен: %+v", rt.Status())
	}
}

func TestOpenNotInitialized(t *testing.T) {
	f := newFixture(t)
	if _, err := f.open(false); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("%v", err)
	}
	if Classify(mustErr(f.open(false))) != ClassUsage {
		t.Error("класс")
	}
	ents, err := os.ReadDir(f.dir + "/data")
	must(t, err)
	if len(ents) != 0 {
		t.Fatalf("созданы файлы: %v", ents)
	}
	// Один из двух файлов отсутствует.
	for _, rm := range []string{f.cfg.StatePath, f.cfg.Audit.Chain} {
		f.mustOpen(true).Close()
		must(t, os.Remove(rm))
		before := dirNames(t, f.dir+"/data")
		if _, err := f.open(false); !errors.Is(err, ErrNotInitialized) {
			t.Fatalf("без %s: %v", rm, err)
		}
		if after := dirNames(t, f.dir+"/data"); strings.Join(before, ",") != strings.Join(after, ",") {
			t.Errorf("каталог изменён: %v -> %v", before, after)
		}
		must(t, os.Remove(f.cfg.StatePath+".lock"))
		os.Remove(f.cfg.StatePath)
		os.Remove(f.cfg.Audit.Chain)
		os.Remove(f.cfg.Audit.Chain + ".lock")
	}
}

func mustErr(_ *Runtime, err error) error { return err }

func dirNames(t *testing.T, d string) []string {
	ents, err := os.ReadDir(d)
	must(t, err)
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestOpenErrorsBeforeDisk(t *testing.T) {
	f := newFixture(t)
	check := func(name string, mut func(), wantUsage bool) {
		t.Helper()
		defer func() {
			f2 := newFixture(t)
			f.cfg, f.env = f2.cfg, f2.env
			f.cfg.StatePath = f.dir + "/data/router.state"
			f.cfg.Audit.Chain = f.dir + "/data/audit.jsonl"
		}()
		mut()
		var sec Secrets
		sec, _ = LoadSecrets(f.getenv)
		if name == "секреты" {
			if _, err := LoadSecrets(f.getenv); err == nil {
				t.Fatal("секреты приняты")
			}
		}
		if sec.Signer == nil {
			sec = f.secretsFromFirst()
		}
		_, err := Open(f.cfg, sec, OpenOptions{Create: true}, f.deps())
		if err == nil {
			t.Fatalf("%s: Open успешен", name)
		}
		if Classify(err) != ClassUsage {
			t.Errorf("%s: класс %v (%v)", name, Classify(err), err)
		}
		if n := dirNames(t, f.dir+"/data"); len(n) != 0 {
			t.Errorf("%s: созданы файлы %v", name, n)
		}
	}
	check("router_id", func() { f.cfg.RouterID = "a b" }, true)
	check("бюджет", func() { f.cfg.Budgets.IncidentTokens = -1 }, true)
	check("internal_nets", func() { f.cfg.InternalNets = []string{"bad"} }, true)
	check("публичный ключ", func() { f.cfg.Audit.PublicKeys = []string{f.dir + "/nope.pub"} }, true)
	// Signer == nil.
	_, err := Open(f.cfg, Secrets{}, OpenOptions{Create: true}, f.deps())
	if err == nil || Classify(err) != ClassUsage {
		t.Errorf("без Signer: %v", err)
	}
	if n := dirNames(t, f.dir+"/data"); len(n) != 0 {
		t.Errorf("созданы файлы %v", n)
	}
}

// secretsFromFirst — резервный набор секретов, когда мутация сломала загрузку.
func (f *fixture) secretsFromFirst() Secrets {
	f2 := newFixture(f.t)
	return f2.secrets()
}

func TestFailClosedCorruptStore(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	must(t, os.WriteFile(f.cfg.StatePath, []byte("мусор, а не состояние\n"), 0o600))
	chainBefore := fileBytes(t, f.cfg.Audit.Chain)
	_, err := f.open(true)
	if !errors.Is(err, routerstate.ErrCorrupt) || Classify(err) != ClassFailClosed {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(chainBefore, fileBytes(t, f.cfg.Audit.Chain)) {
		t.Error("цепочка изменена")
	}
	if Hint(err) == "" {
		t.Error("нет подсказки")
	}
}

func TestFailClosedIdentity(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	f.cfg.RouterID = "another-router"
	_, err := f.open(true)
	if !errors.Is(err, routerstate.ErrIdentity) || Classify(err) != ClassFailClosed {
		t.Fatalf("%v", err)
	}
	// ресурсы освобождены
	f.cfg.RouterID = "llmrouter-test"
	f.mustOpen(false).Close()
}

func TestFailClosedCorruptChain(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	b := fileBytes(t, f.cfg.Audit.Chain)
	i := bytes.IndexByte(b, '\n')
	if i < 10 {
		t.Fatalf("цепочка: %q", b)
	}
	b[i/2] ^= 0x01 // байт в середине первой строки
	must(t, os.WriteFile(f.cfg.Audit.Chain, b, 0o600))
	// store существует и не должен измениться
	storeBefore := fileBytes(t, f.cfg.StatePath)
	_, err := f.open(true)
	var ce *audit.ChainError
	if !errors.As(err, &ce) || Classify(err) != ClassFailClosed {
		t.Fatalf("%v", err)
	}
	if !bytes.Equal(storeBefore, fileBytes(t, f.cfg.StatePath)) {
		t.Error("store изменён")
	}
	// и вариант без store: store не создаётся
	must(t, os.Remove(f.cfg.StatePath))
	if _, err := f.open(true); !errors.As(err, &ce) {
		t.Fatalf("%v", err)
	}
	if _, err := os.Stat(f.cfg.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("store создан при повреждённой цепочке: %v", err)
	}
}

func TestBusy(t *testing.T) {
	f := newFixture(t)
	first := f.mustOpen(true)
	_, err := f.open(true)
	if !errors.Is(err, audit.ErrLocked) || Classify(err) != ClassBusy || Hint(err) == "" {
		t.Fatalf("второй Open: %v", err)
	}
	first.Close()
	f.mustOpen(false).Close()

	// Занят только store: цепочка, открытая в Open, освобождается.
	fs, err := routerstate.OpenFile(f.cfg.StatePath, f.identity(first), routerstate.FileOptions{})
	must(t, err)
	_, err = f.open(false)
	if !errors.Is(err, routerstate.ErrLocked) || Classify(err) != ClassBusy {
		t.Fatalf("store занят: %v", err)
	}
	w, err := audit.OpenWriter(f.cfg.Audit.Chain, f.cfg.Audit.ChainID, f.secrets().Signer, f.keyring())
	if err != nil {
		t.Fatalf("цепочка не освобождена после неудачного Open: %v", err)
	}
	w.Close()
	fs.Close()
	f.mustOpen(false).Close()

	// Занята только цепочка.
	w, err = audit.OpenWriter(f.cfg.Audit.Chain, f.cfg.Audit.ChainID, f.secrets().Signer, f.keyring())
	must(t, err)
	_, err = f.open(false)
	if !errors.Is(err, audit.ErrLocked) || Classify(err) != ClassBusy {
		t.Fatalf("цепочка занята: %v", err)
	}
	fs, err = routerstate.OpenFile(f.cfg.StatePath, f.identity(first), routerstate.FileOptions{})
	if err != nil {
		t.Fatalf("store не освобождён: %v", err)
	}
	fs.Close()
	w.Close()
	f.mustOpen(false).Close()
}

func TestStateLostAndResume(t *testing.T) {
	f := newFixture(t)
	f.mustOpen(true).Close()
	must(t, os.Remove(f.cfg.StatePath))
	rt := f.mustOpen(true)
	defer rt.Close()
	st := rt.Status()
	if !st.Halted || st.HaltReason != "state_lost" || st.LastHalt == nil || st.LastHalt.Reason != "state_lost" {
		t.Fatalf("%+v", st)
	}
	if !strings.Contains(f.log.String(), "llmrouter_halted") {
		t.Error("нет WARN llmrouter_halted")
	}
	// Некорректный operator.
	if err := rt.Resume(context.Background(), "bad operator"); err == nil {
		t.Fatal("некорректный operator принят")
	}
	if !rt.Status().Halted {
		t.Fatal("halt снят при ошибке")
	}
	if err := rt.Resume(context.Background(), "alice"); err != nil {
		t.Fatal(err)
	}
	st = rt.Status()
	if st.Halted || st.LastResume == nil || st.LastResume.Initiator.Kind != "human" || st.LastResume.Initiator.ID != "alice" {
		t.Fatalf("%+v", st)
	}
	_, n0 := f.verifyChain()
	if err := rt.Resume(context.Background(), "alice"); !errors.Is(err, ErrNothingToResume) {
		t.Fatalf("%v", err)
	}
	if Classify(ErrNothingToResume) != ClassFailClosed {
		t.Error("класс ErrNothingToResume")
	}
	if _, n1 := f.verifyChain(); n1 != n0 {
		t.Errorf("длина цепочки изменилась: %v -> %v", n0, n1)
	}
	evs, _ := f.verifyChain()
	if !has(evs, "router_halted") || !has(evs, "router_resumed") {
		t.Errorf("%v", kinds(evs))
	}
	// Resume на здоровом роутере из чистого старта.
	f2 := newFixture(t)
	rt2 := f2.mustOpen(true)
	defer rt2.Close()
	if err := rt2.Resume(context.Background(), "alice"); !errors.Is(err, ErrNothingToResume) {
		t.Fatalf("%v", err)
	}
	evs2, _ := f2.verifyChain()
	if has(evs2, "router_resumed") {
		t.Error("пустой router_resumed")
	}
}

func TestChainLost(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	req, _, err := ParseRequest(requestJSON("hybrid"))
	must(t, err)
	res, rerr := rt.Router.Route(context.Background(), req)
	if rerr != nil || res.Outcome != "sent" {
		t.Fatalf("%v %+v", rerr, res)
	}
	rt.Close()
	must(t, os.Remove(f.cfg.Audit.Chain))
	rt = f.mustOpen(true)
	defer rt.Close()
	if st := rt.Status(); !st.Halted || st.HaltReason != "chain_lost" {
		t.Fatalf("%+v", st)
	}
}

func TestServeCancel(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := rt.Serve(ctx); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	must(t, rt.Close())
	fs, err := routerstate.OpenFile(f.cfg.StatePath, f.identity(rt), routerstate.FileOptions{})
	must(t, err)
	fs.Close()
	// отмена до старта тоже штатна
	rt = f.mustOpen(false)
	defer rt.Close()
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := rt.Serve(ctx2); err != nil {
		t.Fatalf("Serve(canceled): %v", err)
	}
}

func TestServeHealthTransitions(t *testing.T) {
	f := newFixture(t)
	f.cfg.Failover.HealthInterval = "10ms"
	f.tr.setGet(func() (openrouter.Response, error) { return openrouter.Response{Status: 500}, nil })
	d := f.deps()
	d.StatePoll = 5 * time.Millisecond
	rt, err := Open(f.cfg, f.secrets(), OpenOptions{Create: true}, d)
	must(t, err)
	defer rt.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()
	waitFor(t, "endpoint_down и active_changed", func() bool {
		return rt.Status().Active != rt.Assets.Primary.Name && strings.Contains(f.log.String(), `"router_state"`)
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	evs, _ := f.verifyChain()
	var down, changed bool
	for _, e := range evs {
		down = down || (e.Kind == "endpoint_down" && e.Ev.Endpoint == rt.Assets.Primary.Name)
		changed = changed || e.Kind == "active_changed"
	}
	if !down || !changed {
		t.Fatalf("события: %v", kinds(evs))
	}
	if !strings.Contains(f.log.String(), `"msg":"router_state"`) || !strings.Contains(f.log.String(), `"active":`) {
		t.Errorf("нет router_state: %s", f.log.String())
	}
}

// failStore отказывает на Append после взвода.
type failStore struct {
	routerstate.Store
	armed *atomic.Bool
}

func (s failStore) Append(op routerstate.Op) error {
	if s.armed.Load() {
		return routerstate.ErrFailed
	}
	return s.Store.Append(op)
}

func TestServeStoreFailure(t *testing.T) {
	f := newFixture(t)
	f.cfg.Failover.HealthInterval = "10ms"
	f.tr.setGet(func() (openrouter.Response, error) { return openrouter.Response{Status: 500}, nil })
	var armed atomic.Bool
	d := f.deps()
	d.StatePoll = 5 * time.Millisecond
	d.WrapStore = func(s routerstate.Store) routerstate.Store { return failStore{s, &armed} }
	rt, err := Open(f.cfg, f.secrets(), OpenOptions{Create: true}, d)
	must(t, err)
	armed.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = rt.Serve(ctx)
	if err == nil {
		t.Fatal("Serve вернул nil при отказе store")
	}
	if !errors.Is(err, llmrouter.ErrStateStore) && !errors.Is(err, llmrouter.ErrAuditFailed) && !errors.Is(err, routerstate.ErrFailed) {
		t.Fatalf("неожиданная ошибка: %v", err)
	}
	if Classify(err) != ClassFailClosed {
		t.Errorf("класс %v", Classify(err))
	}
	if !strings.Contains(f.log.String(), "health_loop_stopped") {
		t.Error("нет health_loop_stopped")
	}
	armed.Store(false)
	rt.Close()
	rt2 := f.mustOpen(false) // блокировки сняты
	rt2.Close()
}

func TestStatusJSONFields(t *testing.T) {
	f := newFixture(t)
	rt := f.mustOpen(true)
	defer rt.Close()
	b := mustJSON(t, rt.Status())
	for _, k := range []string{"router_id", "chain_id", "chain_seq", "active", "halted", "halt_reason", "endpoints", "masker_version", "last_router_halted", "last_router_resumed"} {
		if !strings.Contains(b, `"`+k+`"`) {
			t.Errorf("нет поля %s в %s", k, b)
		}
	}
}
