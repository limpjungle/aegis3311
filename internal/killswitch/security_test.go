package killswitch

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// Обходы порога двух подписей на уровне Parse.
func TestParseSignatureBypassAttempts(t *testing.T) {
	tk := newTKeys(t)
	d := Document{Schema: DocSchema, Clusters: []string{}, Actions: []string{}, IssuedAt: "2026-11-08T10:00:00.000Z", TTL: "1h0m0s", Issuer: "x", Signatures: []Signature{}}
	sa, _ := SignatureFor(d, tk.signers["a"], "i-a")

	// один ключ дважды (в обход AddSignature) — документ отвергается целиком
	dup := d
	dup.Signatures = []Signature{sa, sa}
	if _, err := Parse(Marshal(dup), tk.ring, ParseOptions{}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("две подписи одного ключа: %v", err)
	}
	// чужой issuer в подписи ключа a: не засчитывается; одна валидная b + подпись a с чужим issuer = запятнан и одна подпись
	forged, _ := SignatureFor(d, tk.signers["a"], "i-b") // ключ a, но issuer b
	sb, _ := SignatureFor(d, tk.signers["b"], "i-b")
	f := d
	f.Signatures = []Signature{forged, sb}
	v, err := Parse(Marshal(f), tk.ring, ParseOptions{})
	if err != nil || len(v.Valid) != 1 || !v.Tainted || v.Confirmation("c1") != "none" {
		t.Errorf("подпись с чужим issuer: err=%v valid=%d tainted=%v conf=%s", err, len(v.Valid), v.Tainted, v.Confirmation("c1"))
	}
	// подпись a, перенесённая на документ с другим содержимым
	g := d
	g.Global = true
	g.Signatures = []Signature{sa}
	if _, err := Parse(Marshal(g), tk.ring, ParseOptions{}); err == nil {
		t.Error("подпись другого документа принята")
	}
	// подпись a под ключом b (key_id подменён)
	swap := sa
	swap.KeyID = tk.signers["b"].KeyID()
	swap.Issuer = "i-b"
	h := d
	h.Signatures = []Signature{swap}
	if _, err := Parse(Marshal(h), tk.ring, ParseOptions{}); err == nil {
		t.Error("подмена key_id принята")
	}
	// пятая подпись
	var many []Signature
	for _, n := range []string{"a", "b", "c", "r1", "r2"} {
		s, _ := SignatureFor(d, tk.signers[n], "i-"+n)
		many = append(many, s)
	}
	m := d
	m.Signatures = many
	if _, err := Parse(Marshal(m), tk.ring, ParseOptions{}); err == nil {
		t.Error("5 подписей приняты")
	}
	// ключ агента (не в keyring) + одна валидная: запятнан, не подтверждает
	t2 := newTKeys(t)
	se, _ := SignatureFor(d, t2.signers["a"], "i-a")
	k := d
	k.Signatures = []Signature{sa, se}
	if v, err := Parse(Marshal(k), tk.ring, ParseOptions{}); err != nil || !v.Tainted || v.Confirmation("") != "none" {
		t.Errorf("незнакомый ключ: %v tainted=%v", err, v.Tainted)
	}
}

func TestParseMalformedAndStrict(t *testing.T) {
	tk := newTKeys(t)
	good := string(tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	cases := map[string]string{
		"дубль ключа":        strings.Replace(good, `"global":false`, `"global":false,"global":true`, 1),
		"лишнее поле":        strings.Replace(good, `"global":false`, `"global":false,"extra":1`, 1),
		"global не bool":     strings.Replace(good, `"global":false`, `"global":"false"`, 1),
		"clusters null":      strings.Replace(good, `"clusters":[]`, `"clusters":null`, 1),
		"нет actions":        strings.Replace(good, `"actions":[],`, ``, 1),
		"ttl 30s":            strings.Replace(good, `"ttl":"1h0m0s"`, `"ttl":"30s"`, 1),
		"ttl 25h":            strings.Replace(good, `"ttl":"1h0m0s"`, `"ttl":"25h"`, 1),
		"issued_at смещение": strings.Replace(good, `.000Z"`, `.000+00:00"`, 1),
		"пусто":              ``,
		"массив":             `[]`,
		"мусор после":        good + `{}`,
	}
	for name, raw := range cases {
		if _, err := Parse([]byte(raw), tk.ring, ParseOptions{}); err == nil {
			t.Errorf("%s: документ принят", name)
		}
	}
	if _, err := Parse([]byte(good), tk.ring, ParseOptions{}); err != nil {
		t.Fatalf("эталон не разобран: %v", err)
	}
	// oversize ровно на границе
	big := []byte(good + strings.Repeat(" ", MaxDocBytes))
	_, err := Parse(big, tk.ring, ParseOptions{})
	var de *DocError
	if !errors.As(err, &de) || de.Class != "oversize" {
		t.Errorf("oversize: %v", err)
	}
	// повтор cluster / action
	for _, raw := range [][]byte{tk.doc(t, false, []string{"c1", "c1"}, nil, t0, time.Hour, "a")} {
		if _, err := Parse(raw, tk.ring, ParseOptions{}); err == nil {
			t.Error("повтор cluster принят")
		}
	}
}

// Подтверждение запятнанным документом, с одним ключом, oncall+renewer после stop, future и просрочка.
func TestEvaluateNoSoftReleasePaths(t *testing.T) {
	tk := newTKeys(t)
	now := t0.Add(10 * time.Minute)
	stopAt := t0.Add(5 * time.Minute)
	W := Marks{Stop: stopAt}

	d := func(at time.Time, names ...string) []byte { return tk.doc(t, false, nil, nil, at, time.Hour, names...) }
	// oncall + renewer (confirmation=renewer) новее stop, но R <= W: не снимает
	if st := eval(tk, now, W, map[string][]byte{"oob": d(now, "a", "r1")}); !st.Stopped {
		t.Error("oncall+renewer после stop снял остановку")
	}
	// только renewer'ы новее stop, R=0 при W>0
	if st := eval(tk, now, W, map[string][]byte{"oob": d(now, "r1", "r2")}); !st.Stopped {
		t.Error("renewer'ы после stop сняли остановку")
	}
	// одна подпись oncall
	if st := eval(tk, now, W, map[string][]byte{"oob": d(now, "a"), "configmap": d(now, "b")}); !st.Stopped {
		t.Error("две разные одноподписные документы в разных каналах сняли остановку")
	}
	// run старше stop
	if st := eval(tk, now, W, map[string][]byte{"oob": d(stopAt.Add(-time.Second), "a", "b")}); !st.Stopped {
		t.Error("старый run снял остановку")
	}
	// run с issued_at == W: не новее
	if st := eval(tk, now, W, map[string][]byte{"oob": d(stopAt, "a", "b")}); !st.Stopped {
		t.Error("run с issued_at == W снял остановку")
	}
	// future двух oncall
	if st := eval(tk, now, W, map[string][]byte{"oob": d(now.Add(time.Hour), "a", "b")}); !st.Stopped {
		t.Error("future снял остановку")
	}
	// запятнанный run с двумя oncall + мусорной подписью
	tt := newTKeys(t)
	dd := Document{Schema: DocSchema, Clusters: []string{}, Actions: []string{}, IssuedAt: now.Format("2006-01-02T15:04:05.000Z"), TTL: "1h0m0s", Issuer: "x", Signatures: []Signature{}}
	for _, n := range []string{"a", "b"} {
		s, _ := SignatureFor(dd, tk.signers[n], "i-"+n)
		dd, _ = AddSignature(dd, s)
	}
	s, _ := SignatureFor(dd, tt.signers["a"], "i-a")
	dd, _ = AddSignature(dd, s)
	if st := eval(tk, now, Marks{}, map[string][]byte{"oob": Marshal(dd)}); !st.Stopped {
		t.Error("запятнанный run подтвердил")
	}
	// запятнанный stop действует и поднимает W
	gd := Document{Schema: DocSchema, Global: true, Clusters: []string{}, Actions: []string{}, IssuedAt: now.Format("2006-01-02T15:04:05.000Z"), TTL: "1h0m0s", Issuer: "x", Signatures: []Signature{}}
	s1, _ := SignatureFor(gd, tk.signers["a"], "i-a")
	gd, _ = AddSignature(gd, s1)
	s2, _ := SignatureFor(gd, tt.signers["b"], "i-b")
	gd, _ = AddSignature(gd, s2)
	if st := eval(tk, now, Marks{}, map[string][]byte{"oob": Marshal(gd)}); !st.Global || st.Marks.Stop.IsZero() {
		t.Errorf("запятнанный stop не действует: %+v", st.Marks)
	}
}

// Просроченный stop поднимает W: старый run после его истечения остаётся неподтверждающим.
func TestExpiredStopRaisesWatermark(t *testing.T) {
	tk := newTKeys(t)
	now := t0.Add(5 * time.Hour)
	stop := tk.doc(t, true, nil, nil, t0.Add(time.Hour), time.Minute, "a")
	oldRun := tk.doc(t, false, nil, nil, t0.Add(30*time.Minute), 24*time.Hour, "a", "b")
	st := eval(tk, now, Marks{}, map[string][]byte{"oob": stop, "configmap": oldRun})
	if st.Global || !st.Stopped || !st.Marks.Stop.Equal(t0.Add(time.Hour)) {
		t.Errorf("просроченный stop: global=%v stopped=%v W=%v", st.Global, st.Stopped, st.Marks.Stop)
	}
	// actions-only не поднимает W
	acts := tk.doc(t, false, nil, []string{"workload.restart"}, t0.Add(time.Hour), time.Hour, "a")
	if st := eval(tk, t0.Add(2*time.Hour), Marks{}, map[string][]byte{"oob": acts}); !st.Marks.Stop.IsZero() {
		t.Errorf("actions-only поднял W: %v", st.Marks.Stop)
	}
	// чужой кластер не поднимает W
	other := tk.doc(t, false, []string{"c2"}, nil, t0.Add(time.Hour), time.Hour, "a")
	if st := eval(tk, t0.Add(2*time.Hour), Marks{}, map[string][]byte{"oob": other}); !st.Marks.Stop.IsZero() {
		t.Errorf("чужой кластер поднял W: %v", st.Marks.Stop)
	}
}

// Подавление остановки: порча одного канала при stop в другом, транспортные ошибки, кэшированный run.
func TestMonitorStopSuppressionAttempts(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	run := f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b")
	f.both(run)
	f.m.PollOnce(ctx)
	if f.m.Stopped() {
		t.Fatal("run не снял")
	}
	f.now = t0.Add(2 * time.Minute)
	stop := f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a")
	f.cm.set(stop, nil)
	for _, bad := range []struct {
		raw []byte
		err error
	}{{nil, kerr("http_404")}, {[]byte("мусор"), nil}, {nil, kerr("http_403")}, {run, nil}, {nil, kerr("timeout")}, {nil, kerr("oversize")}, {[]byte{}, nil}} {
		f.oob.set(bad.raw, bad.err)
		f.m.PollOnce(ctx)
		if !f.m.State().Global || !f.m.Stopped() {
			t.Fatalf("stop подавлен состоянием другого канала (%q %v)", bad.raw, bad.err)
		}
	}
	// удаление stop из канала-источника не снимает: старый run (в oob) старше W
	f.cm.set(nil, kerr("http_404"))
	f.oob.set(run, nil)
	f.now = t0.Add(3 * time.Minute)
	f.m.PollOnce(ctx)
	if !f.m.Stopped() {
		t.Error("удаление stop и повтор старого run снял остановку")
	}
	// кэшированный stop при транспортной ошибке продолжает действовать
	f2 := newMFix(t)
	f2.both(f2.tk.doc(t, true, nil, nil, t0, time.Hour, "a"))
	f2.m.PollOnce(ctx)
	f2.cm.set(nil, kerr("timeout"))
	f2.oob.set(nil, kerr("http_500"))
	f2.m.PollOnce(ctx)
	if !f2.m.State().Global {
		t.Error("кэш stop сброшен транспортной ошибкой")
	}
	// кэшированный run + транспорт + stop появляется в другом канале (после восстановления связи)
	f3 := newMFix(t)
	f3.both(f3.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f3.m.PollOnce(ctx)
	f3.cm.set(nil, kerr("network"))
	f3.oob.set(f3.tk.doc(t, false, []string{"c1"}, nil, f3.now, time.Hour, "a"), nil)
	f3.m.PollOnce(ctx)
	if !f3.m.State().Cluster || !f3.m.Stopped() {
		t.Error("кэшированный run подавил свежий stop по кластеру")
	}
}

// Событие аудита только при смене; повторный опрос с тем же состоянием не пишет; смена W пишет.
func TestMonitorEventsOnlyOnChange(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	for i := 0; i < 5; i++ {
		f.now = f.now.Add(time.Second)
		f.m.PollOnce(ctx)
	}
	if len(f.ev.evs) != 1 {
		t.Fatalf("событий %d", len(f.ev.evs))
	}
	// падение канала с кэшем: статус канала меняется, ключ состояния — нет
	f.cm.set(nil, kerr("timeout"))
	f.m.PollOnce(ctx)
	if len(f.ev.evs) != 1 {
		t.Errorf("кэшированный сбой канала записал событие: %d", len(f.ev.evs))
	}
	// action-stop меняет множество actions — событие updated, не engaged
	f.now = f.now.Add(time.Second)
	f.both(f.tk.doc(t, false, nil, []string{"workload.restart"}, f.now, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	if len(f.ev.evs) != 2 || f.ev.evs[1].Kind != "kill_switch_updated" || f.m.Stopped() {
		t.Errorf("actions: %+v stopped=%v", f.ev.evs, f.m.Stopped())
	}
	if _, _, _, live := f.m.State().Flags(); !live {
		t.Error("liveness должен быть подтверждён двумя подписями")
	}
}

// Сбой записи при остановке: остановка применена до записи и остаётся; ошибка возвращается.
func TestMonitorStopAppliedBeforeAuditWrite(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	f.ev.fail = errors.New("диск")
	f.now = t0.Add(time.Minute + 10*time.Second)
	f.both(f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a"))
	if err := f.m.PollOnce(ctx); err == nil {
		t.Error("сбой записи не вернул ошибку")
	}
	if !f.m.Stopped() {
		t.Error("остановка не применена при сбое записи")
	}
	// Run тоже возвращает ошибку
	f.m.Every = time.Millisecond
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := f.m.Run(cctx); err == nil || cctx.Err() != nil {
		t.Errorf("Run при сбое записи: %v", err)
	}
}

// Restore: повтор старого run после рестарта с восстановленным W; последний ключ не пишет повторное событие.
func TestMonitorRestoreNoDuplicateEvent(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	last := f.ev.evs[len(f.ev.evs)-1]
	g := newMFix(t)
	g.m.Keys = f.tk.ring
	g.m.Restore(last, true)
	g.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	if err := g.m.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if g.m.Stopped() || len(g.ev.evs) != 0 {
		t.Errorf("после Restore: stopped=%v событий=%d", g.m.Stopped(), len(g.ev.evs))
	}
	g.m.Restore(last, false) // ok=false — no-op
}

// Гонки: Guard/PollOnce/State одновременно (-race).
func TestMonitorConcurrentGuardPoll(t *testing.T) {
	f := newMFix(t)
	ctx := context.Background()
	run := f.tk.doc(t, false, nil, nil, t0, 24*time.Hour, "a", "b")
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				g, c := f.m.Guard(ctx)
				_ = g.Err()
				_ = f.m.State()
				_ = f.m.Stopped()
				c()
			}
		}()
	}
	var mu sync.Mutex
	for i := 0; i < 60; i++ {
		mu.Lock()
		if i%2 == 0 {
			f.both(run)
		} else {
			f.both(nil)
			f.cm.set(nil, kerr("http_404"))
			f.oob.set(nil, kerr("http_404"))
		}
		mu.Unlock()
		f.m.PollOnce(ctx)
	}
	close(stop)
	wg.Wait()
}

// После остановки Guard, созданный до неё, отменяется с ErrEngaged; после снятия новый Guard жив.
func TestGuardLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	g1, c1 := f.m.Guard(ctx)
	defer c1()
	f.cm.set(f.tk.doc(t, true, nil, nil, t0.Add(30*time.Second), time.Hour, "a"), nil)
	f.m.PollOnce(ctx)
	select {
	case <-g1.Done():
	case <-time.After(time.Second):
		t.Fatal("Guard не отменён")
	}
	if !errors.Is(context.Cause(g1), ErrEngaged) {
		t.Error(context.Cause(g1))
	}
	f.now = t0.Add(2 * time.Minute)
	f.both(f.tk.doc(t, false, nil, nil, f.now, time.Hour, "b", "c"))
	f.m.PollOnce(ctx)
	g2, c2 := f.m.Guard(ctx)
	defer c2()
	if g2.Err() != nil || f.m.Stopped() {
		t.Error("после снятия Guard отменён")
	}
	c2()
	if !errors.Is(context.Cause(g2), context.Canceled) {
		t.Error("отмена вызывающим должна быть Canceled, не ErrEngaged")
	}
}

// JSON состояния события: подписи и тела не утекают в каналы (только классы).
func TestEventChannelsHaveNoDocBodies(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.cm.set([]byte(`{"секрет":"тело"}`), nil)
	f.m.PollOnce(ctx)
	b, _ := json.Marshal(f.ev.evs)
	if strings.Contains(string(b), "секрет") {
		t.Errorf("тело документа в событии: %s", b)
	}
}

// Злоумышленник стёр stop из обоих каналов, renewer публикует свежий run (2 подписи renewer): intake, видевший stop
// (W в памяти), остаётся остановленным; после рестарта — за счёт W из события аудита.
func TestMonitorStopErasedThenRenewerRunStaysStopped(t *testing.T) {
	ctx := context.Background()
	f := newMFix(t)
	f.both(f.tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"))
	f.m.PollOnce(ctx)
	f.now = t0.Add(2 * time.Minute)
	f.both(f.tk.doc(t, true, nil, nil, f.now, time.Hour, "a"))
	f.m.PollOnce(ctx)
	last := f.ev.evs[len(f.ev.evs)-1]
	f.now = t0.Add(3 * time.Minute)
	f.cm.set(nil, kerr("http_404"))
	f.oob.set(nil, kerr("no_document"))
	f.m.PollOnce(ctx)
	renew := f.tk.doc(t, false, nil, nil, f.now, 6*time.Hour, "r1", "r2")
	f.both(renew)
	f.m.PollOnce(ctx)
	if !f.m.Stopped() {
		t.Error("renewer-run после стёртого stop снял остановку (память)")
	}
	g := newMFix(t)
	g.m.Restore(last, true)
	g.now = f.now
	g.both(renew)
	g.m.PollOnce(ctx)
	if !g.m.Stopped() {
		t.Error("renewer-run после стёртого stop снял остановку (после рестарта)")
	}
}
