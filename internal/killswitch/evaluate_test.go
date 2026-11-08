package killswitch

import (
	"testing"
	"time"
)

func eval(tk *tkeys, now time.Time, prev Marks, docs map[string][]byte) State {
	var views []ChannelView
	for _, ch := range []string{"configmap", "oob"} {
		v := ChannelView{Channel: ch, Err: "http_404"}
		if raw, ok := docs[ch]; ok {
			vv, err := Parse(raw, tk.ring, ParseOptions{})
			if err != nil {
				panic(err)
			}
			v.Doc, v.Err = &vv, ""
		}
		views = append(views, v)
	}
	return Evaluate(now, views, prev, Options{Cluster: "c1", MaxSkew: 2 * time.Minute})
}

func TestEvaluateMatrix(t *testing.T) {
	tk := newTKeys(t)
	now := t0.Add(time.Minute)
	run2 := tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b")
	run1 := tk.doc(t, false, nil, nil, t0, time.Hour, "a")
	runR := tk.doc(t, false, nil, nil, t0, time.Hour, "r1", "r2")
	stopG := tk.doc(t, true, nil, nil, t0, time.Hour, "a")
	stopC := tk.doc(t, false, []string{"c1"}, nil, t0, time.Hour, "a")
	other := tk.doc(t, false, []string{"c2"}, nil, t0, time.Hour, "a", "b")
	acts := tk.doc(t, false, nil, []string{"workload.restart"}, t0, time.Hour, "a")
	acts2 := tk.doc(t, false, nil, []string{"workload.restart"}, t0, time.Hour, "a", "b")
	future := tk.doc(t, false, nil, nil, now.Add(10*time.Minute), time.Hour, "a", "b")
	expired := tk.doc(t, false, nil, nil, t0.Add(-2*time.Hour), time.Hour, "a", "b")
	type want struct {
		stopped bool
		reason  string
	}
	cases := []struct {
		name string
		docs map[string][]byte
		prev Marks
		want want
	}{
		{"оба отсутствуют", nil, Marks{}, want{true, "no_confirmation"}},
		{"run2 в одном канале", map[string][]byte{"oob": run2}, Marks{}, want{false, ""}},
		{"run1", map[string][]byte{"oob": run1, "configmap": run1}, Marks{}, want{true, "no_confirmation"}},
		{"global в одном, run2 в другом", map[string][]byte{"oob": stopG, "configmap": run2}, Marks{}, want{true, "global"}},
		{"cluster свой", map[string][]byte{"oob": stopC, "configmap": run2}, Marks{}, want{true, "cluster"}},
		{"cluster чужой — run", map[string][]byte{"oob": other}, Marks{}, want{false, ""}},
		{"actions1 без подтверждения", map[string][]byte{"oob": acts}, Marks{}, want{true, "no_confirmation"}},
		{"actions1 + run2", map[string][]byte{"oob": acts, "configmap": run2}, Marks{}, want{false, ""}},
		{"actions2 подтверждает", map[string][]byte{"oob": acts2}, Marks{}, want{false, ""}},
		{"renewer при нулевых W и R", map[string][]byte{"oob": runR}, Marks{}, want{false, ""}},
		{"renewer при R <= W", map[string][]byte{"oob": runR}, Marks{Stop: t0.Add(-time.Minute), Release: t0.Add(-2 * time.Minute)}, want{true, "no_confirmation"}},
		{"renewer при R > W", map[string][]byte{"oob": runR}, Marks{Stop: t0.Add(-2 * time.Minute), Release: t0.Add(-time.Minute)}, want{false, ""}},
		{"run старше W", map[string][]byte{"oob": run2}, Marks{Stop: t0.Add(time.Second)}, want{true, "no_confirmation"}},
		{"future не подтверждает", map[string][]byte{"oob": future}, Marks{}, want{true, "no_confirmation"}},
		{"просрочен", map[string][]byte{"oob": expired}, Marks{}, want{true, "no_confirmation"}},
	}
	for _, c := range cases {
		st := eval(tk, now, c.prev, c.docs)
		if st.Stopped != c.want.stopped || st.Reason != c.want.reason {
			t.Errorf("%s: stopped=%v reason=%q", c.name, st.Stopped, st.Reason)
		}
	}
	// actions объединяются и не останавливают при подтверждении
	st := eval(tk, now, Marks{}, map[string][]byte{"oob": acts2, "configmap": tk.doc(t, false, nil, []string{"db.kill_session"}, t0, time.Hour, "a")})
	if len(st.Actions) != 2 || st.Actions[0] > st.Actions[1] {
		t.Errorf("actions: %v", st.Actions)
	}
	// future не поднимает W
	if st := eval(tk, now, Marks{}, map[string][]byte{"oob": tk.doc(t, true, nil, nil, now.Add(time.Hour), time.Hour, "a")}); st.Marks.Stop != (time.Time{}) {
		t.Errorf("future поднял W: %v", st.Marks)
	}
	// границы: skew включительно, TTL исключительно
	edge := tk.doc(t, false, nil, nil, now.Add(2*time.Minute), time.Hour, "a", "b")
	if st := eval(tk, now, Marks{}, map[string][]byte{"oob": edge}); st.Stopped {
		t.Error("issued_at ровно now+skew должен быть свежим")
	}
	ttlEdge := tk.doc(t, false, nil, nil, t0, time.Minute, "a", "b")
	if st := eval(tk, t0.Add(time.Minute), Marks{}, map[string][]byte{"oob": ttlEdge}); !st.Stopped {
		t.Error("now == issued_at+ttl должен быть просрочен")
	}
}

func TestEvaluateTriggers(t *testing.T) {
	tk := newTKeys(t)
	now := t0.Add(time.Minute)
	g1 := tk.doc(t, true, nil, nil, t0, time.Hour, "a")
	st := eval(tk, now, Marks{}, map[string][]byte{"oob": g1, "configmap": g1})
	if len(st.Triggers) != 1 || !st.TriggerIssuedAt.Equal(t0) || len(st.TriggerSigners) != 1 {
		t.Errorf("один документ в двух каналах: %+v", st.Triggers)
	}
	// остановка: min issued_at среди свежих global
	g2 := tk.doc(t, true, nil, nil, t0.Add(10*time.Second), time.Hour, "b")
	st = eval(tk, now, Marks{}, map[string][]byte{"oob": g2, "configmap": g1})
	if len(st.Triggers) != 2 || !st.TriggerIssuedAt.Equal(t0) {
		t.Errorf("триггеры остановки: %+v %v", st.Triggers, st.TriggerIssuedAt)
	}
	// снятие: max issued_at подтверждений и ConfirmedUntil
	r1, r2 := tk.doc(t, false, nil, nil, t0, time.Hour, "a", "b"), tk.doc(t, false, nil, nil, t0.Add(20*time.Second), 2*time.Hour, "b", "c")
	st = eval(tk, now, Marks{}, map[string][]byte{"oob": r1, "configmap": r2})
	if st.Stopped || !st.TriggerIssuedAt.Equal(t0.Add(20*time.Second)) || !st.ConfirmedUntil.Equal(t0.Add(20*time.Second+2*time.Hour)) {
		t.Errorf("снятие: %v until=%v", st.TriggerIssuedAt, st.ConfirmedUntil)
	}
	// no_confirmation: триггеров нет
	if st = eval(tk, now, Marks{}, nil); len(st.Triggers) != 0 || st.Triggers == nil {
		t.Errorf("no_confirmation: %+v", st.Triggers)
	}
}
