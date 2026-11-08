package killswitch

import (
	"sort"
	"time"

	"github.com/limpjungle/aegis3311/internal/audit"
)

// ChannelView — что известно о канале на момент оценки. Doc == nil — документа нет (Err — класс причины).
type ChannelView struct {
	Channel string
	Doc     *Verified
	Cached  bool   // документ из кэша: канал недоступен по транспортной причине
	Err     string // класс ошибки канала
}

// Options — параметры оценки для конкретной цели.
type Options struct {
	Cluster string        // kill_switch.cluster intake: точное совпадение
	MaxSkew time.Duration // допустимое опережение issued_at; 0 — без запаса
}

// Marks — водяные знаки: Stop (W) — максимум issued_at документов, останавливающих цель; Release (R) — максимум
// issued_at документов с подтверждением двумя дежурными. Не дают воспроизвести старый документ и не дают renewer
// снять остановку: подтверждение renewer засчитывается, только если после последней остановки был Release.
type Marks struct{ Stop, Release time.Time }

// State — результат оценки.
type State struct {
	audit.KillSwitchState
	Channels        []audit.KillSwitchChannel
	Marks           Marks
	Triggers        []string  // doc_sha256 документов-триггеров, отсортированы
	TriggerIssuedAt time.Time // остановка: min issued_at; не остановлен: max issued_at подтверждений
	TriggerSigners  []string  // issuer'ы валидных подписей триггеров, отсортированы
	ConfirmedUntil  time.Time // max issued_at + ttl по засчитанным подтверждениям
	ConfirmedTTL    time.Duration
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return audit.Timestamp(t)
}

// Evaluate вычисляет состояние. Чистая функция: время и документы приходят аргументами.
//
// Свежесть: issued_at <= now+skew и now < issued_at+ttl. issued_at дальше skew в будущем — документ future:
// если в нём stop-эффект для цели и issued_at не дальше now+24ч, stop применяется, но водяные знаки не двигает и
// подтверждением не считается (рассинхрон часов подписавшего не должен ни снимать, ни прятать остановку);
// остальные future-документы отбрасываются целиком. Просроченные документы действуют только на
// водяные знаки. Stop-эффекты (global, свой кластер, действия) применяются от любого свежего документа; «не остановлен»
// требует свежего подтверждения новее W (см. Confirmation и Marks).
func Evaluate(now time.Time, views []ChannelView, prev Marks, o Options) State {
	type doc struct {
		v       *Verified
		fresh   bool
		confirm string
		future  bool // issued_at впереди часов: stop применяется, но W/R и подтверждение не затрагиваются
	}
	st := State{Marks: prev}
	var docs []doc
	for _, vw := range views {
		ch := audit.KillSwitchChannel{Channel: vw.Channel, Status: "absent", Error: vw.Err, Cached: vw.Cached, Signers: []string{}}
		future := vw.Doc != nil && vw.Doc.IssuedAt.After(now.Add(o.MaxSkew))
		stopEff := vw.Doc != nil && (vw.Doc.StopsTarget(o.Cluster) || len(vw.Doc.Doc.Actions) > 0)
		if future && (!stopEff || vw.Doc.IssuedAt.After(now.Add(maxTTL))) {
			ch.Error = "future" // документ не участвует
		} else if vw.Doc != nil {
			v := vw.Doc
			d := doc{v: v, fresh: now.Before(v.IssuedAt.Add(v.TTL)), confirm: v.Confirmation(o.Cluster), future: future}
			if future {
				d.fresh, d.confirm = true, "none"
				ch.Error = "future"
			}
			docs = append(docs, d)
			ch.Status = "expired"
			if d.fresh {
				ch.Status = "fresh"
			}
			ch.Effect = "run"
			if v.StopsTarget(o.Cluster) || len(v.Doc.Actions) > 0 {
				ch.Effect = "stop"
			}
			ch.Confirmation = d.confirm
			ch.Signers = v.SignerIssuers()
			ch.IssuedAt = audit.Timestamp(v.IssuedAt)
			ch.DocSHA256 = v.SHA256
			switch {
			case ch.Error != "":
			case v.Tainted:
				ch.Error = "partial_signatures"
			case d.confirm == "none" && !v.StopsTarget(o.Cluster):
				ch.Error = "insufficient_signatures"
			}
		}
		st.Channels = append(st.Channels, ch)
	}
	// Водяные знаки: просроченные документы тоже считаются. Действия без global/кластера W не двигают: ограничение
	// типа действия не должно останавливать роутер.
	for _, d := range docs {
		if d.future {
			continue
		}
		if d.v.StopsTarget(o.Cluster) {
			st.Marks.Stop = maxTime(st.Marks.Stop, d.v.IssuedAt)
		}
		if d.confirm == "oncall" {
			st.Marks.Release = maxTime(st.Marks.Release, d.v.IssuedAt)
		}
	}
	W, R := st.Marks.Stop, st.Marks.Release
	acts := map[string]bool{}
	var global, cluster bool
	var globalDocs, clusterDocs, confirmDocs []*Verified
	for _, d := range docs {
		if !d.fresh {
			continue
		}
		for _, a := range d.v.Doc.Actions {
			acts[a] = true
		}
		switch {
		case d.v.Doc.Global:
			global = true
			globalDocs = append(globalDocs, d.v)
		case d.v.HitsCluster(o.Cluster):
			cluster = true
			clusterDocs = append(clusterDocs, d.v)
		}
		ok := d.v.IssuedAt.After(W) && (d.confirm == "oncall" || (d.confirm == "renewer" && (R.After(W) || W.IsZero())))
		if ok {
			confirmDocs = append(confirmDocs, d.v)
			if u := d.v.IssuedAt.Add(d.v.TTL); u.After(st.ConfirmedUntil) {
				st.ConfirmedUntil, st.ConfirmedTTL = u, d.v.TTL
			}
		}
	}
	st.Actions = make([]string, 0, len(acts))
	for a := range acts {
		st.Actions = append(st.Actions, a)
	}
	sort.Strings(st.Actions)
	st.Global, st.Cluster = global, cluster
	st.LivenessConfirmed = len(confirmDocs) > 0
	st.Stopped = global || cluster || !st.LivenessConfirmed
	switch {
	case global:
		st.Reason = "global"
	case cluster:
		st.Reason = "cluster"
	case !st.LivenessConfirmed:
		st.Reason = "no_confirmation"
	}
	st.EvaluatedAt = audit.Timestamp(now)
	trig := confirmDocs
	pickMin := false
	if st.Stopped {
		trig, pickMin = globalDocs, true
		if st.Reason == "cluster" {
			trig = clusterDocs
		}
	}
	signers := map[string]bool{}
	st.Triggers = []string{}
	seenDoc := map[string]bool{}
	for _, v := range trig {
		if !seenDoc[v.SHA256] { // один документ в обоих каналах — один триггер
			seenDoc[v.SHA256] = true
			st.Triggers = append(st.Triggers, v.SHA256)
		}
		for _, s := range v.Valid {
			signers[s.Issuer] = true
		}
		if st.TriggerIssuedAt.IsZero() || (pickMin && v.IssuedAt.Before(st.TriggerIssuedAt)) || (!pickMin && v.IssuedAt.After(st.TriggerIssuedAt)) {
			st.TriggerIssuedAt = v.IssuedAt
		}
	}
	sort.Strings(st.Triggers)
	st.TriggerSigners = []string{}
	for s := range signers {
		st.TriggerSigners = append(st.TriggerSigners, s)
	}
	sort.Strings(st.TriggerSigners)
	return st
}

// Flags — реальные флаги для PEP (kill_switch.global, .cluster, .actions и liveness_confirmed). actions — копия, не nil.
func (s State) Flags() (global, cluster bool, actions []string, liveness bool) {
	return s.Global, s.Cluster, append([]string{}, s.Actions...), s.LivenessConfirmed
}

// Info — состояние для decision record'а и события аудита (копия).
func (s State) Info() audit.KillSwitchState {
	k := s.KillSwitchState
	k.Actions = append([]string{}, s.Actions...)
	return k
}

func (m Marks) stampStop() string    { return stamp(m.Stop) }
func (m Marks) stampRelease() string { return stamp(m.Release) }
