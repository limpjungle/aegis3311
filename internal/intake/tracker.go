package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sort"
	"time"
)

// ClosedRetention — сколько хранится множество закрытых ID: уже закрытый инцидент не открывается снова,
// иначе обнулился бы его бюджет в роутере.
const ClosedRetention = 7 * 24 * time.Hour

// MaxIncidentAlerts — потолок fingerprint'ов инцидента в состоянии; равен пределу intake.alerts decision record'а.
const MaxIncidentAlerts = 64

// trimAlerts оставляет в m не больше limit fingerprint'ов: keep (первый алерт инцидента) всегда, затем самые
// свежие по времени последнего появления; при равенстве — меньший fingerprint. Возвращает число удалённых.
func trimAlerts(m map[string]time.Time, keep string, limit int) int {
	if len(m) <= limit {
		return 0
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if (a == keep) != (b == keep) {
			return a == keep
		}
		if !m[a].Equal(m[b]) {
			return m[a].After(m[b])
		}
		return a < b
	})
	for _, k := range keys[max(limit, 0):] {
		delete(m, k)
	}
	return len(keys) - max(limit, 0)
}

// alertFingerprints — fingerprint'ы для intake.alerts: отбор по правилу trimAlerts (на копии), по возрастанию.
func alertFingerprints(inc Incident) []string {
	cp := make(map[string]time.Time, len(inc.Alerts))
	for k, v := range inc.Alerts {
		cp[k] = v
	}
	trimAlerts(cp, inc.Alert.Fingerprint, MaxIncidentAlerts)
	fps := make([]string, 0, len(cp))
	for k := range cp {
		fps = append(fps, k)
	}
	sort.Strings(fps)
	return fps
}

// IncidentID — детерминированный ID: время начала первого алерта и хеш ключа группы. Повторная обработка тех же
// алертов (рестарт, потеря состояния) даёт тот же ID; повторное срабатывание после разрешения меняет startsAt.
func IncidentID(k Key, startsAt time.Time) string {
	st := startsAt.UTC().Format("20060102T150405Z")
	h := sha256.Sum256([]byte(k.Env + "\x00" + k.Namespace + "\x00" + k.Service + "\x00" + st))
	return "inc-" + st + "-" + hex.EncodeToString(h[:6])
}

// Tracker группирует алерты в инциденты и решает, какие закрыть. Ввода-вывода нет, кроме сохранения State.
type Tracker struct {
	env        string
	known      func(ns, svc string) bool // реестр сервисов
	closePolls int                       // успешных опросов без алертов ключа до закрытия
	maxOpen    int
	st         *State
	log        *slog.Logger
	Ignored    int // счётчик алертов вне реестра или без меток (только для журнала)
}

// NewTracker: closePolls = ceil(close_after / poll_interval), не меньше 1.
func NewTracker(env string, known func(ns, svc string) bool, closePolls, maxOpen int, st *State, log *slog.Logger) *Tracker {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Tracker{env: env, known: known, closePolls: max(closePolls, 1), maxOpen: maxOpen, st: st, log: log}
}

// Observe учитывает результат УСПЕШНОГО опроса (при ошибке опроса не вызывается: недоступность Alertmanager не
// разрешение). Возвращает копии вновь открытых инцидентов и инцидентов к закрытию (включая ранее начатые, но не
// завершённые закрытия). Ошибка — не удалось сохранить состояние.
func (t *Tracker) Observe(now time.Time, firing []Alert) (opened, toClose []Incident, err error) {
	groups := map[Key][]Alert{}
	for _, a := range firing {
		if a.Namespace == "" || a.Service == "" || !t.known(a.Namespace, a.Service) {
			t.Ignored++
			continue
		}
		k := Key{t.env, a.Namespace, a.Service}
		groups[k] = append(groups[k], a)
	}
	err = t.st.Do(func(d *Data) {
		for id, ts := range d.Closed {
			if now.Sub(ts) > ClosedRetention {
				delete(d.Closed, id)
			}
		}
		byKey := map[Key]*Incident{}
		for _, inc := range d.Incidents {
			byKey[inc.Key] = inc
		}
		keys := make([]Key, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := keys[i], keys[j]
			return a.Namespace+"/"+a.Service < b.Namespace+"/"+b.Service
		})
		for _, k := range keys {
			as := groups[k]
			sort.Slice(as, func(i, j int) bool {
				if !as[i].StartsAt.Equal(as[j].StartsAt) {
					return as[i].StartsAt.Before(as[j].StartsAt)
				}
				return as[i].Fingerprint < as[j].Fingerprint
			})
			inc := byKey[k]
			if inc == nil {
				id := IncidentID(k, as[0].StartsAt)
				if _, closed := d.Closed[id]; closed {
					continue
				}
				if len(d.Incidents) >= t.maxOpen {
					t.log.Warn("intake_max_open_incidents", "limit", t.maxOpen)
					continue
				}
				inc = &Incident{ID: id, Key: k, FirstAlertAt: as[0].StartsAt.UTC(), OpenedAt: now.UTC(), Alerts: map[string]time.Time{},
					Alert: SanitizeAlert(as[0]), Status: StatusOpen}
				d.Incidents[id] = inc
				byKey[k] = inc
				opened = append(opened, *inc)
			}
			inc.LastFiringAt, inc.AbsentPolls = now.UTC(), 0
			if inc.Status == StatusClosing { // алерт вернулся до подтверждения закрытия
				inc.Status = StatusOpen
			}
			for _, a := range as {
				inc.Alerts[SanitizeAlert(a).Fingerprint] = now.UTC()
			}
			if n := trimAlerts(inc.Alerts, inc.Alert.Fingerprint, MaxIncidentAlerts); n > 0 {
				t.log.Debug("intake_incident_alerts_trimmed", "incident", inc.ID, "removed", n)
			}
		}
		ids := make([]string, 0, len(d.Incidents))
		for id := range d.Incidents {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			inc := d.Incidents[id]
			if _, firing := groups[inc.Key]; !firing {
				inc.AbsentPolls++
			}
			if inc.Status == StatusClosing || (inc.AbsentPolls >= t.closePolls && inc.AbsentPolls > 0) {
				inc.Status = StatusClosing
				toClose = append(toClose, *inc)
			}
		}
	})
	return opened, toClose, err
}
