package intake

import (
	"context"
	"github.com/limpjungle/aegis3311/internal/audit"
	"time"
)

// FixtureCollector отдаёт готовый снимок (офлайн-вход replay): источники не опрашиваются.
type FixtureCollector struct{ Snap Snapshot }

func (f FixtureCollector) Collect(context.Context, Incident, ServiceConfig, time.Time) (Snapshot, error) {
	s := f.Snap
	if len(s.Status) == 0 {
		s.Status = []audit.SourceStatus{{Source: "alerts.alertmanager", Status: "ok", Items: 1}}
	}
	return s, nil
}

// ReplayIncident строит открытый инцидент и запись реестра по фикстуре: ключ — окружение и пара из алерта,
// ID — детерминированный, как у живого intake.
func ReplayIncident(env string, s Snapshot) (Incident, ServiceConfig) {
	a := SanitizeAlert(s.Alert)
	k := Key{env, a.Namespace, a.Service}
	inc := Incident{ID: IncidentID(k, a.StartsAt), Key: k, FirstAlertAt: a.StartsAt.UTC(), OpenedAt: s.T0.UTC(), LastFiringAt: s.T0.UTC(),
		Alerts: map[string]time.Time{a.Fingerprint: s.T0.UTC()}, Alert: a, Status: StatusOpen}
	return inc, ServiceConfig{Namespace: a.Namespace, Service: a.Service, LLMMode: "hybrid"}
}
