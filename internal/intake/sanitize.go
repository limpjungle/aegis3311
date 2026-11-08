package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Лимиты и шаблоны нормализации недоверенных полей (T-01, T-02). Числа — предложения.
const (
	MaxAnnotationBytes = 512
	MaxAlertNameBytes  = 128
	MaxEvents          = 20
	MaxPods            = 100
	MaxSeriesTotal     = 40
	MaxDeploys         = 1
)

var (
	dnsRe         = regexp.MustCompile(`^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$`)
	authorRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._@:-]{0,63}$`)
	digestRe      = regexp.MustCompile(`^sha256:[0-9a-f]{16}$`)
	fingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	severities    = map[string]bool{"critical": true, "warning": true, "info": true}
	eventReasons  = map[string]bool{"OOMKilled": true, "BackOff": true, "Unhealthy": true, "Failed": true, "FailedScheduling": true, "Evicted": true}
	eventTypes    = map[string]bool{"Warning": true, "Normal": true}
)

// cutBytes обрезает строку до n байт по границе руны и заменяет управляющие символы пробелами.
func cutBytes(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// SanitizeAlert оставляет у алерта только allowlist полей и ограничивает значения.
func SanitizeAlert(a Alert) Alert {
	if !severities[a.Severity] {
		a.Severity = "unknown"
	}
	if !fingerprintRe.MatchString(a.Fingerprint) {
		h := sha256.Sum256([]byte(a.Fingerprint))
		a.Fingerprint = hex.EncodeToString(h[:8])
	}
	a.Name = cutBytes(a.Name, MaxAlertNameBytes)
	a.Summary, a.Description = cutBytes(a.Summary, MaxAnnotationBytes), cutBytes(a.Description, MaxAnnotationBytes)
	return a
}

func okAuthor(s string) string {
	if authorRe.MatchString(s) {
		return s
	}
	return "unknown"
}

// Sanitize нормализует снимок и возвращает имена секций input, в которых сработал лимит (для статуса truncated).
// Идемпотентна: Assemble вызывает её повторно.
func Sanitize(s Snapshot) (Snapshot, map[string]bool) {
	trunc := map[string]bool{}
	s.Alert = SanitizeAlert(s.Alert)
	var pods []string
	for _, p := range s.Topology.Pods {
		if dnsRe.MatchString(p) {
			pods = append(pods, p)
		}
	}
	if len(pods) > MaxPods {
		pods, trunc["service"] = pods[:MaxPods], true
	}
	if pods == nil {
		pods = []string{}
	}
	s.Topology.Pods = pods

	// previous_analysis_run допустим только без текущего анализа и в фазах Progressing/Bake (см. PreviousAnalysisRun).
	if r := s.Rollout.Value; r != nil && r.PreviousAnalysisRun != nil &&
		(r.AnalysisRun != nil || (r.Phase != "Progressing" && r.Phase != "Bake")) {
		c := *r
		c.PreviousAnalysisRun = nil
		s.Rollout.Value = &c
	}

	var evs []Event
	for _, e := range s.Events {
		name, ok := strings.CutPrefix(e.Object, "pod/")
		if !ok || !dnsRe.MatchString(name) || !eventReasons[e.Reason] || !eventTypes[e.Type] {
			continue
		}
		e.Count = max(e.Count, 0)
		evs = append(evs, e)
	}
	if len(evs) > MaxEvents { // оставляем 20 последних по времени, порядок выбранных — исходный
		idx := make([]int, len(evs))
		for i := range idx {
			idx[i] = i
		}
		sort.SliceStable(idx, func(a, b int) bool { return evs[idx[a]].At.Before(evs[idx[b]].At) })
		keep := idx[len(idx)-MaxEvents:]
		sort.Ints(keep)
		out := make([]Event, 0, MaxEvents)
		for _, i := range keep {
			out = append(out, evs[i])
		}
		evs, trunc["k8s_events"] = out, true
	}
	s.Events = evs

	var ds []Deploy
	for _, d := range s.Deploys {
		d.AuthorID = okAuthor(d.AuthorID)
		if !digestRe.MatchString(d.ImageDigest) {
			d.ImageDigest = "unknown"
		}
		d.Revision = max(d.Revision, 0)
		ds = append(ds, d)
	}
	if len(ds) > MaxDeploys {
		ds, trunc["deploys"] = ds[len(ds)-MaxDeploys:], true
	}
	s.Deploys = ds

	if len(s.Metrics) > MaxSeriesTotal {
		s.Metrics, trunc["metrics"] = s.Metrics[:MaxSeriesTotal], true
	}
	return s, trunc
}
