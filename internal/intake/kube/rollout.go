package kube

import (
	"context"
	"math"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
)

type rolloutObj struct {
	Metadata meta `json:"metadata"`
	Status   struct {
		Phase          string `json:"phase"`
		CurrentPodHash string `json:"currentPodHash"`
		StableRS       string `json:"stableRS"`
		Canary         struct {
			Weights struct {
				Canary struct {
					Weight int `json:"weight"`
				} `json:"canary"`
			} `json:"weights"`
		} `json:"canary"`
		Conditions []struct {
			Type               string    `json:"type"`
			Reason             string    `json:"reason"`
			LastUpdateTime     time.Time `json:"lastUpdateTime"`
			LastTransitionTime time.Time `json:"lastTransitionTime"`
		} `json:"conditions"`
	} `json:"status"`
}

// hashLabel — метка Argo на AnalysisRun и ReplicaSet: хеш шаблона пода ревизии.
const hashLabel = "rollouts-pod-template-hash"

// Rollout (argoproj.io/v1alpha1) с последним AnalysisRun текущей ревизии (`rollouts-pod-template-hash` = `status.currentPodHash`). Фаза: Progressing и Paused → Progressing; Healthy в пределах
// bake после полного продвижения → Bake; иначе фаза Argo как есть. AnalysisRun — threshold-метрики: canary — последнее
// измерение, baseline и p_value — null, holm_significant — метрика в фазе Failed (допущение окружения: нативный
// threshold-AnalysisRun вместо статистического гейта). Если анализа текущей ревизии ещё нет, а фаза Progressing или
// Bake, подставляется PreviousAnalysisRun — новейший AnalysisRun этого Rollout с другим хешем (вторым листом с
// `rollouts-pod-template-hash!=<currentPodHash>`). Ошибка этого второго запроса некритична: подстановки нет, ошибки нет.
func (c *Client) Rollout(ctx context.Context, svc intake.ServiceConfig, t0 time.Time) (*intake.Rollout, error) {
	ns := url.PathEscape(svc.Namespace)
	var ro rolloutObj
	if err := c.c.GetJSON(ctx, "/apis/argoproj.io/v1alpha1/namespaces/"+ns+"/rollouts/"+url.PathEscape(svc.Workload.Name), nil, &ro); err != nil {
		return nil, err
	}
	w, err := c.workload(ctx, svc)
	if err != nil {
		return nil, err
	}
	l, _, rsTr, err := c.replicaSets(ctx, svc, w)
	if err != nil {
		return nil, err
	}
	revOf := func(hash string) *int {
		for _, rs := range l {
			if hash != "" && rs.Metadata.Labels["pod-template-hash"] == hash {
				if r, err := strconv.Atoi(rs.Metadata.Annotations[revisionKey("Rollout")]); err == nil {
					return &r
				}
			}
		}
		return nil
	}
	name := ro.Metadata.Name
	r := &intake.Rollout{Name: &name, StableRevision: revOf(ro.Status.StableRS), CanaryWeightPct: ro.Status.Canary.Weights.Canary.Weight}
	if ro.Status.CurrentPodHash != ro.Status.StableRS {
		r.CanaryRevision = revOf(ro.Status.CurrentPodHash)
	}
	r.Phase = ro.Status.Phase
	switch ro.Status.Phase {
	case "Progressing", "Paused":
		r.Phase = "Progressing"
	case "Healthy":
		if bake, err := time.ParseDuration(svc.Bake); err == nil {
			for _, cd := range ro.Status.Conditions {
				if cd.Type == "Progressing" && cd.Reason == "NewReplicaSetAvailable" {
					if done := first(cd.LastUpdateTime, cd.LastTransitionTime); !done.IsZero() && t0.Sub(done) < bake {
						r.Phase = "Bake"
					}
				}
			}
		}
	}
	h := ro.Status.CurrentPodHash
	sel := ""
	if h != "" {
		if !validValue(h) {
			return nil, badSelector()
		}
		sel = hashLabel + "=" + h
	}
	cur, arTr, err := c.latestAnalysisRun(ctx, svc.Namespace, svc.Workload.Name, sel)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		r.AnalysisRun = toAnalysisRun(*cur)
	} else if h != "" && (r.Phase == "Progressing" || r.Phase == "Bake") {
		// Ошибка второго запроса игнорируется: подстановка — вспомогательная, источник от неё не недоступен.
		prev, prTr, perr := c.latestAnalysisRun(ctx, svc.Namespace, svc.Workload.Name, hashLabel+"!="+h)
		if perr == nil && prev != nil {
			a := toAnalysisRun(*prev)
			r.PreviousAnalysisRun = &intake.PreviousAnalysisRun{Revision: revOf(prev.Metadata.Labels[hashLabel]),
				Name: a.Name, Verdict: a.Verdict, Metrics: a.Metrics}
		}
		arTr = arTr || (perr == nil && prTr)
	}
	return r, truncErr(rsTr || arTr)
}

type analysisRunObj struct {
	Metadata meta `json:"metadata"`
	Status   struct {
		Phase         string `json:"phase"`
		MetricResults []struct {
			Name         string `json:"name"`
			Phase        string `json:"phase"`
			Measurements []struct {
				Value string `json:"value"`
			} `json:"measurements"`
		} `json:"metricResults"`
	} `json:"status"`
}

// latestAnalysisRun: самый новый (creationTimestamp) AnalysisRun этого Rollout (по ownerReference) из листа namespace
// с labelSelector sel ("" — без селектора). nil — нет ни одного. Значение sel собирает вызывающий из проверенного хеша.
func (c *Client) latestAnalysisRun(ctx context.Context, ns, rollout, sel string) (*analysisRunObj, bool, error) {
	q := url.Values{}
	if sel != "" {
		q.Set("labelSelector", sel)
	}
	items, tr, err := list[analysisRunObj](ctx, c.c, "/apis/argoproj.io/v1alpha1/namespaces/"+url.PathEscape(ns)+"/analysisruns", q, capAnalysisRuns)
	if err != nil {
		return nil, false, err
	}
	idx := []int{}
	for i, it := range items {
		for _, o := range it.Metadata.OwnerReferences {
			if o.Kind == "Rollout" && o.Name == rollout {
				idx = append(idx, i)
			}
		}
	}
	if len(idx) == 0 {
		return nil, tr, nil
	}
	sort.SliceStable(idx, func(a, b int) bool {
		return items[idx[a]].Metadata.CreationTimestamp.After(items[idx[b]].Metadata.CreationTimestamp)
	})
	return &items[idx[0]], tr, nil
}

// toAnalysisRun — доменная форма: вердикт и threshold-метрики.
func toAnalysisRun(it analysisRunObj) *intake.AnalysisRun {
	verdict := map[string]string{"Successful": "success", "Failed": "degradation", "Error": "degradation", "Inconclusive": "inconclusive"}[it.Status.Phase]
	if verdict == "" {
		verdict = "running"
	}
	ar := &intake.AnalysisRun{Name: it.Metadata.Name, Verdict: verdict, Metrics: []intake.AnalysisMetric{}}
	for _, m := range it.Status.MetricResults {
		am := intake.AnalysisMetric{Name: m.Name, Test: "threshold", HolmSignificant: m.Phase == "Failed"}
		if n := len(m.Measurements); n > 0 {
			if v, ok := parseMeasurement(m.Measurements[n-1].Value); ok {
				am.Canary = &intake.Num{F: v}
			}
		}
		ar.Metrics = append(ar.Metrics, am)
	}
	return ar
}

// parseMeasurement: значение измерения Argo — число или массив из одного числа ("[0.05]").
func parseMeasurement(s string) (float64, bool) {
	s = strings.Trim(strings.TrimSpace(s), "[]")
	if i := strings.IndexAny(s, ", "); i >= 0 {
		s = s[:i]
	}
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}
