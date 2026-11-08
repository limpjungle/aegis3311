package kube

import (
	"context"
	"net/url"
	"sort"
	"time"

	"github.com/limpjungle/aegis3311/internal/intake"
)

type event struct {
	InvolvedObject struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"involvedObject"`
	Type           string    `json:"type"`
	Reason         string    `json:"reason"`
	Count          int       `json:"count"`
	LastTimestamp  time.Time `json:"lastTimestamp"`
	EventTime      time.Time `json:"eventTime"`
	FirstTimestamp time.Time `json:"firstTimestamp"`
	Series         struct {
		Count            int       `json:"count"`
		LastObservedTime time.Time `json:"lastObservedTime"`
	} `json:"series"`
	// message намеренно не читается: свободный текст недоверенный (T-01).
}

// Events: Warning-события подов сервиса за окно (reason — по allowlist sanitize) и синтезированные OOMKilled:
// в Kubernetes OOMKilled — не Event, а lastState.terminated контейнера пода (поды — по selector workload'а).
func (c *Client) Events(ctx context.Context, svc intake.ServiceConfig, pods []string, since time.Time) ([]intake.Event, error) {
	mine := map[string]bool{}
	for _, p := range pods {
		mine[p] = true
	}
	q := url.Values{"fieldSelector": {"involvedObject.kind=Pod,type=Warning"}}
	items, evTr, err := list[event](ctx, c.c, "/api/v1/namespaces/"+url.PathEscape(svc.Namespace)+"/events", q, capEvents)
	if err != nil {
		return nil, err
	}
	var out []intake.Event
	for _, e := range items {
		if e.InvolvedObject.Kind != "Pod" || !mine[e.InvolvedObject.Name] {
			continue
		}
		at := first(e.Series.LastObservedTime, e.LastTimestamp, e.EventTime, e.FirstTimestamp)
		if at.IsZero() || at.Before(since) {
			continue
		}
		cnt := max(e.Count, e.Series.Count, 1)
		out = append(out, intake.Event{Type: e.Type, Reason: e.Reason, Object: "pod/" + e.InvolvedObject.Name, Count: cnt, At: at.UTC()})
	}
	w, err := c.workload(ctx, svc)
	if err != nil {
		return nil, err
	}
	ls, err := w.Spec.Selector.labelSelector()
	if err != nil {
		return nil, err
	}
	podList, podTr, err := c.pods(ctx, svc.Namespace, ls)
	if err != nil {
		return nil, err
	}
	for _, p := range podList {
		if !mine[p.Metadata.Name] {
			continue
		}
		for _, cs := range p.Status.ContainerStatuses {
			if t := cs.LastState.Terminated; t != nil && t.Reason == "OOMKilled" && !t.FinishedAt.Before(since) {
				out = append(out, intake.Event{Type: "Warning", Reason: "OOMKilled", Object: "pod/" + p.Metadata.Name, Count: 1, At: t.FinishedAt.UTC()})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, truncErr(evTr || podTr)
}

func first(ts ...time.Time) time.Time {
	for _, t := range ts {
		if !t.IsZero() {
			return t
		}
	}
	return time.Time{}
}
