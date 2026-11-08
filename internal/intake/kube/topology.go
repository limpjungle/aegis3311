package kube

import (
	"context"
	"net/url"
	"sort"

	"github.com/limpjungle/aegis3311/internal/intake"
	"github.com/limpjungle/aegis3311/internal/step"
)

// Topology: поды по selector workload'а, автоскейлер (HPA autoscaling/v2 или ScaledObject keda.sh/v1alpha1) и метки
// namespace и workload (только для PEP). declared_min и insufficient_data_policy подставляет сборщик из реестра.
func (c *Client) Topology(ctx context.Context, svc intake.ServiceConfig) (intake.Topology, error) {
	t := intake.Topology{Service: svc.Service, Namespace: svc.Namespace}
	w, err := c.workload(ctx, svc)
	if err != nil {
		return t, err
	}
	ls, err := w.Spec.Selector.labelSelector()
	if err != nil {
		return t, err
	}
	pods, tr, err := c.pods(ctx, svc.Namespace, ls)
	if err != nil {
		return t, err
	}
	for _, p := range pods {
		if p.Status.Phase == "Running" || p.Status.Phase == "Pending" {
			t.Pods = append(t.Pods, p.Metadata.Name)
		}
	}
	sort.Strings(t.Pods)
	t.TargetLabels = w.Metadata.Labels
	var ns struct {
		Metadata meta `json:"metadata"`
	}
	if err := c.c.GetJSON(ctx, "/api/v1/namespaces/"+url.PathEscape(svc.Namespace), nil, &ns); err != nil {
		return t, err
	}
	t.NamespaceLabels = ns.Metadata.Labels
	if a := svc.Autoscaler; a != nil {
		as, err := c.autoscaler(ctx, svc, *a, w.Status.Replicas)
		if err != nil {
			return t, err
		}
		t.Autoscaler = as
	}
	return t, truncErr(tr)
}

func (c *Client) autoscaler(ctx context.Context, svc intake.ServiceConfig, a intake.AutoscalerRef, wlReplicas int) (*step.Autoscaler, error) {
	ns, name := url.PathEscape(svc.Namespace), url.PathEscape(a.Name)
	if a.Kind == "ScaledObject" {
		var so struct {
			Spec struct {
				Min *int `json:"minReplicaCount"`
				Max *int `json:"maxReplicaCount"`
			} `json:"spec"`
		}
		if err := c.c.GetJSON(ctx, "/apis/keda.sh/v1alpha1/namespaces/"+ns+"/scaledobjects/"+name, nil, &so); err != nil {
			return nil, err
		}
		as := &step.Autoscaler{Kind: a.Kind, CurrentMin: 0, Max: 100, Replicas: wlReplicas} // умолчания KEDA
		if so.Spec.Min != nil {
			as.CurrentMin = *so.Spec.Min
		}
		if so.Spec.Max != nil {
			as.Max = *so.Spec.Max
		}
		return as, nil
	}
	var h struct {
		Spec struct {
			Min *int `json:"minReplicas"`
			Max int  `json:"maxReplicas"`
		} `json:"spec"`
		Status struct {
			Current int `json:"currentReplicas"`
		} `json:"status"`
	}
	if err := c.c.GetJSON(ctx, "/apis/autoscaling/v2/namespaces/"+ns+"/horizontalpodautoscalers/"+name, nil, &h); err != nil {
		return nil, err
	}
	as := &step.Autoscaler{Kind: a.Kind, CurrentMin: 1, Max: h.Spec.Max, Replicas: h.Status.Current} // умолчание minReplicas — 1
	if h.Spec.Min != nil {
		as.CurrentMin = *h.Spec.Min
	}
	return as, nil
}
