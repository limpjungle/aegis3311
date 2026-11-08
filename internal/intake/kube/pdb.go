package kube

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/limpjungle/aegis3311/internal/intake"
)

type pdbObj struct {
	Spec struct {
		Selector       selector        `json:"selector"`
		MinAvailable   json.RawMessage `json:"minAvailable"`
		MaxUnavailable json.RawMessage `json:"maxUnavailable"`
	} `json:"spec"`
}

// PDB: PodDisruptionBudget (policy/v1), чей selector (matchLabels и matchExpressions) подходит меткам шаблона пода
// workload'а; значения как есть (число или строка-процент). PDB с пустым селектором игнорируется. Нет подходящего — nil.
func (c *Client) PDB(ctx context.Context, svc intake.ServiceConfig) (*intake.PDB, error) {
	w, err := c.workload(ctx, svc)
	if err != nil {
		return nil, err
	}
	items, tr, err := list[pdbObj](ctx, c.c, "/apis/policy/v1/namespaces/"+url.PathEscape(svc.Namespace)+"/poddisruptionbudgets", url.Values{}, capPDBs)
	if err != nil {
		return nil, err
	}
	lbl := w.Spec.Template.Metadata.Labels
	if len(lbl) == 0 {
		lbl = w.Spec.Selector.MatchLabels
	}
	for _, it := range items {
		if !it.Spec.Selector.matches(lbl) {
			continue
		}
		return &intake.PDB{MinAvailable: intOrString(it.Spec.MinAvailable), MaxUnavailable: intOrString(it.Spec.MaxUnavailable)}, truncErr(tr)
	}
	return nil, truncErr(tr)
}

func intOrString(raw json.RawMessage) any {
	var i int
	if json.Unmarshal(raw, &i) == nil {
		return i
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && s != "" {
		return s
	}
	return nil
}
