package step

import (
	"fmt"

	"github.com/limpjungle/aegis3311/internal/catalog"
)

// AvailableAction — действие, доступное для цели, в той же JSON-форме, что allowed_actions в наборе (generate.py, формат v2).
type AvailableAction struct {
	Type         string                     `json:"type"`
	Target       string                     `json:"target,omitempty"`
	LevelCeiling string                     `json:"level_ceiling,omitempty"`
	Params       map[string]ParamConstraint `json:"params"` // всегда не nil, как в Python
	Computed     map[string]any             `json:"computed,omitempty"`
}

type ParamConstraint struct {
	Enum       []string `json:"enum,omitempty"`
	RequiredIf string   `json:"required_if,omitempty"`
}

// Available возвращает доступные действия в порядке generate.py. Перечисления параметров берутся из каталога.
// Действия, которых нет в каталоге, пропускаются.
func Available(cat *catalog.Catalog, s TargetState) []AvailableAction {
	acts := []AvailableAction{
		{Type: "recommend", Params: map[string]ParamConstraint{}},
		{Type: "none", Params: map[string]ParamConstraint{}},
	}
	add := func(a AvailableAction) {
		e, ok := cat.Get(a.Type)
		if !ok {
			return
		}
		if e.Reversibility == catalog.R3 {
			a.LevelCeiling = "L1"
		}
		acts = append(acts, a)
	}
	if a := s.Autoscaler; a != nil {
		if v, ok := ScaleOut(*a); ok {
			add(AvailableAction{Type: "workload.scale_out", Target: a.Kind, Params: map[string]ParamConstraint{},
				Computed: map[string]any{"new_min_replicas": v}})
		}
		if v, ok := ScaleIn(*a); ok {
			add(AvailableAction{Type: "workload.scale_in", Target: a.Kind, Params: map[string]ParamConstraint{},
				Computed: map[string]any{"new_min_replicas": v}})
		}
	}
	if len(s.Pods) > 0 {
		if e, ok := cat.Get("workload.restart"); ok {
			add(AvailableAction{Type: "workload.restart", Params: map[string]ParamConstraint{
				"scope":    {Enum: e.Params["scope"].Enum},
				"pod_name": {Enum: s.Pods, RequiredIf: condText(e.Params["pod_name"].RequiredIf)},
			}})
		}
	}
	if r := s.Rollout; r != nil && (r.Phase == "Progressing" || r.Phase == "Bake") {
		if e, ok := cat.Get("rollout.abort_and_rollback"); ok {
			add(AvailableAction{Type: "rollout.abort_and_rollback",
				Params:   map[string]ParamConstraint{"reason": {Enum: e.Params["reason"].Enum}},
				Computed: map[string]any{"analysis_run": r.AnalysisRun}})
		}
	}
	if db := s.DB; db != nil {
		if v, ok := ResizePool(*db); ok && s.Database != nil {
			add(AvailableAction{Type: "pgbouncer.resize_pool", Params: map[string]ParamConstraint{},
				Computed: map[string]any{"database": *s.Database, "new_pool_size": v}})
		}
		if e, ok := cat.Get("postgres.set_restart_param"); ok {
			add(AvailableAction{Type: "postgres.set_restart_param",
				Params:   map[string]ParamConstraint{"parameter": {Enum: e.Params["parameter"].Enum}},
				Computed: map[string]any{"value": map[string]int{"max_connections": MaxConnections(db.Postgres)}}})
		}
	}
	return acts
}

func condText(c *catalog.Cond) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf("%s == %s", c.Param, c.Equals)
}
