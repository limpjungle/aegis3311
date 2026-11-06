package step

import (
	"encoding/json"
	"fmt"
)

// StateFromGoldenInput строит TargetState из поля input кейса golden-набора (input.service, input.rollout, input.db).
//
// Списка подов цели во входе нет: единственный источник имён — перечисление
// allowed_actions[type==workload.restart].params.pod_name.enum. Поэтому для restart
// кросс-проверка с набором частично тавтологична.
func StateFromGoldenInput(raw json.RawMessage) (TargetState, error) {
	var in struct {
		Service struct {
			Name       string      `json:"name"`
			Namespace  string      `json:"namespace"`
			Database   *string     `json:"database"`
			Autoscaler *Autoscaler `json:"autoscaler"`
		} `json:"service"`
		Rollout *struct {
			Name        *string `json:"name"`
			Phase       string  `json:"phase"`
			AnalysisRun *struct {
				Name string `json:"name"`
			} `json:"analysis_run"`
		} `json:"rollout"`
		DB             *DB `json:"db"`
		AllowedActions []struct {
			Type   string `json:"type"`
			Params struct {
				PodName struct {
					Enum []string `json:"enum"`
				} `json:"pod_name"`
			} `json:"params"`
		} `json:"allowed_actions"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return TargetState{}, fmt.Errorf("golden input: %w", err)
	}
	s := TargetState{Service: in.Service.Name, Namespace: in.Service.Namespace, Database: in.Service.Database,
		Autoscaler: in.Service.Autoscaler, DB: in.DB}
	if r := in.Rollout; r != nil {
		s.Rollout = &Rollout{Name: r.Name, Phase: r.Phase}
		if r.AnalysisRun != nil {
			s.Rollout.AnalysisRun = r.AnalysisRun.Name
		}
	}
	for _, a := range in.AllowedActions {
		if a.Type == "workload.restart" {
			s.Pods = a.Params.PodName.Enum
		}
	}
	return s, nil
}
