package step

import (
	"encoding/json"
	"fmt"
)

// StateFromGoldenInput строит TargetState из поля input кейса golden-набора (input.service, input.rollout, input.db).
//
// Поды цели берутся из input.service.pods (формат набора v3), а не из enum pod_name в allowed_actions:
// так кросс-проверка restart с allowed_actions набора не тавтологична. Нет поля (набор старше v3) — ошибка,
// отката на enum нет.
func StateFromGoldenInput(raw json.RawMessage) (TargetState, error) {
	var in struct {
		Service struct {
			Name       string      `json:"name"`
			Namespace  string      `json:"namespace"`
			Database   *string     `json:"database"`
			Autoscaler *Autoscaler `json:"autoscaler"`
			Pods       *[]string   `json:"pods"`
			Policy     *string     `json:"insufficient_data_policy"`
		} `json:"service"`
		Rollout *struct {
			Name        *string `json:"name"`
			Phase       string  `json:"phase"`
			AnalysisRun *struct {
				Name    string `json:"name"`
				Verdict string `json:"verdict"`
			} `json:"analysis_run"`
		} `json:"rollout"`
		DB *DB `json:"db"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return TargetState{}, fmt.Errorf("golden input: %w", err)
	}
	if in.Service.Pods == nil {
		return TargetState{}, fmt.Errorf("golden input: нет input.service.pods (набор старше v3)")
	}
	s := TargetState{Service: in.Service.Name, Namespace: in.Service.Namespace, Database: in.Service.Database,
		Autoscaler: in.Service.Autoscaler, DB: in.DB, Pods: *in.Service.Pods, InsufficientDataPolicy: in.Service.Policy}
	if r := in.Rollout; r != nil {
		s.Rollout = &Rollout{Name: r.Name, Phase: r.Phase}
		if r.AnalysisRun != nil {
			s.Rollout.AnalysisRun, s.Rollout.AnalysisVerdict = r.AnalysisRun.Name, r.AnalysisRun.Verdict
		}
	}
	return s, nil
}
