package pep

import "sort"

const (
	VerdictSchema = "aegisops/pep-verdict/v1"
	ModeDryRun    = "dry-run"
)

// Verdict — результат проверки. Временных меток нет (их добавляет decision record): вердикт детерминирован.
type Verdict struct {
	Schema         string        `json:"schema"`
	Mode           string        `json:"mode"`
	Decision       string        `json:"decision"` // allow | downgrade | deny | noop
	Action         VerdictAction `json:"action"`
	Target         *TargetRef    `json:"target"`
	RequestedLevel string        `json:"requested_level"`
	Ceiling        string        `json:"ceiling"`
	EffectiveLevel string        `json:"effective_level"`
	Reasons        []Reason      `json:"reasons"`
	CatalogDigest  string        `json:"catalog_digest"`
	PolicyDigest   string        `json:"policy_bundle_digest"`
	PolicyRevision string        `json:"policy_revision"`
	InputDigest    string        `json:"input_digest"`
}

type VerdictAction struct {
	Type          string         `json:"type"`
	Version       string         `json:"version"`
	Reversibility string         `json:"reversibility"`
	Params        ModelParams    `json:"params"`
	Computed      map[string]any `json:"computed"` // ключи сериализуются отсортированными
}

type TargetRef struct {
	Kind        string `json:"kind"`
	Namespace   string `json:"namespace"`
	Environment string `json:"environment"`
}

// Reason — причина решения. Source: catalog | step | policy | context. Effect: deny | cap.
type Reason struct {
	Code   string `json:"code"`
	Source string `json:"source"`
	Effect string `json:"effect"`
	Level  string `json:"level,omitempty"`
	Detail string `json:"detail"`
}

func sortReasons(rs []Reason) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.Effect != b.Effect {
			return a.Effect < b.Effect
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Detail < b.Detail
	})
}
