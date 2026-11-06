package main

import (
	"bytes"
	"strings"
	"testing"
)

// Регистр ключей и дубли в контексте и конверте — ошибка входа.
func TestRun_CaseAndDuplicateKeysAreErrors(t *testing.T) {
	cases := map[string]string{
		"регистр контекста": strings.Replace(req(cliProposal, cliContext), `"environment"`, `"Environment"`, 1),
		"регистр конверта":  strings.Replace(req(cliProposal, cliContext), `"proposal"`, `"Proposal"`, 1),
		"дубль в контексте": strings.Replace(req(cliProposal, cliContext), `"environment": "staging",`, `"environment": "staging", "environment": "prod-baremetal",`, 1),
		"дубль в конверте":  `{"proposal":` + cliProposal + `,"proposal":` + cliProposal + `,"context":` + cliContext + `}`,
	}
	for name, in := range cases {
		var out bytes.Buffer
		if err := run(strings.NewReader(in), &out); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}
