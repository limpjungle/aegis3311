package pep_test

import (
	"testing"

	"github.com/limpjungle/aegis3311/internal/pep"
)

func TestParseProposal_RejectsDuplicatesAndCase(t *testing.T) {
	const ps = `"params":{"scope":null,"pod_name":null,"reason":null,"parameter":null}`
	bad := map[string]string{
		"дубль type":       `{"type":"none","type":"workload.restart",` + ps + `}`,
		"дубль params":     `{"type":"none",` + ps + `,` + ps + `}`,
		"дубль в params":   `{"type":"none","params":{"scope":null,"scope":"pod","pod_name":null,"reason":null,"parameter":null}}`,
		"регистр type":     `{"Type":"none",` + ps + `}`,
		"регистр в params": `{"type":"none","params":{"Scope":null,"pod_name":null,"reason":null,"parameter":null}}`,
	}
	for name, in := range bad {
		if _, err := pep.ParseProposal([]byte(in)); err == nil {
			t.Errorf("%s: ошибка не возвращена", name)
		}
	}
}
