package routersvc

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/limpjungle/aegis3311/internal/audit"
	"github.com/limpjungle/aegis3311/internal/llmrouter"
	"github.com/limpjungle/aegis3311/internal/routerstate"
)

func TestClassifyHint(t *testing.T) {
	w := func(e error) error { return fmt.Errorf("обёртка: %w", fmt.Errorf("ещё: %w", e)) }
	cases := []struct {
		name    string
		err     error
		class   Class
		hint    bool
		hintSub string
	}{
		{"store locked", routerstate.ErrLocked, ClassBusy, true, "занят"},
		{"audit locked", audit.ErrLocked, ClassBusy, true, "занят"},
		{"corrupt", routerstate.ErrCorrupt, ClassFailClosed, true, "state_lost"},
		{"version", routerstate.ErrVersion, ClassFailClosed, true, ""},
		{"identity", routerstate.ErrIdentity, ClassFailClosed, true, ""},
		{"chain", &audit.ChainError{Reason: "x"}, ClassFailClosed, true, "aegis-audit verify"},
		{"audit failed", llmrouter.ErrAuditFailed, ClassFailClosed, true, ""},
		{"state store", llmrouter.ErrStateStore, ClassFailClosed, true, ""},
		{"routerstate failed", routerstate.ErrFailed, ClassFailClosed, true, ""},
		{"not initialized", ErrNotInitialized, ClassUsage, true, ""},
		{"config", &ConfigError{errors.New("x")}, ClassUsage, false, ""},
		{"invalid request", &llmrouter.InvalidRequestError{Err: errors.New("x")}, ClassUsage, false, ""},
		{"nothing to resume", ErrNothingToResume, ClassFailClosed, false, ""},
		{"unknown", errors.New("что-то"), ClassFailClosed, false, ""},
	}
	for _, c := range cases {
		for _, wrapped := range []bool{false, true} {
			err := c.err
			if wrapped {
				err = w(err)
			}
			if got := Classify(err); got != c.class {
				t.Errorf("%s wrapped=%v: класс %d, ожидается %d", c.name, wrapped, got, c.class)
			}
			h := Hint(err)
			if c.hint && h == "" {
				t.Errorf("%s wrapped=%v: нет подсказки", c.name, wrapped)
			}
			if c.hintSub != "" && !contains(h, c.hintSub) {
				t.Errorf("%s: подсказка %q без %q", c.name, h, c.hintSub)
			}
		}
	}
	if Hint(nil) != "" {
		t.Error("Hint(nil)")
	}
	if int(ClassUsage) != 2 || int(ClassFailClosed) != 1 || int(ClassBusy) != 3 {
		t.Error("значения классов")
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
