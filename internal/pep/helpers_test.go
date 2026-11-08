package pep_test

import (
	"context"
	"sync"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
	"github.com/limpjungle/aegis3311/internal/pep"
	"github.com/limpjungle/aegis3311/internal/policyengine"
	"github.com/limpjungle/aegis3311/internal/step"
	"github.com/limpjungle/aegis3311/policy"
)

var (
	engOnce sync.Once
	engPol  *policyengine.Engine
	engErr  error
)

func sharedPolicy(t testing.TB) *policyengine.Engine {
	t.Helper()
	engOnce.Do(func() { engPol, engErr = policyengine.Load(context.Background(), policy.FS) })
	if engErr != nil {
		t.Fatal(engErr)
	}
	return engPol
}

func newEngine(t testing.TB) *pep.Engine {
	t.Helper()
	cat := catalog.MustLoadEmbedded()
	if err := cat.Validate(step.DefaultRegistry()); err != nil {
		t.Fatal(err)
	}
	return pep.New(cat, sharedPolicy(t))
}

func sp(s string) *string { return &s }
func bp(b bool) *bool     { return &b }
func ip(i int) *int       { return &i }

// permissive — контекст, в котором политика ничего не запрещает и не ограничивает: staging, L3, флаги чистые, lease есть.
func permissive(s step.TargetState) pep.Context {
	return pep.Context{
		Environment:     sp("staging"),
		Namespace:       sp("shop"),
		NamespaceLabels: map[string]string{"aegisops.io/managed": "true"},
		TargetLabels:    map[string]string{"aegisops.io/stateless": "true", "aegisops.io/managed": "true"},
		State:           &s,
		Level:           &pep.LevelGrant{Level: sp("L3"), ByData: bp(false)},
		Flags: &pep.Flags{
			KillSwitch:             &pep.KillSwitch{Global: bp(false), Cluster: bp(false), Actions: []string{}},
			LivenessConfirmed:      bp(true),
			ErrorBudgetExhausted:   bp(false),
			DegradedMode:           bp(false),
			RunbookPreapproved:     bp(false),
			DegradedPolicyAllowsR2: bp(false),
			PolicyCacheExpired:     bp(false),
			LeaseHeld:              bp(true),
			HumanEngaged:           bp(false),
			CircuitBreakerOpen:     bp(false),
		},
		History: &pep.History{ActionsLastHour: ip(0)},
	}
}

// richState — цель со всеми частями: autoscaler, поды, rollout в Progressing, БД.
func richState() step.TargetState {
	db := "geo"
	return step.TargetState{
		Service: "geo-svc", Namespace: "shop", Database: &db,
		Autoscaler: &step.Autoscaler{Kind: "HorizontalPodAutoscaler", DeclaredMin: 2, CurrentMin: 4, Max: 12, Replicas: 4},
		Pods:       []string{"geo-svc-aaa-11111", "geo-svc-aaa-22222"},
		Rollout:    &step.Rollout{Name: sp("geo-svc"), Phase: "Progressing", AnalysisRun: "ar-1", AnalysisVerdict: "degradation"},
		DB: &step.DB{PgBouncer: step.PgBouncer{Database: "geo", PoolSize: 50},
			Postgres: step.Postgres{MaxConnections: 200, SuperuserReserved: 3, OtherPoolsTotal: 13, Headroom: 20}},
		// rollback — правило политики сервиса не вмешивается; сценарии hold/human задают её явно.
		InsufficientDataPolicy: sp("rollback"),
	}
}

func params(scope, pod, reason, parameter *string) pep.ModelParams {
	return pep.ModelParams{Scope: scope, PodName: pod, Reason: reason, Parameter: parameter}
}
