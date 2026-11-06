package step

import (
	"encoding/json"
	"testing"

	"github.com/limpjungle/aegis3311/internal/catalog"
)

func types(acts []AvailableAction) []string {
	var out []string
	for _, a := range acts {
		out = append(out, a.Type)
	}
	return out
}

func eq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestAvailable_Branches(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	db := "geo"
	a := asc(2, 4, 12)
	d := DB{PgBouncer: PgBouncer{Database: db, PoolSize: 50}, Postgres: Postgres{MaxConnections: 200, SuperuserReserved: 3, OtherPoolsTotal: 13, Headroom: 20}}
	phase := func(p string) *Rollout { return &Rollout{Phase: p} }
	cases := []struct {
		name string
		s    TargetState
		want []string
	}{
		{"пусто", TargetState{}, []string{"recommend", "none"}},
		{"autoscaler", TargetState{Autoscaler: &a}, []string{"recommend", "none", "workload.scale_out", "workload.scale_in"}},
		{"поды nil", TargetState{Pods: nil}, []string{"recommend", "none"}},
		{"поды пусто", TargetState{Pods: []string{}}, []string{"recommend", "none"}},
		{"поды", TargetState{Pods: []string{"p"}}, []string{"recommend", "none", "workload.restart"}},
		{"rollout Healthy", TargetState{Rollout: phase("Healthy")}, []string{"recommend", "none"}},
		{"rollout пустая фаза", TargetState{Rollout: phase("")}, []string{"recommend", "none"}},
		{"rollout Progressing", TargetState{Rollout: phase("Progressing")}, []string{"recommend", "none", "rollout.abort_and_rollback"}},
		{"rollout Bake", TargetState{Rollout: phase("Bake")}, []string{"recommend", "none", "rollout.abort_and_rollback"}},
		{"db", TargetState{Database: &db, DB: &d}, []string{"recommend", "none", "pgbouncer.resize_pool", "postgres.set_restart_param"}},
		{"db без database", TargetState{DB: &d}, []string{"recommend", "none", "postgres.set_restart_param"}},
		{"всё, порядок", TargetState{Autoscaler: &a, Pods: []string{"p"}, Rollout: phase("Bake"), Database: &db, DB: &d},
			[]string{"recommend", "none", "workload.scale_out", "workload.scale_in", "workload.restart",
				"rollout.abort_and_rollback", "pgbouncer.resize_pool", "postgres.set_restart_param"}},
	}
	for _, c := range cases {
		if got := types(Available(cat, c.s)); !eq(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAvailable_Details(t *testing.T) {
	cat := catalog.MustLoadEmbedded()
	db := "geo"
	d := DB{PgBouncer: PgBouncer{Database: db, PoolSize: 50}, Postgres: Postgres{MaxConnections: 200, SuperuserReserved: 3, OtherPoolsTotal: 13, Headroom: 20}}
	acts := Available(cat, TargetState{Database: &db, DB: &d})
	b, _ := json.Marshal(acts)
	want := `[{"type":"recommend","params":{}},{"type":"none","params":{}},` +
		`{"type":"pgbouncer.resize_pool","params":{},"computed":{"database":"geo","new_pool_size":63}},` +
		`{"type":"postgres.set_restart_param","level_ceiling":"L1","params":{"parameter":{"enum":["max_connections","shared_buffers"]}},"computed":{"value":{"max_connections":250}}}]`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}
