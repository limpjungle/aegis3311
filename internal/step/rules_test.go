package step

import (
	"math"
	"testing"
)

func asc(declared, cur, max int) Autoscaler {
	return Autoscaler{Kind: "HorizontalPodAutoscaler", DeclaredMin: declared, CurrentMin: cur, Max: max, Replicas: cur}
}

func TestRules_Table(t *testing.T) {
	t.Run("scale_out", func(t *testing.T) {
		cases := []struct {
			name   string
			a      Autoscaler
			ok     bool
			bounds Bounds
			val    int
		}{
			{"cm=1,max=1 недоступен", asc(1, 1, 1), false, Bounds{2, 1}, 0},
			{"cm=1,max=10", asc(1, 1, 10), true, Bounds{2, 2}, 2},
			{"cm=4,max=5 обрезка по max", asc(2, 4, 5), true, Bounds{5, 5}, 5},
			{"cm=4,max=12", asc(2, 4, 12), true, Bounds{5, 8}, 6},
		}
		for _, c := range cases {
			v, ok := ScaleOut(c.a)
			if ok != c.ok || ScaleOutBounds(c.a) != c.bounds || (ok && v != c.val) {
				t.Errorf("%s: got (%d,%v,%v), want (%d,%v,%v)", c.name, v, ok, ScaleOutBounds(c.a), c.val, c.ok, c.bounds)
			}
		}
	})
	t.Run("scale_in", func(t *testing.T) {
		cases := []struct {
			name string
			a    Autoscaler
			ok   bool
			val  int
		}{
			{"dm==cm недоступен", asc(4, 4, 10), false, 0},
			{"cm=1 недоступен", asc(1, 1, 10), false, 0},
			{"cm=2,dm=1", asc(1, 2, 10), true, 1},
			{"cm=8,dm=2", asc(2, 8, 20), true, 6},
		}
		for _, c := range cases {
			v, ok := ScaleIn(c.a)
			if ok != c.ok || (ok && v != c.val) {
				t.Errorf("%s: got (%d,%v), want (%d,%v)", c.name, v, ok, c.val, c.ok)
			}
		}
	})
	t.Run("resize_pool", func(t *testing.T) {
		db := func(pool, mc, others int) DB {
			return DB{PgBouncer: PgBouncer{Database: "x", PoolSize: pool},
				Postgres: Postgres{MaxConnections: mc, SuperuserReserved: 3, OtherPoolsTotal: others, Headroom: 20}}
		}
		cases := []struct {
			name string
			db   DB
			ok   bool
			val  int
			cap  int
		}{
			{"пул 0 недоступен", db(0, 200, 0), false, 0, 0},
			{"cap < pool+1", db(50, 200, 140), false, 0, 37},
			{"cap = pool+1", db(50, 200, 126), true, 51, 51},
			{"отрицательный cap", db(50, 200, 190), false, 0, -13},
			{"обычный", db(50, 400, 10), true, 63, 75},
		}
		for _, c := range cases {
			v, ok := ResizePool(c.db)
			if ok != c.ok || (ok && v != c.val) || ResizeCap(c.db) != c.cap {
				t.Errorf("%s: got (%d,%v,cap=%d), want (%d,%v,cap=%d)", c.name, v, ok, ResizeCap(c.db), c.val, c.ok, c.cap)
			}
		}
	})
	t.Run("max_connections", func(t *testing.T) {
		for in, want := range map[int]int{1: 2, 0: 0, 300: 375, 200: 250} {
			if got := MaxConnections(Postgres{MaxConnections: in}); got != want {
				t.Errorf("MaxConnections(%d)=%d, want %d", in, got, want)
			}
		}
	})
}

// Защита от «оптимизации» float-формул целочисленной арифметикой с другим округлением.
func TestFloatVsIntFormulas(t *testing.T) {
	for n := 0; n <= 100000; n++ {
		if got, want := ceilMul(n, 1.5), (3*n+1)/2; got != want {
			t.Fatalf("ceil(%d*1.5)=%d, want %d", n, got, want)
		}
		if got, want := ceilMul(n, 1.25), (5*n+3)/4; got != want {
			t.Fatalf("ceil(%d*1.25)=%d, want %d", n, got, want)
		}
		if got, want := floorMul(n, 0.75), 3*n/4; got != want {
			t.Fatalf("floor(%d*0.75)=%d, want %d", n, got, want)
		}
		if got, want := ceilMul(n, 0.5), (n+1)/2; got != want {
			t.Fatalf("ceil(%d*0.5)=%d, want %d", n, got, want)
		}
	}
	if math.Ceil(1.5) != 2 {
		t.Fatal("math.Ceil")
	}
}

func TestRegistry(t *testing.T) {
	r := DefaultRegistry()
	for _, id := range []string{"workload.scale_out.v1", "workload.scale_in.v1", "pgbouncer.resize_pool.v1", "postgres.max_connections.v1"} {
		if !r.HasStep(id) || r.HasBounds(id) {
			t.Errorf("%s: ожидалось правило шага", id)
		}
	}
	for _, id := range []string{"workload.scale_out.bounds.v1", "workload.scale_in.bounds.v1", "pgbouncer.resize_pool.bounds.v1"} {
		if !r.HasBounds(id) || r.HasStep(id) {
			t.Errorf("%s: ожидалось правило границ", id)
		}
	}
	if r.HasStep("nope") || r.HasBounds("nope") {
		t.Error("неизвестное правило найдено")
	}
	if _, ok := r["workload.scale_out.v1"].Value(TargetState{}); ok {
		t.Error("правило без autoscaler должно быть неприменимо")
	}
}

func TestValidate(t *testing.T) {
	a := asc(1, 2, 3)
	a.Kind = "Other"
	if (TargetState{Autoscaler: &a}).Validate() == nil {
		t.Error("неизвестный kind принят")
	}
	b := asc(1, 2, 3)
	b.Max = -1
	if (TargetState{Autoscaler: &b}).Validate() == nil {
		t.Error("отрицательное число принято")
	}
	if err := (TargetState{}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestValidate_UpperBound(t *testing.T) {
	a := asc(1, 2, 3)
	a.CurrentMin = maxValue + 1
	if (TargetState{Autoscaler: &a}).Validate() == nil {
		t.Error("значение выше потолка принято")
	}
	a.CurrentMin = maxValue
	if err := (TargetState{Autoscaler: &a}).Validate(); err != nil {
		t.Error(err)
	}
}
