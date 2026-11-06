package step

import "math"

// Bounds — допустимый отрезок величины, Min <= v <= Max.
type Bounds struct{ Min, Max int }

// Все формулы считаются через float64, как float в Python: ceil/floor от n*k.
func ceilMul(n int, k float64) int  { return int(math.Ceil(float64(n) * k)) }
func floorMul(n int, k float64) int { return int(math.Floor(float64(n) * k)) }

func ScaleOutBounds(a Autoscaler) Bounds {
	return Bounds{Min: a.CurrentMin + 1, Max: min(a.Max, 2*a.CurrentMin)}
}

// ScaleOut: ok = границы непусты (действие доступно).
func ScaleOut(a Autoscaler) (int, bool) {
	b := ScaleOutBounds(a)
	return min(b.Max, max(a.CurrentMin+1, ceilMul(a.CurrentMin, 1.5))), b.Min <= b.Max
}

func ScaleInBounds(a Autoscaler) Bounds {
	return Bounds{Min: max(a.DeclaredMin, ceilMul(a.CurrentMin, 0.5)), Max: a.CurrentMin - 1}
}

func ScaleIn(a Autoscaler) (int, bool) {
	b := ScaleInBounds(a)
	return max(b.Min, min(a.CurrentMin-1, floorMul(a.CurrentMin, 0.75))), b.Min <= b.Max
}

// ResizeCap — верхняя граница пула; при нехватке соединений может быть отрицательной.
func ResizeCap(db DB) int {
	pg := db.Postgres
	return min(ceilMul(db.PgBouncer.PoolSize, 1.5), pg.MaxConnections-pg.SuperuserReserved-pg.OtherPoolsTotal-pg.Headroom)
}

func ResizePoolBounds(db DB) Bounds {
	return Bounds{Min: db.PgBouncer.PoolSize + 1, Max: ResizeCap(db)}
}

func ResizePool(db DB) (int, bool) {
	b := ResizePoolBounds(db)
	pool := db.PgBouncer.PoolSize
	return min(b.Max, max(pool+1, ceilMul(pool, 1.25))), b.Min <= b.Max
}

func MaxConnections(pg Postgres) int {
	return min(pg.MaxConnections*2, ceilMul(pg.MaxConnections, 1.25))
}

// Rule — зарегистрированное правило. У правила шага задан Value, у правила границ — Limits.
// ok=false означает, что правило неприменимо к состоянию (нет нужной части цели) или действие недоступно.
type Rule struct {
	Value  func(TargetState) (int, bool)
	Limits func(TargetState) (Bounds, bool)
}

// Registry — правила по идентификаторам из записей каталога.
type Registry map[string]Rule

func (r Registry) HasStep(id string) bool   { return r[id].Value != nil }
func (r Registry) HasBounds(id string) bool { return r[id].Limits != nil }

func DefaultRegistry() Registry {
	return Registry{
		"workload.scale_out.v1": {Value: func(s TargetState) (int, bool) {
			if s.Autoscaler == nil {
				return 0, false
			}
			return ScaleOut(*s.Autoscaler)
		}},
		"workload.scale_out.bounds.v1": {Limits: func(s TargetState) (Bounds, bool) {
			if s.Autoscaler == nil {
				return Bounds{}, false
			}
			return ScaleOutBounds(*s.Autoscaler), true
		}},
		"workload.scale_in.v1": {Value: func(s TargetState) (int, bool) {
			if s.Autoscaler == nil {
				return 0, false
			}
			return ScaleIn(*s.Autoscaler)
		}},
		"workload.scale_in.bounds.v1": {Limits: func(s TargetState) (Bounds, bool) {
			if s.Autoscaler == nil {
				return Bounds{}, false
			}
			return ScaleInBounds(*s.Autoscaler), true
		}},
		"pgbouncer.resize_pool.v1": {Value: func(s TargetState) (int, bool) {
			if s.DB == nil {
				return 0, false
			}
			return ResizePool(*s.DB)
		}},
		"pgbouncer.resize_pool.bounds.v1": {Limits: func(s TargetState) (Bounds, bool) {
			if s.DB == nil {
				return Bounds{}, false
			}
			return ResizePoolBounds(*s.DB), true
		}},
		"postgres.max_connections.v1": {Value: func(s TargetState) (int, bool) {
			if s.DB == nil {
				return 0, false
			}
			return MaxConnections(s.DB.Postgres), true
		}},
	}
}
