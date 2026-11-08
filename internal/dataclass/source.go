package dataclass

import (
	"fmt"
	"regexp"
)

var sourceIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Source — источник данных intake. Реестр источников — data-classes §3 п. 1.
type Source struct {
	ID    string // "metrics.prometheus" и т. п.
	Class Class  // класс по умолчанию
	Title string // строка таблицы §3
	// ExternalConfidential — источник confidential явно включён для внешнего LLM (§4.2).
	// NewRegistry отвергает true, пока ConfidentialExternalAvailable == false.
	ExternalConfidential bool
	// MayContainPersonalDataRU — источник может содержать ПДн граждан РФ: наружу никогда, независимо от класса.
	MayContainPersonalDataRU bool
}

// Registry — реестр источников.
type Registry struct{ m map[string]Source }

// NewRegistry проверяет и собирает реестр.
func NewRegistry(srcs []Source) (*Registry, error) {
	r := &Registry{m: make(map[string]Source, len(srcs))}
	for _, s := range srcs {
		if !sourceIDRe.MatchString(s.ID) {
			return nil, fmt.Errorf("dataclass: некорректный ID источника %q", s.ID)
		}
		if _, dup := r.m[s.ID]; dup {
			return nil, fmt.Errorf("dataclass: источник %q задан дважды", s.ID)
		}
		if s.Class < Public || s.Class > Restricted {
			return nil, fmt.Errorf("dataclass: источник %q: невалидный класс", s.ID)
		}
		if s.ExternalConfidential {
			if !ConfidentialExternalAvailable {
				return nil, fmt.Errorf("dataclass: источник %q: отправка confidential наружу в MVP невозможна", s.ID)
			}
			if s.Class != Confidential {
				return nil, fmt.Errorf("dataclass: источник %q: external_confidential только у класса confidential", s.ID)
			}
		}
		r.m[s.ID] = s
	}
	return r, nil
}

// MVPRegistry — источники MVP (data-classes §3 п. 1 и §1.3). Паника при ошибке: данные в коде, ловится тестом.
func MVPRegistry() *Registry {
	r, err := NewRegistry([]Source{
		// §3 «Метрики Prometheus/Mimir».
		{ID: "metrics.prometheus", Class: Internal, Title: "Метрики Prometheus/Mimir"},
		// §3 «Алерты Alertmanager, PagerDuty, Opsgenie».
		{ID: "alerts.alertmanager", Class: Internal, Title: "Алерты Alertmanager"},
		{ID: "alerts.pagerduty", Class: Internal, Title: "Алерты PagerDuty"},
		{ID: "alerts.opsgenie", Class: Internal, Title: "Алерты Opsgenie"},
		// §3 «Логи (Loki, ClickHouse)», §4.2: возможны ПДн граждан РФ.
		{ID: "logs.loki", Class: Confidential, Title: "Логи Loki", MayContainPersonalDataRU: true},
		{ID: "logs.clickhouse", Class: Confidential, Title: "Логи ClickHouse", MayContainPersonalDataRU: true},
		// §3 «Трейсы Tempo».
		{ID: "traces.tempo", Class: Confidential, Title: "Трейсы Tempo", MayContainPersonalDataRU: true},
		// §3 «Payload (eBPF, тела HTTP)».
		{ID: "payload.ebpf", Class: Restricted, Title: "Payload eBPF"},
		{ID: "payload.http_body", Class: Restricted, Title: "Тела HTTP-запросов"},
		// §3 «pg_stat_activity, медленный лог Postgres» — restricted; «pg_stat_statements» — confidential.
		{ID: "db.pg_stat_activity", Class: Restricted, Title: "pg_stat_activity"},
		{ID: "db.pg_slow_log", Class: Restricted, Title: "Медленный лог Postgres"},
		{ID: "db.pg_stat_statements", Class: Confidential, Title: "pg_stat_statements"},
		// §3 «Код, PR, тикеты, постмортемы»; тикеты и постмортемы могут содержать ПДн.
		{ID: "code.source", Class: Confidential, Title: "Исходный код"},
		{ID: "code.pr", Class: Confidential, Title: "Pull request'ы"},
		{ID: "tickets", Class: Confidential, Title: "Тикеты", MayContainPersonalDataRU: true},
		{ID: "postmortems", Class: Confidential, Title: "Постмортемы", MayContainPersonalDataRU: true},
		// §3 «Манифесты, Helm, IaC» (сюда же PDB): internal «после сканера секретов» — маскировщик
		// вызывается для каждого internal-фрагмента.
		{ID: "manifests.k8s", Class: Internal, Title: "Манифесты Kubernetes, Helm, IaC"},
		// §1.3 «события деплоев и Kubernetes».
		{ID: "k8s.events", Class: Internal, Title: "События Kubernetes"},
		{ID: "k8s.deploys", Class: Internal, Title: "События деплоев"},
		{ID: "k8s.rollout_status", Class: Internal, Title: "Статус rollout"},
		// §2 «имена сервисов, топология».
		{ID: "platform.topology", Class: Internal, Title: "Сервис, автоскейлер, поды"},
		// §1.3 «манифесты и runbook'и»: каталог действий генерирует платформа.
		{ID: "platform.action_catalog", Class: Internal, Title: "Допустимые действия (allowed_actions)"},
		// §1.3 «агрегаты СУБД».
		{ID: "db.aggregates", Class: Internal, Title: "Агрегаты СУБД: сессии по состояниям, SHOW POOLS, параметры пула"},
		// §2 «внутренние runbook'и».
		{ID: "kb.runbooks", Class: Internal, Title: "Runbook'и"},
	})
	if err != nil {
		panic(err)
	}
	return r
}

// Lookup: неизвестный источник → Source{ID: id, Class: Restricted}, false (§3 п. 2, fail-closed).
func (r *Registry) Lookup(id string) (Source, bool) {
	if s, ok := r.m[id]; ok {
		return s, true
	}
	return Source{ID: id, Class: Restricted}, false
}

// ExternalAllowed — можно ли фрагмент источника src с текущим классом c отправить во внешний LLM.
func ExternalAllowed(src Source, c Class) bool {
	if src.MayContainPersonalDataRU {
		return false
	}
	switch c {
	case Public, Internal:
		return true
	case Confidential:
		return ConfidentialExternalAvailable && src.ExternalConfidential
	}
	return false
}
