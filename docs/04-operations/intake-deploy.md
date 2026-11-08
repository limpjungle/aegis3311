# Развёртывание read-only intake (`aegis-intake`)

> Статус: Этап 0a, MVP-A. Всё, что касается конкретики окружения (PromQL, `db_queries`, matchers Alertmanager, URL, реестр сервисов), живёт только в конфигурации intake, не в коде. Пример ниже построен на типовом стеке; допущения окружения **подтверждены владельцем 08.11.2026** (раздел «Допущения»). Конкретные URL, PromQL и реестр сервисов задаются в конфигурации и проверяются командой `collect` перед shadow.

Устройство и поведение — [architecture.md](../00-overview/architecture.md) §6.2 «Intake». Аварийные процедуры — [degraded-mode.md](degraded-mode.md). Запуск: `aegis-intake serve -config /etc/aegis/intake.json` (он же держит роутер: `aegis-llmrouter serve` одновременно не запускается).

## Допущения окружения *(подтверждены 08.11.2026)*

Код и пример конфигурации написаны под типовой стек; владелец окружения подтвердил п. 1–9 *(08.11.2026)*. Если окружение изменится, допущение заменяется правкой конфигурации (код менять не нужно, кроме п. 5, 7–8).

1. **Метрики и экспортеры.** Prometheus (не Mimir; заголовки tenant, если понадобятся, задаются в `prometheus.headers`); ingress-nginx (метрики `nginx_ingress_controller_*` с метками `exported_namespace`/`exported_service`, имя Service ингресса совпадает с именем сервиса); kube-state-metrics и cAdvisor (`container_*`, `kube_pod_*`); pgbouncer_exporter (`pgbouncer_pools_*`, `pgbouncer_databases_*`); postgres_exporter (`pg_settings_*`, `pg_stat_activity_*` и custom query на `aegis.sessions_by_state()`, см. ниже). Метрики приложения `app_http_5xx_ratio` — самоотчёт приложения (`self_reported`), имя и метки выбирает команда сервиса. Для `pg_query_duration_p95_ms` стандартного экспортёра нет: в примере предполагается recording rule `aegis:pg_query_duration_p95_ms`. Метка `limit_mb` серии `memory_working_set_mb` в примере не заполняется (нужен join с `kube_pod_container_resource_limits`).
2. **Alertmanager.** URL, способ аутентификации (Bearer-токен из `AEGIS_ALERTMANAGER_TOKEN_FILE` либо сетевой доступ без токена), CA; у алертов целевого потока есть метки `namespace` и `service`, значения которых совпадают с именами в Kubernetes; `severity` ∈ {critical, warning, info}; есть метка-маркер целевого потока и matcher на неё (в примере `aegis_flow="true"`). Сервисы, чьи алерты используют другие метки, не будут видны intake.
3. **Кластер.** Один кластер на процесс; API-сервер доступен по HTTPS с CA из файла; создан ServiceAccount с read-only ClusterRole (ниже), токен смонтирован в файл (`AEGIS_KUBE_TOKEN_FILE`, ротация — файл перечитывается на каждый запрос).
4. **Среда матрицы.** `environment` ∈ {`staging`, `prod-cloud-hybrid`, `prod-baremetal`} (как в `matrix.rego`); на старте shadow — одна среда.
5. **Rollout.** Argo Rollouts с **нативным threshold-AnalysisRun** (метрики с порогами), а не статистическим гейтом: `baseline` и `p_value` в живых данных `null`. Фаза `Bake` определяется временем (`bake` сервиса) после полного продвижения (условие `Progressing` с причиной `NewReplicaSetAvailable`). Если используется статистический гейт, клиент `internal/intake/kube/rollout.go` нужно доработать. AnalysisRun берётся по метке `rollouts-pod-template-hash` текущей ревизии (`status.currentPodHash`) и ownerReference Rollout; если анализа новой ревизии ещё нет — `analysis_run: null`; в фазах Progressing и Bake дополнительно передаётся `previous_analysis_run` (последний AnalysisRun Rollout другой ревизии, с номером ревизии; к текущему canary не относится, в `computed.analysis_run` не попадает), статус источника `k8s.rollout_status` — `partial`; ошибка этого запроса не делает источник недоступным. Фаза AnalysisRun отображается в вердикт так: `Successful` → `success`, `Failed` → `degradation`, `Error` (сбой провайдера метрик) → `error` (отдельный вердикт, не `degradation` и не `inconclusive`; метрика без значения — `canary: null`, не значима), `Inconclusive` → `inconclusive`, `Pending`/`Running`/пусто → `running`.
6. **Реестр сервисов и метки.** Реестр `services` — целевой поток, ревьюится в Git. Namespace каждого сервиса несёт метку `aegisops.io/managed=true` (иначе каждый вердикт PEP — `deny namespace_not_managed`; `serve` предупреждает при старте), workload — `aegisops.io/stateless=true`, где это верно. `declared_min` и `insufficient_data_policy` берутся из реестра, не из кластера.
7. **Автор деплоя.** `author_id` берётся из аннотации ReplicaSet, имя которой задано в `kubernetes.author_annotation` (её ставит CI); без неё — `unknown`. Автор из ArgoCD — Этап 3a.
8. **Деплой.** Ревизия — аннотация `deployment.kubernetes.io/revision` (Deployment) или `rollout.argoproj.io/revision` (Rollout) у ReplicaSet; digest образа — из `imageID` пода этого ReplicaSet (если подов нет, `unknown`). OOMKilled берётся из подов по селектору workload'а (не из всего namespace).
9. **Экспорт данных БД.** Агрегаты СУБД — из Prometheus; креды БД и драйвер в Control Plane не нужны. Прямой доступ (`stats_users`, `SECURITY DEFINER`) — за Cluster Agent в MVP-B.

## Права в Kubernetes (только чтение)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: aegis-intake-readonly}
rules:
  - apiGroups: [""]
    resources: [pods, events, namespaces]
    verbs: [get, list]
  - apiGroups: [apps]
    resources: [replicasets, deployments]
    verbs: [get, list]
  - apiGroups: [autoscaling]
    resources: [horizontalpodautoscalers]
    verbs: [get, list]
  - apiGroups: [policy]
    resources: [poddisruptionbudgets]
    verbs: [get, list]
  - apiGroups: [argoproj.io]
    resources: [rollouts, analysisruns]
    verbs: [get, list]
  - apiGroups: [keda.sh]
    resources: [scaledobjects]
    verbs: [get, list]
# secrets, pods/exec и любые глаголы записи не выдаются
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: aegis-intake-readonly}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: aegis-intake-readonly}
subjects: [{kind: ServiceAccount, name: aegis-intake, namespace: aegis-system}]
```

`list pods` возвращает спеки подов вместе с `env`; intake читает из ответа только имена, фазы, `imageID` и `lastState.terminated` — принято (риск зафиксирован в [threat-model.md](../02-security/threat-model.md)); альтернатива — metadata-only запросы.

## Листы Kubernetes: пагинация и потолки

Листы читаются постранично (`limit`/`continue`) с потолком объектов и страниц; размер страницы подобран так, чтобы ответ помещался в лимит на один ответ (8 MiB).

| Вид | Страница | Максимум объектов | Максимум страниц |
|---|---|---|---|
| Поды | 100 | 1000 | 20 |
| События | 250 | 1000 | 8 |
| ReplicaSet | 100 | 500 | 10 |
| AnalysisRun (и второй лист для `previous_analysis_run`) | 50 | 200 | 8 |
| PodDisruptionBudget | 100 | 500 | 10 |

- Достижение потолка — статус источника `truncated`, данные используются (для топологии это не сбой критичного источника). Порядок листа — по ключам etcd, поэтому при усечении событий могут потеряться свежие.
- Ошибка любой страницы, включая `410 Gone` истёкшего `continue`, — вся операция `unavailable` с классом ошибки (`http_410` и т. п.), без повтора.
- `resourceVersion` не задаётся: сервер отдаёт все страницы на версии первой, консистентность — по первой странице.
- Весь лист метода укладывается в `request_timeout`, иначе `timeout`.

Селекторы workload'ов: `matchLabels` и `matchExpressions` (`In`, `NotIn`, `Exists`, `DoesNotExist`). Пустой селектор, неизвестный оператор, некорректные ключ или значение — `decode` (источник `unavailable`; для топологии — `not_routed/source_unavailable`). PDB сопоставляется по меткам шаблона пода workload'а с учётом `matchExpressions`; PDB с пустым селектором игнорируется.

## postgres_exporter: custom query на `aegis.sessions_by_state()`

Функция — [runbooks.md](runbooks.md) §4.1 (только агрегаты, без текстов запросов). Файл custom queries:

```yaml
aegis_sessions_by_state:
  query: "SELECT state, sessions, over_60s FROM aegis.sessions_by_state()"
  metrics:
    - state:    {usage: "LABEL",  description: "Состояние сессии"}
    - sessions: {usage: "GAUGE",  description: "Сессий в состоянии"}
    - over_60s: {usage: "GAUGE",  description: "Сессий в состоянии дольше 60 с"}
```

Метрики получают имена `aegis_sessions_by_state_sessions{state=...}` и `aegis_sessions_by_state_over_60s{state=...}`; роль экспортера получает `EXECUTE` на функцию.

## Пример конфигурации

Секреты — только из файлов: `OPENROUTER_API_KEY_FILE`, `AEGIS_MASKER_KEY_FILE`, `AEGIS_AUDIT_KEY_FILE`, `AEGIS_KUBE_TOKEN_FILE` и необязательные `AEGIS_ALERTMANAGER_TOKEN_FILE`, `AEGIS_PROMETHEUS_TOKEN_FILE`. Подстановки в запросах — только `$namespace`, `$service`, `$database`, `$pg_cluster`, и только из реестра `services`, не из алерта. Сокращено: показаны не все 13 метрик; ключи `db_queries` перечислены полностью (`intake.DBQueryKeys`) и обязательны, если у какого-то сервиса задан `database`.

```json
{
  "intake_id": "intake-1",
  "router_config": "/etc/aegis/llmrouter.json",
  "state_path": "/var/lib/aegis/intake.state.json",
  "snapshot_dir": "/var/lib/aegis/snapshots",
  "environment": "prod-cloud-hybrid",
  "poll_interval": "15s", "settle": "2m", "close_after": "15m",
  "collect_timeout": "30s", "request_timeout": "5s",
  "workers": 2, "max_open_incidents": 256, "max_routed_per_service_hour": 6,
  "alertmanager": {"url": "https://alertmanager.monitoring.svc:9093", "ca_file": "/etc/aegis/ca.pem", "matchers": ["aegis_flow=\"true\""]},
  "prometheus": {"url": "https://prometheus.monitoring.svc:9090", "ca_file": "/etc/aegis/ca.pem", "headers": {}},
  "kubernetes": {"api_url": "https://kubernetes.default.svc", "ca_file": "/etc/aegis/kube-ca.pem", "author_annotation": "ci.example.com/deployed-by"},
  "services": [
    {"namespace": "shop", "service": "geo-svc", "workload": {"kind": "Rollout", "name": "geo-svc"},
     "autoscaler": {"kind": "HorizontalPodAutoscaler", "name": "geo-svc"}, "declared_min": 2,
     "database": "geo", "pg_cluster": "pg-main", "insufficient_data_policy": "hold", "bake": "60m", "llm_mode": "hybrid"}
  ],
  "metrics": [
    {"name": "ingress_p99_latency_ms", "unit": "ms", "max_series": 1, "static_labels": {"service": "$service"},
     "query": "1000 * histogram_quantile(0.99, sum by (le) (rate(nginx_ingress_controller_request_duration_seconds_bucket{exported_namespace=\"$namespace\",exported_service=\"$service\"}[2m])))"},
    {"name": "ingress_5xx_ratio", "unit": "ratio", "max_series": 1, "static_labels": {"service": "$service"},
     "query": "sum(rate(nginx_ingress_controller_requests{exported_namespace=\"$namespace\",exported_service=\"$service\",status=~\"5..\"}[2m])) / sum(rate(nginx_ingress_controller_requests{exported_namespace=\"$namespace\",exported_service=\"$service\"}[2m]))"},
    {"name": "ingress_requests_rate", "unit": "rps", "max_series": 1, "static_labels": {"service": "$service"},
     "query": "sum(rate(nginx_ingress_controller_requests{exported_namespace=\"$namespace\",exported_service=\"$service\"}[2m]))"},
    {"name": "app_http_5xx_ratio", "unit": "ratio", "max_series": 1, "self_reported": true, "static_labels": {"service": "$service"},
     "query": "sum(rate(http_server_requests_total{namespace=\"$namespace\",service=\"$service\",status=~\"5..\"}[2m])) / sum(rate(http_server_requests_total{namespace=\"$namespace\",service=\"$service\"}[2m]))"},
    {"name": "cpu_utilization_ratio", "unit": "ratio_of_requests", "max_series": 1, "static_labels": {"service": "$service"},
     "query": "sum(rate(container_cpu_usage_seconds_total{namespace=\"$namespace\",pod=~\"$service-.*\",container!=\"\",container!=\"POD\"}[2m])) / sum(kube_pod_container_resource_requests{namespace=\"$namespace\",pod=~\"$service-.*\",resource=\"cpu\"})"},
    {"name": "memory_working_set_mb", "unit": "MB", "max_series": 12, "series_labels": ["pod"], "static_labels": {"service": "$service"},
     "query": "sum by (pod) (container_memory_working_set_bytes{namespace=\"$namespace\",pod=~\"$service-.*\",container!=\"\",container!=\"POD\"}) / 1048576"},
    {"name": "pod_restarts_total", "unit": "count", "max_series": 1, "static_labels": {"service": "$service"},
     "query": "sum(kube_pod_container_status_restarts_total{namespace=\"$namespace\",pod=~\"$service-.*\"})"},
    {"name": "kafka_consumer_lag", "unit": "messages", "applies": "kafka", "max_series": 6, "series_labels": ["topic"], "static_labels": {"service": "$service"},
     "query": "sum by (topic) (kafka_consumergroup_lag{consumergroup=\"$service\"})"},
    {"name": "pgbouncer_cl_waiting", "unit": "clients", "applies": "database", "max_series": 1, "static_labels": {"database": "$database", "service": "$service"},
     "query": "sum(pgbouncer_pools_client_waiting_connections{database=\"$database\"})"},
    {"name": "pgbouncer_sv_active", "unit": "connections", "applies": "database", "max_series": 1, "static_labels": {"database": "$database", "service": "$service"},
     "query": "sum(pgbouncer_pools_server_active_connections{database=\"$database\"})"},
    {"name": "pgbouncer_maxwait_seconds", "unit": "s", "applies": "database", "max_series": 1, "static_labels": {"database": "$database", "service": "$service"},
     "query": "max(pgbouncer_pools_client_maxwait_seconds{database=\"$database\"})"},
    {"name": "pg_connections_total", "unit": "connections", "applies": "database", "max_series": 1, "static_labels": {"cluster": "$pg_cluster"},
     "query": "sum(pg_stat_activity_count{cluster=\"$pg_cluster\"})"},
    {"name": "pg_query_duration_p95_ms", "unit": "ms", "applies": "database", "max_series": 1, "static_labels": {"database": "$database"},
     "query": "max(aegis:pg_query_duration_p95_ms{database=\"$database\"})"}
  ],
  "db_queries": {
    "pool_size": "max(pgbouncer_databases_pool_size{database=\"$database\"})",
    "max_connections": "max(pg_settings_max_connections{cluster=\"$pg_cluster\"})",
    "superuser_reserved_connections": "max(pg_settings_superuser_reserved_connections{cluster=\"$pg_cluster\"})",
    "other_pools_total": "sum(pgbouncer_databases_pool_size{cluster=\"$pg_cluster\",database!=\"$database\"}) or vector(0)",
    "sessions_active": "sum(aegis_sessions_by_state_sessions{cluster=\"$pg_cluster\",state=\"active\"}) or vector(0)",
    "sessions_active_over_60s": "sum(aegis_sessions_by_state_over_60s{cluster=\"$pg_cluster\",state=\"active\"}) or vector(0)",
    "sessions_idle": "sum(aegis_sessions_by_state_sessions{cluster=\"$pg_cluster\",state=\"idle\"}) or vector(0)",
    "sessions_idle_over_60s": "sum(aegis_sessions_by_state_over_60s{cluster=\"$pg_cluster\",state=\"idle\"}) or vector(0)",
    "sessions_idle_in_transaction": "sum(aegis_sessions_by_state_sessions{cluster=\"$pg_cluster\",state=\"idle in transaction\"}) or vector(0)",
    "sessions_idle_in_transaction_over_60s": "sum(aegis_sessions_by_state_over_60s{cluster=\"$pg_cluster\",state=\"idle in transaction\"}) or vector(0)",
    "cl_active": "sum(pgbouncer_pools_client_active_connections{database=\"$database\"})",
    "cl_waiting": "sum(pgbouncer_pools_client_waiting_connections{database=\"$database\"})",
    "sv_active": "sum(pgbouncer_pools_server_active_connections{database=\"$database\"})",
    "sv_idle": "sum(pgbouncer_pools_server_idle_connections{database=\"$database\"})",
    "maxwait_s": "max(pgbouncer_pools_client_maxwait_seconds{database=\"$database\"})"
  }
}
```

Поведение при пустом результате: в `metrics` запрос без серий даёт секцию без элементов (статус `empty`); в `db_queries` пустой вектор — ошибка (агрегаты неполны, `db.aggregates` критичен), поэтому запросы, у которых «нет данных» значит «ноль», заканчиваются на `or vector(0)`.

## Проверка перед shadow

1. `aegis-intake collect -config FILE -namespace NS -service SVC -print-input` по каждому сервису реестра: все источники `ok`, форма входа читается глазами, нет исключённых фрагментов (`excluded`), `not_sent` пусто.
2. `aegis-intake replay -config FILE -in snapshot.json -prepare-only` — красные команды RT-01/02/04 без живых источников.
3. ~~Подтверждение п. 1–9 раздела «Допущения» владельцами окружения~~ — подтверждено 08.11.2026; остаётся убедиться по выводу `collect` (п. 1), что фактические имена метрик и меток совпадают с конфигурацией.
4. `aegis-audit verify` после первых записей: блок `intake` читается новыми версиями; старые `aegis-audit` записи с этим блоком не прочтут — обновить все копии.
