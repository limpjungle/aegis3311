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

## Kill switch

Устройство — [architecture.md](../00-overview/architecture.md) §2.2, угроза — T-22 в [threat-model.md](../02-security/threat-model.md), учение G0 — [kill-switch-drill.md](kill-switch-drill.md). Intake опрашивает два канала с одним и тем же подписанным документом: ConfigMap `aegisops-control/kill-switch` (ключ `document`) и объект в S3 (внешний канал). Нет свежего подтверждения двумя подписями — роутер в режиме `off` для всех целей intake.

**1. Namespace и ConfigMap.** ConfigMap создаётся при установке (server-side apply без права `create` его не создаёт); начальное содержимое пусто — intake остановлен, пока не опубликован первый документ:

```yaml
apiVersion: v1
kind: Namespace
metadata: {name: aegisops-control}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: kill-switch, namespace: aegisops-control}
data: {}
```

**2. Права (Role в `aegisops-control`, не ClusterRole).** Intake — `get` на ConfigMap `kill-switch`; дежурные и renewer — `get`, `patch`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: aegis-kill-switch-read, namespace: aegisops-control}
rules: [{apiGroups: [""], resources: [configmaps], resourceNames: [kill-switch], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: aegis-kill-switch-write, namespace: aegisops-control}
rules: [{apiGroups: [""], resources: [configmaps], resourceNames: [kill-switch], verbs: [get, patch]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: aegis-intake-kill-switch, namespace: aegisops-control}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: aegis-kill-switch-read}
subjects: [{kind: ServiceAccount, name: aegis-intake, namespace: aegis-system}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: aegis-oncall-kill-switch, namespace: aegisops-control}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: aegis-kill-switch-write}
subjects: [{kind: Group, name: aegis-oncall, apiGroup: rbac.authorization.k8s.io}, {kind: ServiceAccount, name: aegis-renewer, namespace: aegisops-control}]
```

Запись в ConfigMap — единственное, что подавляет in-band канал, не имея ключей подписи (стереть stop, положить ещё свежий старый документ), поэтому: (а) включите аудит Kubernetes (`audit.k8s.io`, уровень `Metadata`) на `update`/`patch`/`delete` ConfigMap `aegisops-control/kill-switch` и заведите алерт, если писал не `aegis-oncall` и не `aegis-renewer`; (б) в журнале intake следите за `kill_switch_channel_regressed` (шаг 7). Out-of-band канал при этом остаётся.

Токен записи — `AEGIS_KILLSWITCH_KUBE_TOKEN_FILE` у `aegis-killswitch`. Renewer с внешней инфраструктуры нужен kube-доступ на запись в ConfigMap; если его нет, renewer работает только с `-channels oob`: через ConfigMap тогда проходят только остановки и снятия, а продление подтверждения идёт по внешнему каналу — допустимо, потому что хватает одного свежего подтверждения в любом канале.

**3. Bucket (внешний канал).** Отдельный аккаунт или облако (не там, где живёт кластер), версионирование включено, без CDN и кэширующих прокси, адресация path-style для Yandex Object Storage. Политики по ключам доступа: intake — только `GetObject` на объект `kill-switch.json` (отдельная read-only пара); дежурные — `GetObject`/`PutObject` на него же; renewer — `GetObject`/`PutObject` на него и на `renew/*`, а также `s3:ListBucket` на префикс `renew/` (без него S3 отвечает 403 вместо 404 на ещё не созданную подпись пира; `renew` трактует 403 как «подписи пока нет», но в выводе `peers[].status` различает `missing` (пир ещё не подписал) и `http_403`; постоянный `http_403` у пира — нет прав на чтение или нет `ListBucket`, а не медленный коллега). Lifecycle для префикса `renew/` — удаление через 7 дней. У intake, дежурных и renewer — разные ключи доступа и разные файлы (`AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE`, `AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE`, при временных ключах `AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE`); файлы перечитываются на каждый запрос, ротация без рестарта.

**4. Ключи подписи.** Каждый ключ — `aegis-audit keygen -priv KEY.pem -pub KEY.pub.pem`; приватный остаётся у владельца, публичный раздаётся в `kill_switch.keys` на всех intake и в конфигурацию `aegis-killswitch`. Нужно не меньше двух ключей `oncall` (разные люди) и два ключа `renewer` на независимых хостах и планировщиках (запуск `aegis-killswitch renew` раз в час, в разные минуты). Ключ подписи аудита intake в `keys` входить не должен (код 2). На всех участниках — NTP: `latency_ms` и проверка свежести зависят от часов (допуск `max_skew`, по умолчанию 2m).

**5. Начальная публикация (bootstrap).** Порядок строгий: **сначала запуск intake, потом release.** На цепочке без истории kill switch первая оценка выставляет водяной знак `W` по часам intake («сейчас»), пишет событие `kill_switch_engaged` с `bootstrap=true` и предупреждение `kill_switch_bootstrap`; любой документ с `issued_at` раньше `W` цель не вернёт, даже свежий. Затем `release` одним дежурным (`aegis-killswitch release -out release.json`) и подпись вторым (`aegis-killswitch cosign -in release.json -publish`) — `issued_at` релиза должен быть позже `stop_watermark` из события (часы NTP на машине дежурных; при сомнении подготовьте release заново после старта). До него intake работает с `llm.mode=off` (`no_confirmation`); `bootstrap_awaiting_release=1` в `/metrics` — признак ожидания. Release, подготовленный до старта intake, не действует. То же верно для новой цепочки после потери старой (см. [degraded-mode.md](degraded-mode.md)) и для `replay` на пустой цепочке: первый прогон идёт в `off`, модель — после release.

**6. Поведение.** Документ в каналах — полное состояние: любой новый документ заменяет предыдущий. Остановка одной подписью по `actions` (или по чужому кластеру) без второй подписи заменяет run и останавливает этот intake по `no_confirmation` (fail-safe); чтобы запретить только тип действия и сохранить работу LLM, документ с `actions` должен нести две подписи (`stop -action ... -out`, затем `cosign -publish`). Событие смены состояния — запись `aegisops/killswitch-event/v1` в цепочке аудита; состояние на момент решения — поле `kill_switch` decision record'а. Предупреждения в журнале: `kill_switch_channel` (канал недоступен или документ отвергнут, с классом), `kill_switch_confirmation_expiring` (до конца подтверждения меньше трети TTL: продление не пришло). `replay` без `-prepare-only` читает kill switch так же, как `serve` (с тем же bootstrap), и требует kube-токен и ключи S3 чтения; его записи помечены `intake.source = replay.snapshot`; `collect` и `aegis-llmrouter route` kill switch не читают.

**7. Мониторинг.** Тихий простой — оба renewer сломаны, подтверждение истекло, intake молча в `off` — ловят два независимых механизма; нужны оба.

*`aegis-killswitch check` — в отдельном стеке мониторинга, не в кластере intake* (общая беда не должна ослепить обоих). Хост с правом `GetObject` на `kill-switch.json` (read-only пара S3), `get` на ConfigMap `kill-switch` (токен с `aegis-kill-switch-read`) и конфигурацией `aegis-killswitch`; читает оба канала, подписи не ставит. По cron или systemd timer раз в минуту:

```
aegis-killswitch check -config /etc/aegis/killswitch.json -cluster prod-eu-1 -format prom -out /var/lib/node_exporter/textfile/aegis_killswitch.prom
```

Файл подхватывает textfile-collector node_exporter; запись атомарная. Статус (`ok | stopped | warning | critical`) и причины — без `-format` (JSON); код выхода 0 для `ok` и `stopped`, 1 для `warning` и `critical`. Пороги: `-warn-age` (по умолчанию `renew.slot + 15m` = 75 мин) и `-crit-left` (по умолчанию `renew.ttl / 3` = 2 ч). Метка `cluster` есть у всех рядов check.

*`/metrics` intake.* `"metrics_listen": ":9464"` в конфигурации; пути `GET`/`HEAD` `/metrics` и `/healthz`. `/healthz` отвечает 200, пока жив процесс, и от kill switch не зависит: **readiness по нему не делать**. Занятый или недоступный адрес — код выхода 2 до приёма инцидентов. В метриках нет ID инцидентов, сервисов, namespace, issuer'ов, хешей документов и `intake_id`. Service и PodMonitor:

```yaml
apiVersion: v1
kind: Service
metadata: {name: aegis-intake-metrics, namespace: aegis-system, labels: {app: aegis-intake}}
spec:
  selector: {app: aegis-intake}
  ports: [{name: metrics, port: 9464, targetPort: 9464}]
---
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata: {name: aegis-intake, namespace: aegis-system}
spec:
  selector: {matchLabels: {app: aegis-intake}}
  podMetricsEndpoints: [{port: metrics, path: /metrics, interval: 15s}]
```

(порт пода `metrics: 9464` объявите в Deployment). NetworkPolicy `aegis-intake-metrics` (скрейп только из Prometheus) — в [`deploy/intake/networkpolicy.yaml`](../../deploy/intake/networkpolicy.yaml).

*Алерты.* Правило расхождения требует обоих рядов в одном Prometheus (федерация `/federate` с `match[]` или прямой скрейп); `cluster` у check и intake совпадает (`kill_switch.cluster`).

```yaml
groups:
- name: aegis-killswitch-check            # внешний стек
  rules:
  - alert: KillSwitchRenewalMissed
    expr: time() - aegis_killswitch_confirmation_issued_timestamp_seconds > 4500 and on(cluster) aegis_killswitch_stopped == 0
  - alert: KillSwitchConfirmationExpiring
    expr: aegis_killswitch_confirmed_until_timestamp_seconds > 0 and aegis_killswitch_confirmed_until_timestamp_seconds - time() < 7200
  - alert: KillSwitchCheckStale
    expr: time() - aegis_killswitch_check_timestamp_seconds > 900 or absent(aegis_killswitch_check_timestamp_seconds)
  - alert: KillSwitchChannelDown
    expr: aegis_killswitch_channel_ok == 0
    for: 15m
- name: aegis-intake
  rules:
  - alert: IntakeKillSwitchNoConfirmation
    expr: aegis_intake_killswitch_reason{reason="no_confirmation"} == 1 and on() aegis_intake_killswitch_bootstrap_awaiting_release == 0
    for: 15m
  - alert: IntakeKillSwitchBootstrapAwaitingRelease
    expr: aegis_intake_killswitch_bootstrap_awaiting_release == 1
    for: 10m
    labels: {severity: warning}
  - alert: IntakeKillSwitchPollStale
    expr: time() - aegis_intake_killswitch_last_poll_timestamp_seconds > 60
  - alert: IntakeKillSwitchDisagree     # каналы «работаем», а intake стоит
    expr: aegis_killswitch_check_status{status="ok"} == 1 and on(cluster) aegis_intake_killswitch_stopped == 1
    for: 10m
  - alert: IntakeMetricsDown
    expr: up{job="aegis-intake"} == 0 or absent(up{job="aegis-intake"})
    for: 5m
  - alert: IntakeRouterHalted
    expr: aegis_intake_router_halted == 1
    for: 5m
  - alert: IntakeEgressCanaryDetected   # инцидент безопасности: маскировщик пропустил canary
    expr: increase(aegis_intake_router_canary_blocked_total[10m]) > 0 or aegis_intake_router_halt_reason{reason="egress_canary"} == 1
    labels: {severity: critical}
  - alert: IntakeEgressCanaryDisabled   # только staging, где подбрасываются маркеры
    expr: aegis_intake_router_canary_markers == 0
    for: 30m
    labels: {severity: warning}
```

`IntakeKillSwitchDisagree`: каналы показывают «работаем», а intake остановлен — `W` новее подтверждения (после bootstrap или стёртого stop), у intake нет доступа к каналам (RBAC или egress: `aegis_intake_killswitch_channel_ok == 0`), либо уехали его часы. Алерт Alertmanager `Watchdog` (всегда горящий) направьте во внешний heartbeat (например, сервис dead man's switch): если цепочка Alertmanager сломана, intake не получит инцидентов, и сигналом остановки это не считается. Журнал: `kill_switch_channel_regressed` (`older_document` или `stop_removed`) — запись в канал не из процесса публикации, разбор как инцидент безопасности; `kill_switch_bootstrap` — ожидание release.

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

Секреты — только из файлов: `OPENROUTER_API_KEY_FILE`, `AEGIS_MASKER_KEY_FILE`, `AEGIS_AUDIT_KEY_FILE`, `AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE`, `AEGIS_AUDIT_S3_SECRET_KEY_FILE`, `AEGIS_KUBE_TOKEN_FILE`, `AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE`, `AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE` и необязательные `AEGIS_ALERTMANAGER_TOKEN_FILE`, `AEGIS_PROMETHEUS_TOKEN_FILE`, `AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE` (носители и пути Vault — [инвентаризация](../02-security/identity-secrets-mvp-a.md#3-инвентаризация-секретов)). Секция `kill_switch` обязательна (без неё intake не запускается); `metrics_listen` необязателен (пусто — метрики выключены, см. «Kill switch», шаг 7); пути ключей и пример `oob` — см. «Kill switch» ниже. Подстановки в запросах — только `$namespace`, `$service`, `$database`, `$pg_cluster`, и только из реестра `services`, не из алерта. Сокращено: показаны не все 13 метрик; ключи `db_queries` перечислены полностью (`intake.DBQueryKeys`) и обязательны, если у какого-то сервиса задан `database`.

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
  "metrics_listen": ":9464",
  "kill_switch": {
    "cluster": "prod-eu-1",
    "keys": [
      {"path": "/etc/aegis/kill-switch/oncall-ivanov.pub.pem", "issuer": "oncall-ivanov", "role": "oncall"},
      {"path": "/etc/aegis/kill-switch/oncall-petrov.pub.pem", "issuer": "oncall-petrov", "role": "oncall"},
      {"path": "/etc/aegis/kill-switch/renewer-a.pub.pem", "issuer": "renewer-a", "role": "renewer"},
      {"path": "/etc/aegis/kill-switch/renewer-b.pub.pem", "issuer": "renewer-b", "role": "renewer"}
    ],
    "poll_interval": "10s", "max_skew": "2m",
    "configmap": {"namespace": "aegisops-control", "name": "kill-switch"},
    "oob": {"endpoint": "https://storage.yandexcloud.net", "region": "ru-central1", "bucket": "aegis3311-kill-switch", "key": "kill-switch.json", "path_style": true, "ca_file": ""}
  },
  "policy_bundle": {"path": "/etc/aegis/policy-bundle.json", "required": true, "keys": [{"path": "/etc/aegis/keys/ci-policy-signing.pub", "issuer": "ci/policy-signing"}, {"path": "/etc/aegis/keys/break-glass.pub", "issuer": "ci/break-glass"}]},
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

**`policy_bundle` (обязательна в prod-окружениях, необязательна в staging).** Подписанный policy bundle подтверждает, что политики, каталог и eval-ассеты LLM, встроенные в бинарь, одобрены двумя людьми из разных групп ([ci-four-eyes.md](../07-governance/ci-four-eyes.md), T-24). `aegis-intake serve` и `replay` (без `-prepare-only`) при старте читают `path`, проверяют подпись ключами `keys` (ed25519), одобрения и совпадение файлов bundle со встроенными и пишут в журнал `policy_bundle_verified` (`sequence`, `commit`, `pr`, дайджесты). Поведение зависит от секции:

| Конфигурация | Что делает intake |
|---|---|
| Prod-окружение (`prod-cloud-hybrid`, `prod-baremetal`): секции нет или `required: false` | Код 2 на этапе разбора конфигурации, до чтения секретов (в том числе `collect`) |
| Секции нет (staging) | Запускается, в журнале `policy_bundle_missing`: политики не подтверждены четырьмя глазами |
| Секция есть, `required: false` | Bundle проверяется полностью; при ошибке — предупреждение `policy_bundle_unverified` (причина в `error`), работа продолжается |
| Секция есть, `required: true` | Любая ошибка проверки — код 2 до приёма инцидентов |

Ключи bundle не должны совпадать с ключом аудита и ключами kill switch: пересечение — код 2 при любом `required`. В prod-окружениях секция обязательна и `required: true` (T-24, [stage-0a-status.md](../01-planning/stage-0a-status.md) п. 3); `collect` в prod тоже потребует секцию, потому что проверка конфигурации общая. В staging сохраняется двухшаговое включение: сначала `required: false` и ожидание `policy_bundle_verified` в журнале, затем `true` (чек-лист [ci-four-eyes.md](../07-governance/ci-four-eyes.md), порядок обновления — [migrations.md](migrations.md)). Ключи в примере соответствуют `deploy/policy-bundle/keys.json` (`ci/policy-signing` и `ci/break-glass`). Файл `policy-bundle.json` берётся из того же релиза `v*`, что и бинарь; для сборки не из релиза подходящий `policy-bundle-N` подбирается командой `go run ./cmd/aegis-ci bundle verify -in policy-bundle.json -keys deploy/policy-bundle/keys.json` из того же коммита, из которого собран бинарь (нужен тот, чьё содержимое совпадает со сборкой). Открытые ключи — из `deploy/policy-bundle/keys.json` репозитория. Процедура включения на стенде — [policy-bundle-stand.md](policy-bundle-stand.md).

Поведение при пустом результате: в `metrics` запрос без серий даёт секцию без элементов (статус `empty`); в `db_queries` пустой вектор — ошибка (агрегаты неполны, `db.aggregates` критичен), поэтому запросы, у которых «нет данных» значит «ноль», заканчиваются на `or vector(0)`.

## Бакеты в Yandex Object Storage *(решение 09.11.2026)*

Нужны два бакета Yandex Object Storage, класс хранения **Standard** для обоих: объекты маленькие и читаются постоянно (опрос kill switch, сверка checkpoint'ов на старте), холодные классы только удорожают чтение. Имена глобально уникальны, поэтому с префиксом репозитория; если имя занято — взять другое и поменять `bucket` в конфигурации.

| | `aegis3311-kill-switch` | `aegis3311-audit-worm` |
|---|---|---|
| Назначение | Внешний (out-of-band) канал kill switch, шаг 3 выше | Checkpoint'ы цепочки аудита, раздел «WORM для checkpoint'ов аудита» ниже |
| Где | Отдельное облако или каталог, не там, где кластер | Отдельный каталог, лучше не тот, что у kill switch |
| Версионирование | Включено | Включено |
| Object Lock | Не нужен (объект перезаписывают дежурные и renewer) | Включён; режим по умолчанию **не задавать** — сервис ставит COMPLIANCE и срок на каждый объект |
| Шифрование KMS-ключом | По желанию | **Не включать**: удаление KMS-ключа сделает checkpoint'ы нечитаемыми — обход WORM. Если требуется — ключ в отдельном каталоге с защитой от удаления |
| Доступ | Приватный; без CDN, без хостинга сайта; path-style | Приватный; без CDN, без хостинга сайта; path-style |
| Lifecycle | `renew/` — удаление через 7 дней | Нет (удаление запрещено Object Lock) |
| Ключи | Три разные пары: intake (только чтение `kill-switch.json`), дежурные, renewer — шаг 3 | Отдельный сервисный аккаунт: `PutObject`, `GetObject` (с версиями), `ListBucketVersions`, без Delete |

Порядок для `aegis3311-audit-worm`: COMPLIANCE необратим до истечения срока, поэтому сначала тестовый бакет с `retention: "24h"` — прогнать `aegis-audit checkpoint` и `verify -anchor-config`, попытаться удалить версию объекта (ожидается 403) и проверить пункт 6 раздела WORM. Боевой `retention` — только после утверждения срока хранения Security (`trix13371`) и compliance.

## WORM для checkpoint'ов аудита *(09.11.2026)*

1. Bucket `aegis3311-audit-worm` (см. [«Бакеты в Yandex Object Storage»](#бакеты-в-yandex-object-storage-решение-09112026)) в **отдельном аккаунте/каталоге**: включить версионирование и Object Lock, режим по умолчанию не обязателен — сервис ставит COMPLIANCE и срок на каждый checkpoint (`retention`, например `8760h`; режим необратим до истечения срока, выбирать осознанно).
2. Отдельная пара ключей сервисного аккаунта (не ключи kill switch): `PutObject`, `GetObject` (включая версии), `ListBucketVersions`; **без** `DeleteObject`/`DeleteObjectVersion`. Пути — в `AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE`, `AEGIS_AUDIT_S3_SECRET_KEY_FILE`, необязательно `AEGIS_AUDIT_S3_SESSION_TOKEN_FILE`.
3. В конфигурации роутера (`router_config`):

```json
"audit": {"chain": "...", "chain_id": "aegis-prod", "public_keys": [],
  "anchor": {"kind": "s3", "interval": "5m", "max_lag": "1h",
    "s3": {"endpoint": "https://storage.yandexcloud.net", "region": "ru-central1", "bucket": "aegis3311-audit-worm",
           "prefix": "prod/", "path_style": true, "retention": "8760h", "timeout": "10s"}}}
```

4. Алерты: `aegis_intake_audit_anchor_enabled == 0` (anchor выключен), `aegis_intake_audit_anchor_lag_seconds > 3600` (синхронно с `max_lag`), `rate(aegis_intake_audit_anchor_errors_total[15m]) > 0`, давность `aegis_intake_audit_anchor_last_success_timestamp_seconds`.
5. Проверка: `aegis-audit checkpoint ... -anchor-config FILE`, затем `aegis-audit verify ... -id CHAIN_ID -anchor-config FILE` (в выводе `checkpoints_checked`). Те же `AEGIS_AUDIT_S3_*` в окружении.
6. Не проверено на живом Yandex Object Storage: per-object lock-заголовки без default retention, lock-заголовки в ответе GET, точный XML `?versions` — проверить до включения в shadow.

## Секреты: Vault Agent

Решение — [identity-secrets-mvp-a.md](../02-security/identity-secrets-mvp-a.md). Vault Agent работает init-контейнером: входит по projected-токену с audience `vault`, пишет файлы в tmpfs с правами `0400` и завершается. В поде после старта токена Vault нет; у процесса intake его нет вообще. Фрагмент пода (сокращено):

```yaml
spec:
  serviceAccountName: aegis-intake
  automountServiceAccountToken: false
  initContainers:
    - name: vault-agent
      image: <образ Vault Agent или OpenBao Agent, закреплённый по digest>
      args: ["agent", "-config=/vault/config/aegis-intake.json"]
      securityContext: {runAsUser: 10001, runAsNonRoot: true, readOnlyRootFilesystem: true}
      volumeMounts:
        - {name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true}   # только здесь
        - {name: vault-config, mountPath: /vault/config, readOnly: true}
        - {name: vault-ca, mountPath: /vault/ca, readOnly: true}
        - {name: secrets, mountPath: /vault/secrets}
  containers:
    - name: intake
      securityContext: {runAsUser: 10001, runAsNonRoot: true, readOnlyRootFilesystem: true}
      env:
        - {name: OPENROUTER_API_KEY_FILE, value: /vault/secrets/openrouter}
        - {name: AEGIS_MASKER_KEY_FILE, value: /vault/secrets/masker}
        - {name: AEGIS_AUDIT_KEY_FILE, value: /vault/secrets/audit-signing}
        - {name: AEGIS_ALERTMANAGER_TOKEN_FILE, value: /vault/secrets/alertmanager}
        - {name: AEGIS_PROMETHEUS_TOKEN_FILE, value: /vault/secrets/prometheus}
        - {name: AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE, value: /vault/secrets/killswitch-s3-access-key-id}
        - {name: AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE, value: /vault/secrets/killswitch-s3-secret-key}
        - {name: AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE, value: /vault/secrets/audit-anchor-s3-access-key-id}
        - {name: AEGIS_AUDIT_S3_SECRET_KEY_FILE, value: /vault/secrets/audit-anchor-s3-secret-key}
        - {name: AEGIS_KUBE_TOKEN_FILE, value: /var/run/secrets/kube/token}
      volumeMounts:
        - {name: secrets, mountPath: /vault/secrets, readOnly: true}
        - {name: kube-token, mountPath: /var/run/secrets/kube, readOnly: true}
  volumes:
    - name: secrets
      emptyDir: {medium: Memory}
    - name: kube-token
      projected:
        sources: [{serviceAccountToken: {audience: https://kubernetes.default.svc, expirationSeconds: 3600, path: token}}]
    - name: vault-token
      projected:
        sources: [{serviceAccountToken: {audience: vault, expirationSeconds: 600, path: token}}]
    - {name: vault-config, configMap: {name: aegis-intake-vault-agent}}
    - {name: vault-ca, configMap: {name: vault-ca}}
```

Дополнительно:

- У init-контейнера и intake одинаковый `runAsUser`: иначе файлы `0400` не читаются (проверить на стенде).
- NetworkPolicy: egress к OpenBao (8200) — правило в [`deploy/intake/cilium-egress.yaml`](../../deploy/intake/cilium-egress.yaml); ingress в OpenBao — сделано, [`deploy/vault/network/`](../../deploy/vault/network/), см. [README](../../deploy/vault/README.md).
- Политика, роль и конфигурация агента лежат в [`deploy/vault/`](../../deploy/vault/); меняются только через PR с четырьмя глазами.
- Секреты читаются при старте пода. Ротация — rolling restart; автоматической ротации нет (цена отсутствия живого токена).
- Vault недоступен или секрет не найден: init-контейнер завершается с ошибкой, под не стартует (fail-closed). Для kill switch это допустимо: intake без состояния не работает.
- OpenBao sealed (после рестарта узлов Shamir требует ввода долей кворумом 2 из 3, [identity-secrets-mvp-a.md §9](../02-security/identity-secrets-mvp-a.md#9-vault-или-openbao)): новые поды intake не стартуют до unseal (init-контейнер повторяет вход с backoff, под остаётся в Pending), уже работающие продолжают — секреты у них в tmpfs. Поэтому для Deployment intake `strategy.rollingUpdate.maxUnavailable: 0`: старый под не убирается, пока новый не стал Ready. Проверено на стенде [`deploy/vault/dev/run-ha.sh`](../../deploy/vault/dev/run-ha.sh).

## Сеть: NetworkPolicy и Cilium *(T-17)*

Манифесты — [`deploy/intake/`](../../deploy/intake/) (каталог защищён четырьмя глазами); применяет их CI-применитель после PR, до применения обязателен `kubectl apply --dry-run=server`. Порядок: сначала `cilium-egress.yaml`, затем `networkpolicy.yaml`.

**CNI — Cilium (решение 11.11.2026).** Egress по именам (`toFQDNs`) работает только через DNS-прокси Cilium, SNI-фильтр (`serverNames`) — через L7-прокси (Envoy). Без Cilium `CiliumNetworkPolicy` не применится (нет CRD), а default-deny останется: intake без egress не стартует (fail-closed).

*Создание кластера Yandex MK8s.* Cilium выбирается только при создании кластера (режим tunnel/VXLAN; сервисному аккаунту кластера нужна роль `k8s.tunnelClusters.agent`); Cilium заменяет kube-proxy, Hubble встроен. Требования к кластеру одним списком:

- **версия Cilium ≥ 1.13** (поле `serverNames` появилось в 1.13; в 1.12 его нет). Документация Yandex версию не называет (в примере вывода — образы 1.12.9), поэтому это блокирующая проверка: `kubectl -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.containers[0].image}'` и `kubectl explain ciliumnetworkpolicy.spec.egress.toPorts.serverNames`. Если поля нет, `kubectl apply --dry-run=server` отклонит `aegis-intake-egress` (fail-closed), и кластер не годится;
- `cilium-dbg status`: `Proxy Status: OK`; Envoy — встроенный (embedded) режим достаточен;
- домен кластера `cluster.local`; NodeLocal DNS **не устанавливать** (с Cilium он ставится через `CiliumLocalRedirectPolicy`; если он всё же нужен, в DNS-правило обеих CNP добавляется второй селектор — поды `kube-system/k8s-app: node-local-dns`);
- не менее 3 узлов; Hubble включён; порт API-сервера 443.

Default-deny (`aegis-system-default-deny`) закрывает ingress и egress всего namespace `aegis-system`. Весь egress intake описан одной `CiliumNetworkPolicy` `aegis-intake-egress`; ни одного egress-правила в стандартной NetworkPolicy нет намеренно: L4-разрешение kube-dns:53 из другой политики сложилось бы (union) с L7-правилом DNS и сняло бы фильтр имён.

| Куда | Порт | Механизм (столбец SNI — у правил toFQDNs) | Кто в коде ходит |
|---|---|---|---|
| kube-dns | 53 (UDP/TCP) | `toEndpoints` + L7 `rules.dns` | все |
| OpenBao (`app.kubernetes.io/name: openbao`, `component: server`, namespace из `vault.address` агента) | 8200 | `toEndpoints` | init-контейнер Vault Agent (политика действует на весь под) |
| Alertmanager | 9093 | `toEndpoints` | `internal/intake/httpget` |
| Prometheus | 9090 | `toEndpoints` | `internal/intake/httpget` |
| API-сервер Kubernetes | 443 (self-hosted часто 6443) | `toEntities: kube-apiserver` | `internal/intake/httpget` (список подов, ConfigMap kill switch) |
| `openrouter.ai` | 443 | `toFQDNs.matchName` + `serverNames: [openrouter.ai]` | `internal/openrouter` (роутер в процессе intake) |
| `storage.yandexcloud.net` | 443 | `toFQDNs.matchName` + `serverNames: [storage.yandexcloud.net]` | `internal/killswitch/s3` (внешний канал kill switch и WORM-выгрузка аудита, `internal/audit/worm`) |

- **DNS-allowlist.** Intake может спросить у kube-dns только `openrouter.ai`, `storage.yandexcloud.net` и `*.*.svc.cluster.local`; остальное получает `REFUSED` (защита от DNS-туннеля и от резолва чужих имён). Домен кластера должен быть `cluster.local`; NodeLocal DNS не ставится (трафик пошёл бы на адрес NodeLocal, а не на kube-dns). Тест запрещает шаблоны `*` и `**.`.
- **Прокси не используется.** `HTTPS_PROXY`/`NO_PROXY` не задаются: `ProxyFromEnvironment` в клиенте OpenRouter без переменной даёт прямое соединение, остальные клиенты с `Proxy: nil`.
- **S3: `path_style: true` обязателен.** Разрешено одно имя `storage.yandexcloud.net`; virtual-hosted адресация (`<bucket>.storage.yandexcloud.net`) будет заблокирована (fail-closed; по SNI — тоже: `bucket.storage.yandexcloud.net` не равно `serverNames`).
- **SNI (`serverNames`).** `toFQDNs` действует по IP из DNS, а `openrouter.ai` стоит за Cloudflare: тот же IP обслуживает другие сайты. Поэтому в правилах 6 и 7 задан `serverNames` с тем же именем: Cilium читает SNI из ClientHello без терминации TLS (L7-прокси Envoy) и пропускает TLS только с SNI `openrouter.ai` или `storage.yandexcloud.net` на IP из DNS. TLS без SNI, не-TLS на 443 и ECH с внешним SNI, не равным имени, отклоняются: TCP-соединение с прокси устанавливается всегда, отказ — сброс после ClientHello. SNI не аутентифицирован: это защита от ошибок и простой утечки, а не от RCE (domain fronting, собственный ключ). Go-клиенты шлют SNI по host URL (`internal/openrouter`: `openrouter.ai`; `internal/killswitch/s3` при `path_style: true`: `storage.yandexcloud.net`), `EncryptedClientHelloConfigList` не задан. DNS-прокси живёт в cilium-agent: при его перезапуске DNS intake на узле кратковременно не проходит (ловят `aegis_intake_killswitch_channel_ok`, `aegis_intake_audit_anchor_errors_total`).
- **Замена canary-сканирования прокси.** Egress-прокси с поиском маркеров в трафике не используется (MITM-терминация TLS не вводится): тело запроса к LLM проверяет роутер перед отправкой, см. «Canary-маркеры» ниже.
- **Подстраховка.** Go-резолвер после `REFUSED` идёт по search-списку; в Deployment intake задайте `dnsConfig.options: [{name: ndots, value: "1"}]` и используйте полные имена.
- **Порты — порты пода** (после DNAT), не Service. Порт API-сервера у Yandex 443, у self-hosted 6443; правится в `cilium-egress.yaml` по маркеру `# kube-api-port`.

Проверено на стенде [`deploy/intake/dev/run-netpol.sh`](../../deploy/intake/dev/run-netpol.sh) (Cilium 1.20.4, встроенный Envoy), 11.11.2026: 54 PASS, 0 провалов без интернета; SNI-проверки (`openrouter.ai` на IP OpenRouter проходит; чужой SNI на том же IP, TLS без SNI и `openrouter.ai` на IP S3 отклонены на TLS-этапе: curl 35, `tcp>0`, `tls=0`; не-TLS на :443 — curl 56 при установленном TCP) — в этом прогоне. Критерий отказа — код curl и этап соединения вместе (28 — неопределённо): DNS-ошибка, connect refused и L3-дроп (6/7/28) отказом на TLS-этапе не считаются; прогон после этого изменения проверки — 11.11.2026, 54 PASS, 0 провалов. Режим `internet`: 0 провалов, 2 SKIP (из узла minikube нет выхода в интернет — реальный openrouter.ai не проверен). Ingress в OpenBao — стенд `deploy/vault/dev/run-ha.sh cilium`: 61 PASS, 0 провалов, 0 SKIP.

### Canary-маркеры: проверка исходящих запросов к LLM *(data-classes.md §5.2)*

Замена сканирования трафика на egress-прокси: `llmrouter.Route` сравнивает итоговое тело запроса (те же байты, что уходят в POST) с маркерами из файла, после `AssertRequestSafe` и до резерва бюджета. Совпадение без учёта регистра ASCII — запрос не отправляется (`not_sent/egress_canary`, L1), роутер останавливается (`router_halted/egress_canary`) до `Resume`, растёт `aegis_intake_router_canary_blocked_total`, горит `IntakeEgressCanaryDetected`. Разбор — [degraded-mode.md](degraded-mode.md).

В конфигурации роутера: `"canary": {"markers_file": "/etc/aegis/canary/markers.txt"}`. Файл — ConfigMap `aegis-canary-markers`, смонтированный read-only; по маркеру в строке, `#` и пустые строки пропускаются; маркер — 12–128 символов из `[A-Za-z0-9@._+-]` (их pyjson не экранирует), не более 256 маркеров, файл до 64 KiB, дубли без учёта регистра и пустой файл — ошибка старта. Без блока `canary` проверка выключена: в журнале `egress_canary_disabled`, метрика `aegis_intake_router_canary_markers 0` (в проде алерт `IntakeEgressCanaryDisabled`; допустимо только там, где маркеры не подбрасываются).

Включение двухфазное ([migrations.md](migrations.md), «Порядок обновления» п. 9, «Откат»): сначала бинарь без блока `canary`, затем фиксация rollback floor и `aegis-audit` с `chain_format 4` везде, только после этого `canary.markers_file`. После первой записи `egress_canary` откат бинаря ниже floor невозможен; canary снимают удалением блока `canary`, не откатом образа. Старый `aegis-audit` (< 4) не проверит цепочку и с `-integrity-only`.

Границы: проверка слабее прокси там, где важна независимость от процесса (компрометация процесса intake, путь мимо `Route`), — та же зона доверия; сильнее прокси тем, что нет MITM. Усиление: `toFQDNs` + SNI (выше), потоки Hubble `intake → world:443` с алертом на объём относительно `sent`-записей, сверка расхода ключа OpenRouter.

## Проверка перед shadow

1. `aegis-intake collect -config FILE -namespace NS -service SVC -print-input` по каждому сервису реестра: все источники `ok`, форма входа читается глазами, нет исключённых фрагментов (`excluded`), `not_sent` пусто.
2. `aegis-intake replay -config FILE -in snapshot.json -prepare-only` — красные команды RT-01/02/04 без живых источников.
3. ~~Подтверждение п. 1–9 раздела «Допущения» владельцами окружения~~ — подтверждено 08.11.2026; остаётся убедиться по выводу `collect` (п. 1), что фактические имена метрик и меток совпадают с конфигурацией.
4. `aegis-audit verify` после первых записей: блок `intake` читается новыми версиями; старые `aegis-audit` записи с этим блоком не прочтут — обновить все копии.
5. В боевом кластере версия Cilium ≥ 1.13 (см. «Создание кластера»), политики из `deploy/intake/` и `deploy/vault/network/` применены; из пода intake проверены разрешённые и запрещённые направления, `cilium-dbg status` показывает рабочий прокси (`Proxy Status: OK`), SNI-проверка по процедуре:

   ```
   # из пода intake (или ephemeral debug-контейнера в нём: та же политика)
   getent hosts openrouter.ai            # IP_OR; DNS-запрос обязателен: без него toFQDNs не пустит IP (дроп, curl 28 — ложный «отказ»)
   curl -sk -o /dev/null --connect-timeout 3 --max-time 6 \
     -w 'rc=%{exitcode} tcp=%{time_connect} tls=%{time_appconnect}\n' \
     --resolve evil.example:443:<IP_OR> https://evil.example/
   # ожидается: rc=35 (или 56), tcp>0, tls=0 — сброс после ClientHello. rc=6/7/28 или tcp=0 — проверка ничего не доказала.
   # контроль: то же с openrouter.ai (--resolve openrouter.ai:443:<IP_OR> https://openrouter.ai/) — tls>0.
   ```
6. Канарейка: маркеры посажены в staging, `canary.markers_file` задан, метрика `aegis_intake_router_canary_markers` > 0; rollback floor зафиксирован, `aegis-audit version` везде показывает `chain_format 4`.
7. Policy bundle: `required: true`, в журнале `policy_bundle_verified`, негативная проверка дала код 2 — [policy-bundle-stand.md](policy-bundle-stand.md).
