# Каталог действий

> Основа — [architecture.md](../00-overview/architecture.md) §4.1, §4.3. Потолки уровней — в [autonomy-matrix.md](autonomy-matrix.md) и здесь не дублируются. Детализация записей ведётся в этом файле, а после старта разработки — в Git-каталоге, который загружает PEP.
>
> Машиночитаемые записи — в [`catalog/actions/`](../../catalog/actions/): они источник истины для PEP (`internal/pep`). Формулы шага в YAML не интерпретируются — запись ссылается на зарегистрированное Go-правило (`rule`), текст `expr` нужен для ревью. Расхождения с этим документом, схемой ответа v2 и golden-набором ловят тесты (`go test ./...`).
>
> Статус: **проект на утверждение**. Целевой поток — stateless-сервисы в Kubernetes и PostgreSQL/PgBouncer. Числа с пометкой *(предложение)* калибруются по данным shadow-фазы.

## 4.1 Каталог действий

Каждое действие — запись каталога: имя, схема параметров с границами, предусловия, постусловия (проверка успеха), процедура отката, класс обратимости, допустимые цели, лимит частоты. LLM выбирает действие и его дискретные параметры (какой под, причина отката, какой параметр СУБД); величину изменения и параметры-идентификаторы вычисляет детерминированное правило шага каталога (формат ответа v2, решение 06.11.2026). PEP проверяет схему, политику, уровень и lease. Исполняет детерминированный код. Каталог хранится в Git и меняется через ревью.

## 4.3 Классы обратимости

- **R1 — полностью обратимо:** rollback деплоя, scale out. До L3.
- **R2 — обратимо с издержками:** рестарт, scale in, reload пула соединений. До L2, до L3 только по данным (§4.5).
- **R3 — необратимо или риск потери данных:** миграции схемы, удаление томов и OSD, рестарт СУБД, изменения Ceph/IPMI/BGP, меняющие топологию. Не выше L1.

## 1. Формат записи

| Поле | Обязательно | Смысл |
|---|---|---|
| `name`, `version` | да | Имя `домен.действие`, семантическая версия. Изменение схемы параметров — новая major-версия |
| `reversibility` | да | R1 / R2 / R3 |
| `targets` | да | Селектор допустимых целей: тип ресурса, метки, namespace'ы. Запрещённые цели задаёт политика, а не запись |
| `params` | да | JSON Schema с границами. Границы могут ссылаться на свойства цели (`target.spec.maxReplicas`). Это ограждение для PEP: даже вычисленное значение проверяется по границам |
| `step` | для действий с величиной | Детерминированное правило вычисления величины изменения. Величину выбирает код каталога, а не модель; модель выбирает только действие и дискретные параметры (`chosen_by: model`) |
| `preconditions` | да | Проверки перед исполнением; провал любой — отказ без исполнения |
| `postconditions` | да | Проверка успеха и окно наблюдения; провал → `rollback` (на L3 автоматически, на L2 — по окну отмены) |
| `rollback` | да | Ссылка на действие отката и правило вычисления его параметров из снимка «до» |
| `execution` | да | Канал исполнения: `gitops` (коммит в GitOps-репозиторий) или `api` (прямой вызов API с зарегистрированным исключением из drift detection) |
| `rate_limit` | да | Не более N на цель в час, cooldown между повторами |
| `blast_radius` | да | Ограничение охвата: доля реплик, число целей за один вызов |
| `lease` | да | Требуется ли lease с fencing token. Для всех изменяющих действий — да |
| `error_budget_exhausted` | да | `allowed` или `frozen` (§4.5: при исчерпанном бюджете разрешены только rollback и scale out) |
| `degraded_mode` | да | Разрешено ли в деградационном режиме (только предодобренные R1; R2 — если политика разрешает) |
| `snapshot` | да | Что сохраняется до исполнения для отката и аудита |

**Канал исполнения и GitOps.** Прямое изменение ресурса, которым управляет ArgoCD, вызывает дрейф, и с включённым self-heal ArgoCD вернёт его обратно. Поэтому:

- изменения, которые должны сохраниться, идут через `gitops`: агент коммитит в GitOps-репозиторий по своей identity, и ArgoCD синхронизирует. Это медленнее, но не порождает дрейфа;
- срочные и временные изменения идут через `api`, только по полям, которые заранее зарегистрированы в `ignoreDifferences`, или через нативные операции контроллера (abort/undo в Argo Rollouts). Каждое такое изменение помечается аннотацией `aegisops.io/decision-id`, по которой drift detection отличает его от ручного вмешательства.

**Масштабирование и HPA/KEDA.** Если репликами управляет HPA или KEDA, прямое изменение `replicas` будет перезаписано. Для таких целей scale out и scale in меняют границы autoscaler'а (`minReplicas` у HPA, `minReplicaCount` у `ScaledObject`), а не сам Deployment.

### 1.1 Права исполнителя

Каталог ограничивает, что агент *выбирает*. Права ниже ограничивают, что агент *может*, даже если он скомпрометирован ([threat-model.md](../02-security/threat-model.md) T-25, T-27, T-28).

**Kubernetes.** RBAC не ограничивает поля: право `patch deployments`, нужное для рестарта, позволяет заменить образ. Поэтому поверх RBAC работает ValidatingAdmissionPolicy (CEL) или Kyverno для ServiceAccount агента. Разрешено ровно:

| Ресурс | Разрешённое изменение | Действие каталога |
|---|---|---|
| `apps/Deployment` | Только аннотация `kubectl.kubernetes.io/restartedAt` в `spec.template.metadata.annotations` | `workload.restart` (scope `deployment`) |
| `core/Pod` | Только `delete` пода с меткой `aegisops.io/stateless: "true"` | `workload.restart` (scope `pod`) |
| `autoscaling/HorizontalPodAutoscaler` | Только `spec.minReplicas`, в границах каталога и не выше `spec.maxReplicas` | `workload.scale_out`, `workload.scale_in` |
| `keda.sh/ScaledObject` | Только `spec.minReplicaCount`, в тех же границах | `workload.scale_out`, `workload.scale_in` |
| `argoproj.io/Rollout` | Только abort | `rollout.abort_and_rollback` |

Всё остальное отклоняется admission-политикой. Нет прав `get/list secrets`, `pods/exec`, `create`; namespace'ы — только с меткой `aegisops.io/managed: "true"`. Образ агента — distroless, read-only root FS. Отдельный node pool в MVP не нужен.

**GitOps-репозиторий.** Агент пишет только в выделенный путь `aegis-managed/<service>/` — это ограничено правилами репозитория на стороне сервера. CI с conftest проверяет каждый коммит агента: только разрешённые ключи и значения в границах каталога. Application в Argo CD для этого пути входит в AppProject с allowlist типов ресурсов. Коммиты агента подписаны и проверяются.

**PgBouncer и PostgreSQL.** Агент подключается к admin-консоли PgBouncer как пользователь из `stats_users` (только `SHOW`), а не `admin_users`: без `RELOAD`, `PAUSE`, `SHUTDOWN`. Reload после изменения конфигурации выполняет оператор конфигурации. В PostgreSQL у роли агента нет `pg_monitor`: доступ только к функциям-агрегатам ([runbooks.md](../04-operations/runbooks.md) §4.1). Креды динамические, из Vault database secrets engine.

## 2. Записи каталога

### 2.1 `rollout.abort_and_rollback` — откат canary (R1)

```yaml
name: rollout.abort_and_rollback
version: 1.0.0
reversibility: R1
targets:
  kind: argoproj.io/Rollout
  labels: {aegisops.io/managed: "true"}
params:
  reason: {type: string, enum: [canary_degradation, bake_degradation, insufficient_data_policy], chosen_by: model}
  analysis_run: {type: string, chosen_by: catalog}   # активный AnalysisRun цели, подставляется кодом
preconditions:
  - rollout в состоянии Progressing или в bake-периоде
  - предыдущая стабильная ревизия существует и сохранена
  - вердикт статистического гейта: значимая деградация (или политика сервиса для «недостаточно данных»)
postconditions:
  window: 10m                              # (предложение)
  checks:
    - 100% трафика на стабильной ревизии
    - error rate и p99 latency вернулись в пределы baseline (тот же статистический тест)
rollback:
  action: manual                           # повторное продвижение — новый релиз, не откат отката
execution: api                             # нативный abort/undo Argo Rollouts
rate_limit: {per_target_per_hour: 3, cooldown: 0m}
blast_radius: {targets_per_call: 1}
lease: required
error_budget_exhausted: allowed
degraded_mode: allowed                     # только если runbook предодобрен
snapshot: [rollout.status, revision_history, analysis_run]
```

Без анализа текущей ревизии (`computed.analysis_run` пуст) PEP понижает откат до L1 (cap `analysis_missing`, `policy/aegis/pep/guards.rego`): вердикта нет, откат решает человек. Вердикт анализа `error` (сбой провайдера метрик) отдельный и не `inconclusive`; в каталоге ничего не меняется (golden-set.md §16).

### 2.2 `workload.scale_out` — увеличение реплик stateless (R1)

```yaml
name: workload.scale_out
version: 1.0.0
reversibility: R1
targets:
  kind: [apps/Deployment, autoscaling/HorizontalPodAutoscaler, keda.sh/ScaledObject]
  labels: {aegisops.io/stateless: "true"}
params:
  new_min_replicas:
    type: int
    minimum: target.current_min + 1
    maximum: min(target.max_replicas, ceil(target.current_min * 2))   # не более чем вдвое за шаг (предложение)
    chosen_by: catalog
step: min(maximum, max(target.current_min + 1, ceil(target.current_min * 1.5)))   # +50%, минимум +1 (предложение)
preconditions:
  - цель stateless (метка + отсутствие PVC с ReadWriteOnce)
  - в кластере есть capacity или буфер overprovisioning; иначе предупреждение о времени появления ноды
  - нет активного scale_in по той же цели в cooldown-окне
postconditions:
  window: 5m
  checks:
    - готовых реплик не меньше new_min_replicas
    - насыщение (CPU или длина очереди), вызвавшее действие, снижается
rollback:
  action: workload.scale_in
  params: {new_min_replicas: snapshot.min_replicas}
execution: api                             # поле minReplicas в ignoreDifferences; постоянное изменение — отдельным PR
rate_limit: {per_target_per_hour: 4, cooldown: 10m}
blast_radius: {targets_per_call: 1}
lease: required
error_budget_exhausted: allowed
degraded_mode: allowed
snapshot: [min_replicas, max_replicas, ready_replicas]
```

### 2.3 `workload.scale_in` — уменьшение реплик (R2)

```yaml
name: workload.scale_in
version: 1.0.0
reversibility: R2
targets: {same_as: workload.scale_out}
params:
  new_min_replicas:
    type: int
    minimum: max(target.declared_min_replicas, ceil(target.current_min * 0.5))   # не ниже значения из Git (предложение)
    maximum: target.current_min - 1
    chosen_by: catalog
step: max(minimum, min(target.current_min - 1, floor(target.current_min * 0.75)))   # −25%, минимум −1 (предложение)
preconditions:
  - загрузка за последние 30 минут ниже порога, заданного политикой сервиса
  - PodDisruptionBudget не будет нарушен
  - нет scale_out по той же цели в cooldown-окне (защита от flapping)
postconditions:
  window: 15m
  checks:
    - SLO burn rate не вырос
    - насыщение остаётся ниже порога
rollback:
  action: workload.scale_out
  params: {new_min_replicas: snapshot.min_replicas}
execution: api
rate_limit: {per_target_per_hour: 2, cooldown: 30m}
blast_radius: {targets_per_call: 1}
lease: required
error_budget_exhausted: frozen
degraded_mode: forbidden
snapshot: [min_replicas, ready_replicas, load_30m]
```

### 2.4 `workload.restart` — рестарт пода или Deployment stateless (R2)

```yaml
name: workload.restart
version: 1.0.0
reversibility: R2
targets:
  kind: [apps/Deployment, core/Pod]
  labels: {aegisops.io/stateless: "true"}
params:
  scope: {type: string, enum: [pod, deployment]}
  pod_name: {type: string, required_if: "scope == pod"}
preconditions:
  - причина не в образе: под не в CrashLoopBackOff после свежего релиза (иначе — rollback, а не рестарт)
  - "scope=deployment: готовых реплик ≥ 2 и PDB допускает недоступность"
  - "scope=pod: под не единственная готовая реплика"
postconditions:
  window: 10m
  checks:
    - все реплики Ready, число рестартов не растёт
    - симптом, вызвавший действие (утечка памяти, зависание), не повторился в окне
rollback:
  action: none                             # рестарт нельзя «откатить»; издержки — прерванные запросы
execution: api                             # rolling restart; аннотация restartedAt в ignoreDifferences
rate_limit: {per_target_per_hour: 2, cooldown: 30m}
blast_radius: {max_unavailable: 25%}       # (предложение)
lease: required
error_budget_exhausted: frozen
degraded_mode: policy                      # R2: только если разрешено политикой
snapshot: [ready_replicas, restart_counts, memory_usage]
```

### 2.5 `pgbouncer.resize_pool` — размер пула PgBouncer через reload (R2)

```yaml
name: pgbouncer.resize_pool
version: 1.0.0
reversibility: R2
targets:
  kind: pgbouncer
  labels: {aegisops.io/managed: "true"}
params:
  database: {type: string, chosen_by: catalog}       # база цели, подставляется кодом
  new_pool_size:
    type: int
    minimum: 5
    maximum: >-
      min(
        ceil(snapshot.pool_size * 1.5),                       # шаг не более +50% (предложение)
        postgres.max_connections
          - postgres.superuser_reserved_connections
          - sum(other_pools.pool_size)
          - headroom                                          # запас 10% max_connections (предложение)
      )
    chosen_by: catalog
step: min(maximum, max(snapshot.pool_size + 1, ceil(snapshot.pool_size * 1.25)))   # +25%, минимум +1 (предложение)
preconditions:
  - "диагноз подтверждён: cl_waiting > 0 и maxwait выше порога в SHOW POOLS"
  - "причина не в утечке: доля сессий idle in transaction дольше 60 с ниже порога (иначе — L1-карточка и PR с исправлением)"
  - "СУБД не деградирует: p95 длительности запросов к БД за последние 5 минут не выше 3 × baseline (baseline — медиана p95 за предыдущие 24 часа без окон инцидентов; множитель 3 — предложение). Иначе — отказ: больше соединений нагрузят и без того медленную СУБД; L1-карточка. Если метрика недоступна — предусловие не выполнено (fail-closed)"
  - сумма пулов после изменения не превышает max_connections с запасом
postconditions:
  window: 10m
  checks:
    - cl_waiting и maxwait вернулись ниже порога
    - число активных соединений к PostgreSQL ниже max_connections − headroom
    - error rate клиентов по ошибкам подключения не вырос
rollback:
  action: pgbouncer.resize_pool
  params: {new_pool_size: snapshot.pool_size}
execution: gitops                          # конфиг PgBouncer в Git; reload выполняет оператор конфигурации
rate_limit: {per_target_per_hour: 2, cooldown: 15m}
blast_radius: {targets_per_call: 1}
lease: required                            # lease на экземпляр PgBouncer и на кластер PostgreSQL
error_budget_exhausted: frozen
degraded_mode: forbidden
snapshot: [pool_size, show_pools, pg_connections_by_state, pg_query_duration_p95_vs_baseline]
```

### 2.6 `postgres.set_restart_param` — параметры СУБД с рестартом (R3, не выше L1)

Действие есть в каталоге, чтобы L1-карточка исполнялась детерминированно и проверялась PEP после нажатия «Применить» человеком. Автономное исполнение запрещено матрицей на любом уровне выше L1.

```yaml
name: postgres.set_restart_param
version: 1.0.0
reversibility: R3
targets:
  kind: postgresql-cluster
params:
  parameter: {type: string, enum: [max_connections, shared_buffers], chosen_by: model}
  value:                                   # chosen_by: catalog
    max_connections: {type: int, maximum: "ограничение по памяти: work_mem × value ≤ доля RAM (предложение)"}
    shared_buffers: {type: size, maximum: "40% RAM"}           # граница из §2.2 архитектуры
step:
  max_connections: min(2 * current, ceil(current * 1.25))   # +25% (предложение); итог подтверждает человек (L1)
  shared_buffers: "нет правила: требует данных о RAM; только рекомендация"
preconditions:
  - подтверждение человека с ролью, разрешённой политикой (L1)
  - окно изменений открыто, change freeze не действует (ITSM)
  - реплика в синхронном состоянии; свежий бэкап подтверждён (проверку восстановления ведёт отдельный контур)
  - "для max_connections: значение на репликах не меньше, чем на primary"
postconditions:
  window: 30m
  checks:
    - кластер доступен, репликация восстановлена
    - параметр применён (pg_settings, pending_restart = false)
rollback:
  action: postgres.set_restart_param
  params: {value: snapshot.value}           # тоже R3 и тоже L1: повторный рестарт
execution: gitops                           # манифест оператора PostgreSQL; рестарт выполняет оператор
rate_limit: {per_target_per_hour: 1, cooldown: 24h}
blast_radius: {targets_per_call: 1}
lease: required
error_budget_exhausted: frozen
degraded_mode: forbidden
snapshot: [pg_settings, replication_state, last_backup_id]
```

## 3. Чего нет в каталоге

- Удаление данных, томов, бэкапов, PVC — запрещено на любом уровне, записи в каталоге не будет.
- `pg_terminate_backend` для сессий idle in transaction — кандидат для обсуждения. Действие обрывает транзакции клиентов и в матрицу не внесено. До решения — только L1-рекомендация в тексте карточки.
- Изменения схемы и миграции — только PR (L1) по паттерну expand/contract, не через каталог.

## 4. Процесс изменения каталога

1. Новое действие или изменение границ — PR в Git-каталог с тестами политик (OPA) и тестами постусловий на staging.
2. Ревью: владелец домена (например, DBA для `postgres.*`) и SRE-лид, по принципу четырёх глаз. Агент не может предлагать изменения каталога в обход этого процесса.
3. Новое действие всегда стартует с L0 для всех сервисов, независимо от потолка в матрице.
4. Изменение major-версии сбрасывает статистику повышения уровня (§4.5) для этого действия.
5. Любое изменение каталога запускает регрессионный прогон eval-контура (§6.3).
