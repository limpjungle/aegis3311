# Runbook-каталог

> Основа — [plan.md](../01-planning/plan.md) Этапы 0a (п. 12) и 3a (п. 2, 4); [architecture.md](../00-overview/architecture.md) §5, шаг 5. Правила жизненного цикла и стартовый каталог ведутся в этом файле, сами runbook'и — в Git-каталоге.
>
> Статус: **проект на утверждение**. Целевой поток — stateless-сервисы в Kubernetes и PostgreSQL/PgBouncer. Числа с пометкой *(предложение)* калибруются по данным shadow-фазы.

## 1. Что такое runbook в Aegis

Runbook связывает **симптом** с **диагностикой** и **действиями каталога**. Сам runbook ничего не исполняет: он задаёт, какие read-only проверки выполнить и какое действие каталога предложить при каком результате. Исполнение идёт через PEP по уровню автономности ([levels.md](../03-autonomy/levels.md)), с проверкой lease и постусловий ([action-catalog.md](../03-autonomy/action-catalog.md)).

Runbook'и — основной контекст для LLM (RAG, индексируются в Qdrant) и основа деградационного режима: без связи с Control Plane агент исполняет только предодобренные runbook'и с детерминированной логикой.

## 2. Формат записи

```yaml
id: RB-001
title: Насыщение пула PgBouncer
version: 1.2.0
status: approved            # draft | approved | preapproved | stale | deprecated
owner: team-db              # отвечает за содержание
environments: [staging, prod-cloud]
ttl: 90d                    # (предложение)
last_validated: 2026-11-05
validated_by: [incident:INC-2041, chaos:CH-W04]
trigger:
  alerts: [PgBouncerClientsWaiting, PgBouncerMaxWaitHigh]
  incident_class: db-connection-saturation
diagnosis:                  # только read-only, через каталог диагностических запросов
  - id: pools
    query: pgbouncer.show_pools
  - id: sessions
    query: postgres.sessions_by_state
decision:                   # детерминированная таблица; LLM выбирает ветку, но не придумывает действия
  - when: "sessions.idle_in_tx_over_60s_ratio > 0.2"
    propose: l1_card         # утечка в клиенте: карточка + задача на исправление
  - when: "db.query_p95_ratio_to_baseline >= 3"
    propose: l1_card         # медленные запросы в СУБД: пул не увеличивать (предусловие resize_pool тоже это запрещает)
  - when: "pools.cl_waiting > 0 and pools.maxwait_s > 2 and headroom_ok"
    action: pgbouncer.resize_pool
  - when: "not headroom_ok"
    propose: postgres.set_restart_param   # R3, только L1
escalation: on-call команды владельца, если ни одна ветка не подошла
stats:                      # заполняет платформа
  applied: 14
  succeeded: 13
  rolled_back: 1
  caused_incidents: 0
```

Обязательные поля: `id`, `version`, `status`, `owner`, `environments`, `ttl`, `last_validated`, `trigger`, `diagnosis`, `decision`, `escalation`. Каждая ветка `decision` ссылается на существующее действие каталога или на L1-карточку: свободные команды в runbook'е запрещены.

## 3. Жизненный цикл

```
draft ──ревью SRE──▶ approved ──критерии §3.2──▶ preapproved
  ▲                     │  ▲                        │
  │                     │  └──── провалы §3.3 ──────┘
  │                     ▼
  │                   stale ──ревалидация──▶ approved
  │                     │
  └── переработка ──────┴──▶ deprecated
```

### 3.1 Статусы

| Статус | Что разрешено |
|---|---|
| `draft` | Только контекст для анализа в shadow; действия не предлагаются |
| `approved` | Действие предлагается по уровню автономности; нетиповые параметры проходят песочницу |
| `preapproved` | Исполнение без песочницы; единственный статус, разрешённый в деградационном режиме (для R1, для R2 — если разрешает политика) |
| `stale` | Истёк TTL или изменилась зависимость (§3.4). Используется только как контекст, действия — не выше L1 |
| `deprecated` | Исключён из индекса RAG; хранится в Git для истории |

### 3.2 Критерии `preapproved` *(предложение)*

- Не менее 10 успешных применений за последние 90 дней, из них не менее 3 в prod.
- 0 инцидентов, вызванных применением.
- Не более одного отката по провалу постусловия за 90 дней.
- Детерминированная таблица `decision` покрывает все наблюдавшиеся ветки без участия LLM.
- Подтверждение SRE-лида; решение пишется в аудит.

### 3.3 Понижение

- Два подряд провала постусловия или одна отмена человеком с пометкой «вредно» → `preapproved` переходит в `approved`.
- Инцидент, вызванный применением → `approved`, обязательный разбор и пересмотр runbook'а.
- Runbook'и с низкой долей успеха понижаются в выдаче RAG (§5 архитектуры, «Закрытие цикла»).

### 3.4 TTL и ревалидация

- TTL по умолчанию — 90 дней *(предложение)*. Для runbook'ов, привязанных к версии ПО (PostgreSQL, PgBouncer, контроллер), — до следующего обновления этой версии.
- Runbook переходит в `stale` автоматически: по истечении TTL; при major-изменении любого действия каталога, на которое он ссылается; при смене версии компонента из `environments`.
- Ревалидация — одно из трёх: успешное применение в реальном инциденте с подтверждением SRE; прогон соответствующего chaos-сценария ([chaos.md](../05-testing/chaos.md)) на staging; replay исторического инцидента в песочнице.

### 3.5 Связь с постмортемами

Постмортем попадает в базу знаний только после утверждения SRE. Если постмортем выявил новый паттерн, создаётся `draft` runbook'а. Если runbook применялся и не помог, постмортем ссылается на его версию, и runbook пересматривается.

## 4. Стартовый каталог для целевого потока (Этап 0a, п. 12)

Классы первого shadow (утверждено 05.11.2026): **RB-001, RB-003, RB-006** — они диагностируются по метрикам, событиям деплоев и агрегатам СУБД, без логов приложений с ПДн. Остальные runbook'и каталога работают в shadow как контекст и источник статистики, но в G0 MVP не оцениваются.

| ID | Симптом / класс инцидента | Диагностика (read-only) | Действия каталога | Макс. путь |
|---|---|---|---|---|
| RB-001 | Насыщение пула PgBouncer: клиенты ждут соединений | `SHOW POOLS`, `SHOW STATS`; сессии PostgreSQL по состояниям | `pgbouncer.resize_pool`; при утечке — L1-карточка + PR | R2 |
| RB-002 | Исчерпание `max_connections` PostgreSQL | Соединения по пользователям и приложениям; сумма пулов | L1-карточка: `postgres.set_restart_param` или снижение пулов | R3 (L1) |
| RB-003 | Деградация после релиза: рост error rate или latency на canary или в bake-периоде | Вердикт AnalysisRun; сравнение со свежим baseline; корреляция с деплоем | `rollout.abort_and_rollback` | R1 |
| RB-004 | CrashLoopBackOff | События пода, exit code, последние логи; был ли свежий релиз | После релиза → RB-003; иначе L1-карточка (рестарт не лечит crashloop) | R1 |
| RB-005 | OOMKilled / утечка памяти в stateless-сервисе | Рост RSS по времени, лимиты, частота OOM | `workload.restart` (временно) + L1-карточка на лимиты или исправление | R2 |
| RB-006 | Нехватка capacity: насыщение CPU или длины очереди при росте нагрузки | Метрики KEDA/HPA, достигнут ли `maxReplicas`, буфер | `workload.scale_out`; при достигнутом `maxReplicas` — L1-карточка | R1 |
| RB-007 | Избыточная capacity после пика | Загрузка за 30+ минут, PDB | `workload.scale_in` | R2 |

### 4.1 Пример: RB-001, диагностические запросы

У роли агента нет `pg_monitor`: эта роль видит тексты запросов всех сессий, а это restricted-данные ([data-classes.md](../02-security/data-classes.md), [threat-model.md](../02-security/threat-model.md) T-28). Вместо неё — функция `SECURITY DEFINER`, которая возвращает только агрегаты. Её владелец — служебная роль с `pg_read_all_stats`, а роль агента получает только `EXECUTE`:

```sql
-- postgres.sessions_by_state: только агрегаты, без текста запросов
CREATE FUNCTION aegis.sessions_by_state()
RETURNS TABLE (state text, sessions bigint, over_60s bigint)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
  SELECT a.state,
         count(*),
         count(*) FILTER (WHERE now() - a.state_change > interval '60 seconds')
  FROM pg_stat_activity a
  WHERE a.backend_type = 'client backend'
  GROUP BY a.state
$$;

REVOKE ALL ON FUNCTION aegis.sessions_by_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION aegis.sessions_by_state() TO aegis_agent;
```

```
-- pgbouncer.show_pools: admin-консоль PgBouncer под пользователем из stats_users
SHOW POOLS;   -- cl_active, cl_waiting, sv_active, sv_idle, maxwait
```

Нормализованные запросы из `pg_stat_statements`, если источник включён, проходят нормализатор, который вырезает SQL-комментарии. Значения `application_name` сопоставляются со списком известных сервисов (T-03).

Интерпретация:
- `cl_waiting > 0` и `maxwait` растёт, а доля `idle in transaction` старше 60 секунд невелика — пул мал для нагрузки: `pgbouncer.resize_pool` в границах.
- Много `idle in transaction` — утечка или долгие транзакции в клиенте. Увеличение пула только отложит проблему: L1-карточка, ссылка на сервис-источник, задача на исправление.
- Почти все сессии `active`, а p95 длительности запросов выросла в 3 раза и больше — медленные запросы в СУБД. Увеличение пула добавит нагрузки и ухудшит ситуацию: L1-карточка, разбор запросов и нагрузки на СУБД. Этот случай проверяется раньше, чем «пул мал».
- Запаса до `max_connections` нет — переход к RB-002.

Порядок проверок важен: утечка → медленные запросы → нет запаса → пул мал. В eval на `dev` 05.11.2026 модель (GLM 5.3 Flash, fp4) во всех трёх кейсах с медленными запросами предложила увеличить пул, и параметры при этом были в границах каталога. Поэтому запрет закреплён и в промпте, и детерминированным предусловием `pgbouncer.resize_pool` в [action-catalog.md](../03-autonomy/action-catalog.md).

## 5. Открытые вопросы

1. Порог `preapproved` (10 применений за 90 дней) реалистичен только для частых классов. Для редких — допускать ли replay и chaos вместо части реальных применений.
2. Кто владелец runbook'ов RB-001 и RB-002: команда DBA или команда сервиса.
3. Нужен ли `pg_terminate_backend` для зависших сессий в каталоге ([action-catalog.md](../03-autonomy/action-catalog.md) §3).
