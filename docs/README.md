# Документация AegisOps AI

## Структура репозитория документации

```
docs/
├── 00-overview/
│   ├── vision.md              # Видение и цели платформы
│   ├── architecture.md        # Архитектура (основной документ)
│   └── glossary.md            # Глоссарий (база знаний)
├── 01-planning/
│   ├── roadmap.md             # Дорожная карта с фазами и gates
│   ├── plan.md                # План реализации (полный)
│   └── plan-mvp.md            # План до MVP (MVP-A, MVP-B)
├── 02-security/
│   ├── threat-model.md        # Модель угроз
│   ├── security-principles.md # Принципы безопасности
│   ├── data-classes.md        # Классы данных и политика LLM
│   └── audit.md               # Аудит, decision record, WORM
├── 03-autonomy/
│   ├── action-catalog.md      # Каталог действий (схемы, границы, откаты)
│   ├── autonomy-matrix.md     # Матрица «действие × среда × обратимость»
│   └── levels.md              # Уровни L0–L3, повышение/понижение
├── 04-operations/
│   ├── runbooks.md            # Каталог runbook'ов, TTL, ревалидация
│   ├── incident-flow.md       # Жизненный цикл инцидента
│   ├── kill-switch-drill.md   # Runbook учения kill switch (G0)
│   ├── degraded-mode.md       # Деградационный режим, reconciliation
│   └── migrations.md          # Заметки о миграции (kill switch, bootstrap, формат цепочки)
├── 05-testing/
│   ├── eval.md                # Eval-контур, golden-набор
│   ├── golden-set.md          # Синтетический golden-набор (код — eval/golden-synthetic/)
│   ├── canary.md              # Статистический canary, методы анализа
│   └── chaos.md               # Хаос-тесты, сценарии
├── 06-metrics/
│   ├── metrics.md             # Метрики ценности, безопасности, платформы
│   └── baseline.md            # Baseline из shadow-фазы
└── 07-governance/
    ├── raci.md                # Матрица ответственности
    ├── compliance.md          # GDPR, SOC 2, ISO 27001
    └── gates.md               # Описание всех decision gates
```

## Ключевые документы

### 1. Архитектура ([architecture.md](00-overview/architecture.md))
Источник истины: принципы проектирования, компоненты (Control Plane, Cluster Agent, PEP), модель угроз, каталог действий, матрица автономности, жизненный цикл, аудит, метрики, дорожная карта.

### 2. План реализации ([plan.md](01-planning/plan.md))
Этапы −1…4, gates, зависимости, принципы безопасности, реестр рисков, критерии готовности к prod. Оценок трудоёмкости и распределения по команде в плане пока нет — черновые оценки только для MVP, в plan-mvp.md.

### 3. План до MVP ([plan-mvp.md](01-planning/plan-mvp.md))
Сокращённый путь: MVP-A (Shadow + L1) → MVP-B (Control Plane + пилот L2). Явно исключено: L3, canary-rollback, аудит кода, sandbox, degraded mode, Bare Metal, fine-tuning.

### 4. Модель угроз ([threat-model.md](02-security/threat-model.md))
Угрозы: prompt injection, избыточные права, самоизменение, утечка данных, supply chain, компрометация агента, eBPF-риски, отравление знаний, атака на стоимость. Меры для каждой.

### 5. Каталог действий ([action-catalog.md](03-autonomy/action-catalog.md))
Формат записи: имя, схема параметров, предусловия, постусловия, откат, класс R1–R3, допустимые цели, лимит частоты. Примеры: rollback canary, scale out/in, рестарт пода, reload PgBouncer, параметры СУБД.

### 6. Матрица автономности ([autonomy-matrix.md](03-autonomy/autonomy-matrix.md))
Потолки уровней по средам. Правило: prod ≤ staging. Bare Metal: железо/хранилище/сеть ≤ L2, необратимые ≤ L1.

### 7. Метрики ([metrics.md](06-metrics/metrics.md))
Baseline → цели. Парность: ценность всегда с safety-метриками. Независимый мониторинг, dead-man's switch.

---

## Быстрый старт для нового участника

1. **Прочитать**: [architecture.md](00-overview/architecture.md) → [plan-mvp.md](01-planning/plan-mvp.md) → [threat-model.md](02-security/threat-model.md), термины — в [glossary.md](00-overview/glossary.md)
2. **Понять**: уровни L0–L3, классы R1–R3, принцип «LLM предлагает — каталог исполняет — PEP проверяет»
3. **Найти свою зону**: Platform (Control Plane) / Agent-Security (PEP, leases) / Reliability (eval, canary) / Integrations (Cloud/Hybrid/Bare Metal)
4. **Проверить** по [gates.md](07-governance/gates.md): какие gates уже пройдены, какие критерии актуальны для текущего этапа

## Как поддерживать документы

- Источники — `00-overview/architecture.md` (архитектура) и `01-planning/plan.md` (план). Тематические файлы в `02-…07-` — выдержки из них: в шапке каждого указано, откуда взят текст. Правку сначала вносить в источник, затем синхронизировать выдержку.
- Файлы threat-model, data-classes, action-catalog, runbooks, chaos, baseline и raci содержат собственную детализацию: она ведётся в них, а основа взята из источников (указано в шапке). Их статус — «проект на утверждение»; значения с пометкой *(предложение)* нужно утвердить.
- `vision.md` из исходной структуры собран из обзора и принципов архитектуры.
