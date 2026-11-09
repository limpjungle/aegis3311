# Этап 0a: что осталось (на 09.11.2026)

> Сверка работ Этапа 0a ([plan.md](plan.md) §0a, [plan-mvp.md](plan-mvp.md), недели 3–6) и списка P1 «до старта shadow» ([threat-model.md](../02-security/threat-model.md) §7) с состоянием репозитория после выгрузки checkpoint'ов аудита в WORM (09.11.2026). Статусы, которые не видны из репозитория (настройки GitHub, договорённости), отмечены отдельно. Кодовые пункты из [ci-four-eyes-risks.md](../07-governance/ci-four-eyes-risks.md) указаны со ссылкой «риск N».

## Сделано

Модель угроз; каталог действий и матрица автономности; PEP dry-run; LLM-роутер с маскированием, исключением restricted-контекста и режимом `off`; read-only intake; синтетический golden-набор и ежедневная eval-проба (набор и промпт v5); kill switch: код, наблюдаемость (`aegis-killswitch check`, `/metrics` intake), версия формата цепочки аудита. Закрыты угрозы T-01…T-03, T-08, T-12, T-15. CI, правило четырёх глаз, подпись policy bundle и релизный пайплайн — в репозитории (механизмы; T-24 пока не закрыт, см. п. 3). Аудит: выгрузка checkpoint'ов в WORM (`S3Anchor`, object lock COMPLIANCE, чтение всех версий), сверка на старте, периодическая фиксация с метриками отставания (09.11.2026).

## Пункты этапа

| # | Пункт | Состояние | Важность |
|---|---|---|---|
| 1 | Калибровка ежедневной пробы v5 | Идёт с 08.11.2026, freeze ≈ 28–30.11.2026 | **Блокер shadow** |
| 2 | Аудит: подпись через KMS/HSM, checkpoint'ы в WORM (T-23, P1) | WORM в коде сделан; KMS-подписанта нет (ключ в файле); bucket не создан, на живом Yandex Object Storage не проверено | **Блокер shadow** |
| 3 | Четыре глаза на изменения политик (T-24, P1; RT-11) | Механизмы в репозитории ([ci-four-eyes.md](../07-governance/ci-four-eyes.md)); не включено | **Блокер shadow** |
| 4 | SPIFFE/SPIRE и Vault (plan.md §0a п. 2; T-35, P1; RT-17) | Нет; секреты — файлы через переменные окружения | **Блокер** по модели угроз, кандидат на пересмотр объёма |
| 5 | Базовый red-team RT-01…RT-08, RT-11, RT-17 | Тесты RT-01…RT-04, RT-07, RT-08 есть; формального прогона и отчёта нет | **Блокер shadow** |
| 6 | Egress только через роутер (T-17, P1) | NetworkPolicy описана в [intake-deploy.md](../04-operations/intake-deploy.md), не применена | Высокая |
| 7 | Kill switch: стенд и учение G0 | Код и [runbook учения](../04-operations/kill-switch-drill.md) готовы | Высокая (критерий выхода G0; стенд нужен до shadow) |
| 8 | Подпись артефактов: SBOM, cosign, SLSA (plan.md §0a п. 11) | `release.yml` готов (SBOM CycloneDX 1.5, провенанс SLSA, аттестация SBOM); не запускался; образов нет | Высокая |
| 9 | Runbook-каталог и индексация для LLM (plan.md §0a п. 12) | Таблица в [runbooks.md](../04-operations/runbooks.md); модель работает без RAG | Средняя (T-20 — P1, если появится RAG) |
| 10 | Gate G(−1): DPA с OpenRouter (ZDR), legal, DPIA, инвентаризация ПДн | Из репозитория не видно | **Блокер** (организационный) |
| 11 | Eval по реальным данным | Только синтетика | Средняя для 0a, высокая для G0 |
| 12 | Открытые вопросы golden-набора ([golden-set.md](../05-testing/golden-set.md) §16.7) | Записаны | Низкая |
| 13 | Роутер: подпись через KMS, четыре глаза для `resume` | Отложено решением 07.11.2026 | Низкая (после MVP) |

## Что осталось по категориям

### Люди и решения

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 1 | Набрать 20 точек калибровки v5, следить за ночными прогонами, заморозить набор | **Блокер shadow** | Время |
| 2 | Выбрать KMS для подписи цепочки аудита (Yandex KMS — только ECDSA/RSA, без Ed25519; Vault Transit; HSM) | **Блокер shadow** | — |
| 2 | Утвердить срок хранения checkpoint'ов в WORM (режим COMPLIANCE необратим до истечения срока) — Security и compliance | **Блокер shadow** | До создания bucket'а |
| 2 | Принять (или отклонить) отступление от T-23: отставание выгрузки не блокирует запись до G1 — Security | Высокая | — |
| 3 | Найти минимум двух ревьюеров помимо владельца | **Блокер shadow** | — |
| 3 | Прогнать RT-11 вручную на живом репозитории | **Блокер shadow** | Включение четырёх глаз |
| 4 | Решение Security: развернуть SPIRE/Vault или формально сузить объём для MVP-A | **Блокер** | — |
| 5 | Формальный прогон red-team и отчёт (RT-05/RT-06 — от RAG, RT-11 — от п. 3, RT-17 — от п. 4) | **Блокер shadow** | п. 2–4 |
| 7 | Провести учение G0 по kill switch | Высокая | Стенд (инфраструктура) |
| 9 | Решить, нужен ли RAG в MVP-A | Средняя | — |
| 10 | Подтвердить статус DPA с OpenRouter (ZDR), legal, DPIA, инвентаризации ПДн | **Блокер** | — |
| 11 | Разметка SRE, исторический golden-набор из постмортемов | Средняя / высокая для G0 | Выгрузка (`aegis-intake export`, этап 3a) |
| 12 | Семантика Argo `Error` на живом кластере, threshold-форма Argo `Inconclusive` | Низкая | Следующая смена набора |

### Инфраструктура

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | Создать bucket аудита: версионирование, Object Lock COMPLIANCE, отдельный аккаунт ([intake-deploy.md](../04-operations/intake-deploy.md)) | **Блокер shadow** | Срок хранения |
| 2 | Прогнать `aegis-audit checkpoint`/`verify` на живом bucket'е: per-object заголовки lock без default retention, lock-заголовки в GET, формат XML `?versions`, `DELETE` версии → 403 | **Блокер shadow** | Bucket |
| 2 | Алерты на `aegis_intake_audit_anchor_lag_seconds` и `aegis_intake_audit_anchor_errors_total` | Высокая | Bucket |
| 4 | Развернуть SPIRE и Vault (если не сузят объём) | **Блокер** | Решение Security |
| 6 | Применить NetworkPolicy egress и проверить на стенде | Высокая | — |
| 7 | Стенд kill switch: ConfigMap и RBAC, bucket, расписание renewer, `check` во внешнем мониторинге | Высокая | Ключи kill switch |
| 8 | Образы и их подпись cosign — когда появятся образы | Высокая | — |
| 9 | Индексация runbook'ов и Qdrant с аутентификацией (T-20) | Средняя | Решение по RAG |

### Ключи

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | Ключ подписи цепочки аудита в KMS | **Блокер shadow** | Выбор KMS, подписант в коде |
| 2 | Отдельная пара S3-ключей для выгрузки checkpoint'ов: `PutObject`, `GetObject(Version)`, `ListBucketVersions`, без Delete (`AEGIS_AUDIT_S3_*_FILE`) | **Блокер shadow** | Bucket |
| 3 | Ключ подписи policy bundle офлайн → секрет environment `policy-signing`; ключи в `deploy/policy-bundle/keys.json` | **Блокер shadow** | Ревьюеры |
| 7 | Ключи дежурных и двух renewer kill switch | Высокая | — |
| 8 | Ключ и environment `release` | Высокая | п. 3 |

### Настройки GitHub и конфигурация

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 3 | Группы в `.github/four-eyes.json` и CODEOWNERS с новыми ревьюерами (один PR) | **Блокер shadow** | Ревьюеры |
| 3 | Применить rulesets и environments `policy-signing`, `release` | **Блокер shadow** | Группы, ключ |
| 3 | Отключить merge-коммит и rebase в настройках репозитория (риск 14) | **Блокер shadow** | — |
| 3 | Ограничить круг write; проверить и включить immutable releases для `policy-bundle-*` (риск 6) | Средняя | — |
| 3 | Genesis-bundle (`workflow_dispatch`, `genesis=true`) | **Блокер shadow** | Rulesets, ключ, кодовые правки до genesis (ниже) |
| 3 | `policy_bundle.required: true` у intake | **Блокер shadow** | Genesis |
| 2 | Секция `audit.anchor` в конфигурации intake на стенде | **Блокер shadow** | Bucket, ключи |
| 8 | Первый прогон `release` на GitHub, сверить входы actions v7/v8 | Высокая | Environment `release` |

### Код

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | KMS-подписант цепочки аудита; для Yandex KMS — ECDSA P-256 в keyring и `ChainFormat = 4` (сначала верификаторы) | **Блокер shadow** | Выбор KMS |
| 3 | Защитить весь Go-код, попадающий в бинари: `eval/golden-synthetic/*.go`, `internal/promtext/`; тест «`go list -deps ./cmd/aegis-*` ⊆ защищённых путей» (риск 11) | **Блокер shadow** | До genesis |
| 3 | `cache: false` в `four-eyes.yml` и проверка отсутствующего ключа в `TestWorkflowCacheOnlyInCI` (риск 25) | Низкая | До genesis |
| 3 | Цикл по `keys.json` в `policy-bundle.yml` через `while IFS= read -r p` (риск 17) | Низкая | До genesis |
| 3 | Правило «защищённые PR сливать по одному» в §5 [ci-four-eyes.md](../07-governance/ci-four-eyes.md) (риск 8) | Средняя | До включения |
| 2 | Добавить `internal/audit/...` и `internal/routersvc` в race-шаг `ci.yml` | Низкая | — |
| 11 | `aegis-intake export` для разметки SRE | Средняя | Этап 3a |
| 12 | Golden-набор v6: убрать причину `insufficient_data_policy` из enum при политике не `rollback` | Низкая | Следующая смена набора |
| — | Отложено до этапа 1 / MVP-B: проверка подписанного bundle в `aegis-llmrouter` и `aegis-pep` (риск 19), защита от отката bundle (риск 13), группы по id и проверка права write (риск 21), трейлеры `Co-authored-by` (риск 12), проверка провенанса при деплое (риск 10) | Низкая для 0a | — |
| 13 | Роутер: подпись через KMS, четыре глаза для `resume` | Низкая (после MVP) | — |

## Предлагаемый порядок

1. CI и четыре глаза (п. 3 и п. 8): кодовые правки до genesis (риски 11, 17, 25), затем люди, ключ, настройки GitHub, genesis, `required: true`, RT-11.
2. Аудит в KMS и WORM (п. 2): WORM в коде готов (09.11.2026); выбор KMS и подписант, срок хранения, bucket и ключи, прогон на живом bucket'е.
3. Формальный red-team (п. 5) по готовым сценариям — после п. 2–3.
4. Решение по SPIRE/Vault (п. 4): развёртывать или формально сузить для MVP-A — утверждает Security.
