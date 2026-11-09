# Этап 0a: что осталось (на 09.11.2026)

> Сверка работ Этапа 0a ([plan.md](plan.md) §0a, [plan-mvp.md](plan-mvp.md), недели 3–6) и списка P1 «до старта shadow» ([threat-model.md](../02-security/threat-model.md) §7) с состоянием репозитория после выгрузки checkpoint'ов аудита в WORM (09.11.2026). Статусы, которые не видны из репозитория (настройки GitHub, договорённости), отмечены отдельно. Кодовые пункты из [ci-four-eyes-risks.md](../07-governance/ci-four-eyes-risks.md) указаны со ссылкой «риск N».

## Сделано

Модель угроз; каталог действий и матрица автономности; PEP dry-run; LLM-роутер с маскированием, исключением restricted-контекста и режимом `off`; read-only intake; синтетический golden-набор и ежедневная eval-проба (набор и промпт v5); kill switch: код, наблюдаемость (`aegis-killswitch check`, `/metrics` intake), версия формата цепочки аудита. Закрыты угрозы T-01…T-03, T-08, T-12, T-15. CI, правило четырёх глаз, подпись policy bundle и релизный пайплайн — в репозитории (механизмы; T-24 пока не закрыт, см. п. 3). Аудит: выгрузка checkpoint'ов в WORM (`S3Anchor`, object lock COMPLIANCE, чтение всех версий), сверка на старте, периодическая фиксация с метриками отставания (09.11.2026). Кодовые правки до genesis: защищён `internal/promtext/`, тест покрытия файлов сборки, `cache: false` в four-eyes, цикл по ключам B0, правило слияния по одному (риски 8, 11, 17, 25; 09.11.2026).

## Пункты этапа

| # | Пункт | Состояние | Важность |
|---|---|---|---|
| 1 | Калибровка ежедневной пробы v5 | Идёт с 08.11.2026, freeze ≈ 28–30.11.2026 | **Блокер shadow** |
| 2 | Аудит: подпись через KMS/HSM, checkpoint'ы в WORM (T-23, P1) | WORM в коде сделан; KMS-подписанта нет (ключ в файле; Vault Transit стал естественным кандидатом, выбор не сделан); bucket не создан, на живом Yandex Object Storage не проверено | **Блокер shadow** |
| 3 | Четыре глаза на изменения политик (T-24, P1; RT-11) | Механизмы в репозитории ([ci-four-eyes.md](../07-governance/ci-four-eyes.md)); не включено | **Блокер shadow** |
| 4 | SPIFFE/SPIRE и Vault (plan.md §0a п. 2; T-36, P1; RT-18) | Решено 09.11.2026 (Security): SPIRE (T-35, RT-17) в MVP-B; Vault/OpenBao в MVP-A как хранилище секретов ([identity-secrets-mvp-a.md](../02-security/identity-secrets-mvp-a.md)); документ решения и `deploy/vault/` в репозитории; развёртывания нет; открытые вопросы — [identity-secrets-mvp-a.md §10](../02-security/identity-secrets-mvp-a.md#10-что-осталось-нерешённым-на-09112026) | **Блокер shadow** (T-36 — P1) |
| 5 | Базовый red-team RT-01…RT-08, RT-11, RT-18 | Тесты RT-01…RT-04, RT-07, RT-08 есть; формального прогона и отчёта нет | **Блокер shadow** |
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
| 2 | Выбрать KMS для подписи цепочки аудита (Yandex KMS — только ECDSA/RSA, без Ed25519; Vault Transit — нужен живой токен в поде, противоречит init-режиму Vault Agent и требует пересмотра T-36; HSM) | **Блокер shadow** | — |
| 2 | Утвердить срок хранения checkpoint'ов в WORM (режим COMPLIANCE необратим до истечения срока) — Security и compliance | **Блокер shadow** | До создания bucket'а |
| 2 | Принять (или отклонить) отступление от T-23: отставание выгрузки не блокирует запись до G1 — Security | Высокая | — |
| 3 | ~~Найти ещё одного ревьюера~~ Сделано 09.11.2026: `limpjungle` и `Oltix146` — SRE-лиды, `trix13371` — security; два одобрения набираются при любом авторе. Остаётся: второй участник `security` — иначе PR от `trix13371` в пути с `require: security` не слить (средняя) | Решено | — |
| 3 | Прогнать RT-11 вручную на живом репозитории | **Блокер shadow** | Включение четырёх глаз |
| 4 | ~~Решение Security: развернуть SPIRE/Vault или сузить объём~~ Принято 09.11.2026: SPIRE в MVP-B, Vault/OpenBao в MVP-A | Решено | — |
| 4 | Выбрать Vault или OpenBao (лицензия BSL 1.1 — legal; unseal: Yandex KMS у Vault, у OpenBao проверить) | Высокая, до развёртывания | — |
| 4 | Токены Alertmanager и Prometheus: в коде необязательны, а шаблоны агента требуют оба секрета в KV — загружать всегда или сделать шаблоны условными | Средняя | — |
| 5 | Формальный прогон red-team и отчёт (RT-05/RT-06 — от RAG, RT-11 — от п. 3, RT-18 — от развёртывания Vault) | **Блокер shadow** | п. 2–4 |
| 7 | Провести учение G0 по kill switch | Высокая | Стенд (инфраструктура) |
| 9 | Решить, нужен ли RAG в MVP-A | Средняя | — |
| 10 | Подтвердить статус DPA с OpenRouter (ZDR), legal, DPIA, инвентаризации ПДн | **Блокер** | — |
| 11 | Разметка SRE, исторический golden-набор из постмортемов | Средняя / высокая для G0 | Выгрузка (`aegis-intake export`, этап 3a) |
| 12 | Семантика Argo `Error` на живом кластере, threshold-форма Argo `Inconclusive` | Низкая | Следующая смена набора |

### Инфраструктура

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | Создать бакет `aegis3311-audit-worm` (Yandex Object Storage, Standard, версионирование, Object Lock без режима по умолчанию, без KMS-шифрования, отдельный каталог — [intake-deploy.md](../04-operations/intake-deploy.md#бакеты-в-yandex-object-storage-решение-09112026)); сначала тестовый бакет с `retention: 24h` | **Блокер shadow** | Срок хранения (для боевого) |
| 2 | Прогнать `aegis-audit checkpoint`/`verify` на живом bucket'е: per-object заголовки lock без default retention, lock-заголовки в GET, формат XML `?versions`, `DELETE` версии → 403 | **Блокер shadow** | Bucket |
| 2 | Алерты на `aegis_intake_audit_anchor_lag_seconds` и `aegis_intake_audit_anchor_errors_total` | Высокая | Bucket |
| 4 | Развернуть Vault/OpenBao в HA (Raft, auto-unseal), два audit device и алерты, Kubernetes auth, применение политик из `deploy/vault/`, сверка расхождений с Git, recovery-ключи | **Блокер shadow** | Выбор Vault или OpenBao |
| 4 | Проверить на dev-Vault и dev-OpenBao: под не стартует при отсутствующем пути в KV (не пустой файл); нужен ли агенту записываемый `/tmp` при `readOnlyRootFilesystem`; intake читает файлы `0400` при одинаковом `runAsUser` | Высокая | Dev-стенд |
| 4 | Подставить реальные `vault.address` и `vault.ca_cert` в `deploy/vault/agent/aegis-intake.json` (сейчас условные) | Средняя | Развёртывание Vault |
| 6 | Применить NetworkPolicy egress и проверить на стенде | Высокая | — |
| 7 | Стенд kill switch: ConfigMap и RBAC, бакет `aegis3311-kill-switch` (Standard, версионирование, без Object Lock, отдельное облако/каталог), расписание renewer, `check` во внешнем мониторинге | Высокая | Ключи kill switch |
| 8 | Образы и их подпись cosign — когда появятся образы | Высокая | — |
| 9 | Индексация runbook'ов и Qdrant с аутентификацией (T-20) | Средняя | Решение по RAG |

### Ключи

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 4 | Загрузить секреты intake в Vault KV (`aegis-kv/data/mvp-a/…`) с response wrapping при передаче | **Блокер shadow** | Развёртывание Vault |
| 2 | Ключ подписи цепочки аудита в KMS | **Блокер shadow** | Выбор KMS, подписант в коде |
| 2 | Отдельная пара S3-ключей для выгрузки checkpoint'ов: `PutObject`, `GetObject(Version)`, `ListBucketVersions`, без Delete (`AEGIS_AUDIT_S3_*_FILE`) | **Блокер shadow** | Bucket |
| 3 | Ключ подписи policy bundle офлайн → секрет environment `policy-signing`; ключи в `deploy/policy-bundle/keys.json` | **Блокер shadow** | Ревьюеры |
| 7 | Ключи дежурных и двух renewer kill switch | Высокая | — |
| 8 | Ключ и environment `release` | Высокая | п. 3 |

### Настройки GitHub и конфигурация

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 3 | ~~Группы в `.github/four-eyes.json` и CODEOWNERS~~ Сделано 09.11.2026: `sre-leads` — `limpjungle`, `Oltix146`; `security` — `trix13371` | Решено | — |
| 3 | Применить rulesets `main` и `tags` (environments `policy-signing`, `release` созданы 09.11.2026: ревьюеры `trix13371`, `Oltix146`, `prevent_self_review`) | **Блокер shadow** | Ключ и секрет `POLICY_BUNDLE_SIGNING_KEY` |
| 3 | ~~Отключить merge-коммит и rebase~~ Сделано 09.11.2026: только squash | Решено | — |
| 3 | ~~Круг write и immutable releases~~ Проверено 09.11.2026: write — `trix13371`, `Oltix146` (admin — `limpjungle`); immutable releases включены | Решено | — |
| 3 | Genesis-bundle (`workflow_dispatch`, `genesis=true`) | **Блокер shadow** | Rulesets, ключ |
| 3 | `policy_bundle.required: true` у intake | **Блокер shadow** | Genesis |
| 2 | Секция `audit.anchor` в конфигурации intake на стенде | **Блокер shadow** | Bucket, ключи |
| 8 | Первый прогон `release` на GitHub, сверить входы actions v7/v8 | Высокая | Environment `release` |

### Код

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | KMS-подписант цепочки аудита; для Yandex KMS — ECDSA P-256 в keyring и `ChainFormat = 4` (сначала верификаторы) | **Блокер shadow** | Выбор KMS |
| 2 | Добавить `internal/audit/...` и `internal/routersvc` в race-шаг `ci.yml` | Низкая | — |
| 11 | `aegis-intake export` для разметки SRE | Средняя | Этап 3a |
| 12 | Golden-набор v6: убрать причину `insufficient_data_policy` из enum при политике не `rollback` | Низкая | Следующая смена набора |
| — | Отложено до этапа 1 / MVP-B: проверка подписанного bundle в `aegis-llmrouter` и `aegis-pep` (риск 19), защита от отката bundle (риск 13), группы по id и проверка права write (риск 21), трейлеры `Co-authored-by` (риск 12), проверка провенанса при деплое (риск 10) | Низкая для 0a | — |
| 13 | Роутер: подпись через KMS, четыре глаза для `resume` | Низкая (после MVP) | — |

## Предлагаемый порядок

1. CI и четыре глаза (п. 3 и п. 8): люди, ключ, настройки GitHub, genesis, `required: true`, RT-11.
2. Аудит в KMS и WORM (п. 2): WORM в коде готов (09.11.2026); выбор KMS и подписант, срок хранения, bucket и ключи, прогон на живом bucket'е.
3. Формальный red-team (п. 5) по готовым сценариям — после п. 2–3.
4. Развёртывание Vault и RT-18 (п. 4): решение принято 09.11.2026, SPIRE — в MVP-B.
