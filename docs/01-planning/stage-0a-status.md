# Этап 0a: что осталось (на 11.11.2026)

> Сверка работ Этапа 0a ([plan.md](plan.md) §0a, [plan-mvp.md](plan-mvp.md), недели 3–6) и списка P1 «до старта shadow» ([threat-model.md](../02-security/threat-model.md) §7) с состоянием репозитория после выгрузки checkpoint'ов аудита в WORM (09.11.2026). Статусы, которые не видны из репозитория (настройки GitHub, договорённости), отмечены отдельно. Кодовые пункты из [ci-four-eyes-risks.md](../07-governance/ci-four-eyes-risks.md) указаны со ссылкой «риск N».

## Сделано

Модель угроз; каталог действий и матрица автономности; PEP dry-run; LLM-роутер с маскированием, исключением restricted-контекста и режимом `off`; read-only intake; синтетический golden-набор и ежедневная eval-проба (набор и промпт v5); kill switch: код, наблюдаемость (`aegis-killswitch check`, `/metrics` intake), версия формата цепочки аудита. Закрыты угрозы T-01…T-03, T-08, T-12, T-15. CI, правило четырёх глаз, подпись policy bundle и релизный пайплайн — в репозитории (механизмы; T-24 пока не закрыт, см. п. 3). Аудит: выгрузка checkpoint'ов в WORM (`S3Anchor`, object lock COMPLIANCE, чтение всех версий), сверка на старте, периодическая фиксация с метриками отставания (09.11.2026). Egress intake: default-deny и CiliumNetworkPolicy с toFQDNs и фильтром SNI в `deploy/intake/`, ingress и egress OpenBao — `deploy/vault/network/` (тесты и стенды на Cilium; 11.11.2026), canary-проверка исходящих запросов к LLM в роутере вместо сканирования на прокси, race-шаг CI расширен на `internal/audit/...` и `internal/routersvc` (11.11.2026). Кодовые правки до genesis: защищён `internal/promtext/`, тест покрытия файлов сборки, `cache: false` в four-eyes, цикл по ключам B0, правило слияния по одному (риски 8, 11, 17, 25; 09.11.2026).

## Пункты этапа

| # | Пункт | Состояние | Важность |
|---|---|---|---|
| 1 | Калибровка ежедневной пробы v5 | Идёт с 08.11.2026, freeze ≈ 28–30.11.2026 | **Блокер shadow** |
| 2 | Аудит: подпись через KMS/HSM, checkpoint'ы в WORM (T-23, P1) | WORM в коде сделан; KMS-подписанта нет (ключ в файле; Vault Transit стал естественным кандидатом, выбор не сделан); bucket не создан, на живом Yandex Object Storage не проверено | **Блокер shadow** |
| 3 | Четыре глаза на изменения политик (T-24, P1; RT-11) | Включено на GitHub 09.11.2026: ruleset `main: четыре глаза` активен (2 одобрения, обязательные проверки `go`, `race`, `eval`, `four-eyes`), genesis-bundle опубликован; на практике `four-eyes` блокировал PR №6 до снятия запроса изменений. T-24 не закрыт: остаются `policy_bundle.required: true` у intake и RT-11 ([чек-лист](../07-governance/ci-four-eyes.md#чек-лист-включения), п. 7–8) | **Блокер shadow** |
| 4 | SPIFFE/SPIRE и Vault (plan.md §0a п. 2; T-36, P1; RT-18) | Решено 09.11.2026 (Security): SPIRE (T-35, RT-17) в MVP-B; Vault/OpenBao в MVP-A как хранилище секретов ([identity-secrets-mvp-a.md](../02-security/identity-secrets-mvp-a.md)); документ решения и `deploy/vault/` в репозитории; развёртывания нет; открытые вопросы — [identity-secrets-mvp-a.md §10](../02-security/identity-secrets-mvp-a.md#10-что-осталось-нерешённым-на-09112026-обновлено-10112026) | **Блокер shadow** (T-36 — P1) |
| 5 | Базовый red-team RT-01…RT-08, RT-11, RT-18 | Тесты RT-01…RT-04, RT-07, RT-08 есть; формального прогона и отчёта нет | **Блокер shadow** |
| 6 | Egress только через роутер (T-17, P1) | Манифесты [`deploy/intake/`](../../deploy/intake/): default-deny в `aegis-system` (NetworkPolicy), egress intake — CiliumNetworkPolicy (DNS с фильтром имён, OpenBao, Alertmanager, Prometheus, `kube-apiserver`, toFQDNs `openrouter.ai` и `storage.yandexcloud.net`); SNI (`serverNames`) на правилах `openrouter.ai` и `storage.yandexcloud.net`; ingress в OpenBao — [`deploy/vault/network/`](../../deploy/vault/network/); тесты `TestIntakeNetworkPolicy`, `TestOpenBaoNetworkPolicy`; стенды `run-netpol.sh` (54 PASS, 0 провалов; `internet` — 2 SKIP) и `run-ha.sh cilium` (61 PASS, 0 провалов) — 11.11.2026, Cilium 1.20.4. В бою не применено: нужен кластер с Cilium ≥ 1.13 | Высокая |
| 7 | Kill switch: стенд и учение G0 | Код и [runbook учения](../04-operations/kill-switch-drill.md) готовы | Высокая (критерий выхода G0; стенд нужен до shadow) |
| 8 | Подпись артефактов (plan.md §0a п. 11) | [Первый прогон `release`](https://github.com/limpjungle/aegis3311/actions/runs/42839402165) прошёл 10.11.2026. В [`v0.1.0`](https://github.com/limpjungle/aegis3311/releases/tag/v0.1.0) опубликованы пять бинарников Linux amd64, SBOM CycloneDX 1.5 и `SHA256SUMS`. Workflow выпустил SLSA-аттестации происхождения и аттестации SBOM. Подпись cosign запланирована при выпуске контейнерных образов. | Высокая для контейнерных образов |
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
| 4 | ~~Выбрать Vault или OpenBao~~ Выбран OpenBao (10.11.2026). Unseal: Raft 3, Shamir 3/2, HA-стенд проверен (решено 11.11.2026, утверждено Security: [PR №6](https://github.com/limpjungle/aegis3311/pull/6) одобрен `trix13371` и слит 11.11.2026; [identity-secrets-mvp-a.md §9](../02-security/identity-secrets-mvp-a.md#9-vault-или-openbao)) | Решено | — |
| 4 | Токены Alertmanager и Prometheus: в коде необязательны, а шаблоны агента требуют оба секрета в KV — загружать всегда или сделать шаблоны условными | Средняя | — |
| 5 | Формальный прогон red-team и отчёт (RT-05/RT-06 — от RAG, RT-11 — от п. 3, RT-18 — от развёртывания Vault) | **Блокер shadow** | п. 2–4 |
| 6 | Security: egress-прокси заменён на Cilium toFQDNs + SNI. Замена сканирования на canary-маркеры сделана: проверка в роутере перед отправкой ([data-classes.md](../02-security/data-classes.md) §5.2), реакция — halt роутера до `Resume` — утверждение Security. Включение двухфазное, `ChainFormat = 4`: после первой записи `egress_canary` откат ниже rollback floor невозможен ([migrations.md](../04-operations/migrations.md) «Откат») | Средняя | — |
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
| 4 | Развернуть OpenBao в HA (Raft 3, Shamir 3/2, HA-стенд проверен — [`deploy/vault/server/openbao-ha.yaml`](../../deploy/vault/server/openbao-ha.yaml)), два audit device и алерты, Kubernetes auth, применение политик из `deploy/vault/`, сверка расхождений с Git, церемония init с долями у держателей | **Блокер shadow** | Утверждение Security, PGP-ключи держателей, боевой кластер |
| 4 | ~~Проверить на dev-Vault и dev-OpenBao: отсутствующий путь в KV, `/tmp` агента, файлы `0400`~~ Сделано 10.11.2026: стенд [`deploy/vault/dev/`](../../deploy/vault/dev/) (minikube, `./run.sh openbao|vault`), обе реализации — 0 провалов; найдена и исправлена ошибка в `deploy/vault/agent/aegis-intake.json` (`method` должен быть списком), добавлен `num_retries: 3` | Решено | — |
| 4 | Подставить реальные `vault.address` и `vault.ca_cert` в `deploy/vault/agent/aegis-intake.json` (сейчас условные) | Средняя | Развёртывание Vault |
| 6 | ~~Применить NetworkPolicy egress и проверить на стенде~~ Сделано на стенде 11.11.2026 (Cilium 1.20.4, 0 провалов) | Решено | — |
| 6 | Создать боевой кластер Yandex MK8s с Cilium (**решено 11.11.2026**): версия ≥ 1.13 (`serverNames`; версия в документации Yandex не названа), L7-прокси, `cluster.local`, без NodeLocal DNS, ≥ 3 узлов — [intake-deploy.md](../04-operations/intake-deploy.md) | Высокая | — |
| 6 | Применить `deploy/intake/` и `deploy/vault/network/` в бою и прогнать проверки из пода intake | Высокая | Кластер с Cilium, развёртывание OpenBao |
| 6 | ~~NetworkPolicy ingress в OpenBao~~ Сделано: `deploy/vault/network/`, стенд `run-ha.sh cilium` 11.11.2026, 0 провалов | Решено | — |
| 6 | Сетевой путь CI-применителя к OpenBao (in-cluster Job или port-forward) и RBAC `pods/exec`/`pods/portforward` в namespace OpenBao только для держателей | Высокая | Развёртывание OpenBao |
| 6 | Hubble: алерт на объём egress intake → `openrouter.ai` и ежедневная сверка расхода OpenRouter с decision record'ами | Средняя | Кластер с Cilium |
| 6 | Staging: посадка canary-маркеров и `canary.markers_file` (data-classes.md §5.2) | Высокая для shadow | Staging |
| 7 | Стенд kill switch: ConfigMap и RBAC, бакет `aegis3311-kill-switch` (Standard, версионирование, без Object Lock, отдельное облако/каталог), расписание renewer, `check` во внешнем мониторинге | Высокая | Ключи kill switch |
| 8 | Образы и их подпись cosign — когда появятся образы | Высокая | — |
| 9 | Индексация runbook'ов и Qdrant с аутентификацией (T-20) | Средняя | Решение по RAG |

### Ключи

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 4 | PGP-ключи трёх держателей долей unseal (`limpjungle`, `Oltix146`, `trix13371`) и церемония init: доли и root шифруются этими ключами, хранение долей вне OpenBao | **Блокер развёртывания** | Утверждение Security |
| 4 | Загрузить секреты intake в Vault KV (`aegis-kv/data/mvp-a/…`) с response wrapping при передаче | **Блокер shadow** | Развёртывание Vault |
| 2 | Ключ подписи цепочки аудита в KMS | **Блокер shadow** | Выбор KMS, подписант в коде |
| 2 | Отдельная пара S3-ключей для выгрузки checkpoint'ов: `PutObject`, `GetObject(Version)`, `ListBucketVersions`, без Delete (`AEGIS_AUDIT_S3_*_FILE`) | **Блокер shadow** | Bucket |
| 3 | ~~Ключ подписи policy bundle офлайн → секрет environment `policy-signing`; ключи в `deploy/policy-bundle/keys.json`~~ Сделано 09.11.2026: секрет `POLICY_BUNDLE_SIGNING_KEY` создан (ключ перевыпущен: первый вариант приватного ключа попал в лог сессии), открытые ключи `ci-policy-signing.pub` и `break-glass.pub` в `deploy/policy-bundle/keys/`; break-glass зашифрован и разнесён на двух хранителей. В `main` вошли через [PR №1](https://github.com/limpjungle/aegis3311/pull/1) | Решено | — |
| 7 | Ключи дежурных и двух renewer kill switch | Высокая | — |
| 8 | ~~Настроить подпись бинарного релиза~~ Сделано в `v0.1.0`: публикация через environment `release`, аттестации подписаны через OIDC GitHub Actions и Sigstore. | Решено для бинарников | — |

### Настройки GitHub и конфигурация

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 3 | ~~Группы в `.github/four-eyes.json` и CODEOWNERS~~ Сделано 09.11.2026: `sre-leads` — `limpjungle`, `Oltix146`; `security` — `trix13371` | Решено | — |
| 3 | ~~Применить rulesets `main` и `tags`~~ Сделано 09.11.2026: `main: четыре глаза` (id 26882802) и `теги релизов и policy bundle` (id 26882804), `active`, без обхода; environments `policy-signing`, `release` — ревьюеры `trix13371`, `Oltix146`, `prevent_self_review` | Решено | — |
| 3 | ~~Отключить merge-коммит и rebase~~ Сделано 09.11.2026: только squash | Решено | — |
| 3 | ~~Круг write и immutable releases~~ Проверено 09.11.2026: write — `trix13371`, `Oltix146` (admin — `limpjungle`); immutable releases включены | Решено | — |
| 3 | ~~Genesis-bundle (`workflow_dispatch`, `genesis=true`)~~ Сделано 10.11.2026: опубликованы [policy-bundle-1](https://github.com/limpjungle/aegis3311/releases/tag/policy-bundle-1) и [policy-bundle-2](https://github.com/limpjungle/aegis3311/releases/tag/policy-bundle-2) | Решено | — |
| 3 | `policy_bundle.required: true` у intake | **Блокер shadow** | Genesis |
| 2 | Секция `audit.anchor` в конфигурации intake на стенде | **Блокер shadow** | Bucket, ключи |
| 8 | ~~Первый прогон `release` на GitHub~~ Сделано 10.11.2026: сборка, аттестации и публикация прошли в [прогоне `v0.1.0`](https://github.com/limpjungle/aegis3311/actions/runs/42839402165). | Решено | — |

### Код

| # | Что сделать | Важность | Зависит от |
|---|---|---|---|
| 2 | KMS-подписант цепочки аудита; для Yandex KMS — ECDSA P-256 в keyring и следующий уровень формата цепочки (5; уровень 4 занят причиной `egress_canary`; сначала верификаторы) | **Блокер shadow** | Выбор KMS |
| 2 | ~~Добавить `internal/audit/...` и `internal/routersvc` в race-шаг `ci.yml`~~ Сделано 11.11.2026 | Решено | — |
| 11 | `aegis-intake export` для разметки SRE | Средняя | Этап 3a |
| 12 | Golden-набор v6: убрать причину `insufficient_data_policy` из enum при политике не `rollback` | Низкая | Следующая смена набора |
| — | Отложено до этапа 1 / MVP-B: проверка подписанного bundle в `aegis-llmrouter` и `aegis-pep` (риск 19), защита от отката bundle (риск 13), группы по id и проверка права write (риск 21), трейлеры `Co-authored-by` (риск 12), проверка провенанса при деплое (риск 10) | Низкая для 0a | — |
| 13 | Роутер: подпись через KMS, четыре глаза для `resume` | Низкая (после MVP) | — |

## Предлагаемый порядок

1. Четыре глаза (п. 3): подтвердить `required: true` на стенде и пройти RT-11.
2. Аудит в KMS и WORM (п. 2): WORM в коде готов (09.11.2026); выбор KMS и подписант, срок хранения, bucket и ключи, прогон на живом bucket'е.
3. Формальный red-team (п. 5) по готовым сценариям — после п. 2–3.
4. Развёртывание Vault и RT-18 (п. 4): решение принято 09.11.2026, SPIRE — в MVP-B.
