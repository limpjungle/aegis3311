# Identity и секреты в MVP-A: Vault/OpenBao вместо SPIFFE/SPIRE

> Статус: **утверждено Security, 09.11.2026**. Документ защищён правилом четырёх глаз с обязательным одобрением `security` ([ci-four-eyes.md](../07-governance/ci-four-eyes.md) §1). Развёртывания пока нет: в репозитории решение, примеры политики и роли ([`deploy/vault/`](../../deploy/vault/)) и тесты `cmd/aegis-ci/secrets_inventory_test.go`.

## 1. Что требовалось

- [plan.md](../01-planning/plan.md) §0a п. 2: идентификация агентов (SPIFFE/SPIRE), управление секретами (Vault), минимальные привилегии.
- DF10 модели угроз ([threat-model.md](threat-model.md) §4): SVID и краткоживущие секреты.
- T-35 (компрометация SPIRE, P1), T-36 (кража токенов Vault) и RT-17 (registration entry одним человеком).

## 2. Решение

1. **SPIRE, T-35 и RT-17 переносятся в MVP-B** (P1 до пилота L2) вместе с T-18, T-26 и Cluster Agent. Основания: в MVP-A один процесс `aegis-intake serve` (роутер и PEP внутри него), межсервисных каналов нет, входящий порт только `/metrics`, прав на запись у платформы нет. SVID некому предъявлять.
2. **Vault/OpenBao разворачивается в MVP-A как хранилище секретов** (KV v2, mount `aegis-kv`). Код по-прежнему читает секреты только из файлов (`*_FILE`).
3. **Identity рабочей нагрузки в MVP-A — ServiceAccount Kubernetes**, вход в Vault через Kubernetes auth.
4. **T-36 повышается до P1 до shadow:** в Vault лежат ключ подписи аудита (T-23) и ключ OpenRouter (T-14), взлом Vault означает нарушение T-23.
5. **KMS для аудита не выбран** (§7). Подписант в код не пишется.

## 3. Инвентаризация секретов

Таблицу разбирает тест `TestSecretInventoryMatchesCode`: имена в первом столбце должны совпадать с литералами `*_FILE` в коде `cmd/` и `internal/`. Носитель — одно из `Vault KV`, `projected SA token`, `вне Vault` (после запятой допускается уточнение; тест сверяет префикс до запятой). Путь Vault указан только для `Vault KV`. Если переменную читают разные потребители, это разные строки. `{ACCESS_KEY_ID,SECRET_KEY,SESSION_TOKEN}` раскрыты в отдельные строки; `SESSION_TOKEN` необязателен и в MVP-A не используется (ключи статичные), поэтому шаблона для него в агенте нет.

| Переменная | Потребитель | Что это | Срок жизни | Ротация / перечитывание | Последствия компрометации | Носитель в MVP-A | Путь Vault |
|---|---|---|---|---|---|---|---|
| `OPENROUTER_API_KEY_FILE` | intake | Ключ OpenRouter | до ротации | читается на старте; ротация — rolling restart | расходы и утечка контекста у OpenRouter (T-14) | Vault KV | `aegis-kv/data/mvp-a/intake/openrouter` |
| `AEGIS_MASKER_KEY_FILE` | intake | Мастер-ключ псевдонимов маскировщика | до ротации | читается на старте; смена ключа меняет псевдонимы | расшифровка псевдонимов, связывание данных | Vault KV | `aegis-kv/data/mvp-a/intake/masker` |
| `AEGIS_AUDIT_KEY_FILE` | intake | Приватный ключ подписи цепочки аудита (ed25519) | до ротации (keyring) | читается на старте; ротация — новый ключ в keyring | подделка записей аудита (T-23) | Vault KV, до выбора KMS | `aegis-kv/data/mvp-a/intake/audit-signing` |
| `AEGIS_ALERTMANAGER_TOKEN_FILE` | intake | Токен чтения Alertmanager | до ротации | перечитывается на каждый запрос | чтение алертов | Vault KV | `aegis-kv/data/mvp-a/intake/alertmanager` |
| `AEGIS_PROMETHEUS_TOKEN_FILE` | intake | Токен чтения Prometheus | до ротации | перечитывается на каждый запрос | чтение метрик | Vault KV | `aegis-kv/data/mvp-a/intake/prometheus` |
| `AEGIS_KUBE_TOKEN_FILE` | intake | Токен API-сервера Kubernetes (только чтение) | 1 час | kubelet обновляет файл; перечитывается на каждый запрос | чтение спеков подов, окно — срок токена | projected SA token | — |
| `AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE` | intake, read-only пара | S3-ключ чтения объекта kill switch | до ротации | перечитывается на каждый запрос | чтение состояния kill switch; записи нет | Vault KV | `aegis-kv/data/mvp-a/intake/killswitch-s3` |
| `AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE` | intake, read-only пара | S3-ключ чтения объекта kill switch | до ротации | перечитывается на каждый запрос | чтение состояния kill switch; записи нет | Vault KV | `aegis-kv/data/mvp-a/intake/killswitch-s3` |
| `AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE` | intake, read-only пара | S3-ключ чтения объекта kill switch | до ротации | перечитывается на каждый запрос | чтение состояния kill switch; записи нет | Vault KV | `aegis-kv/data/mvp-a/intake/killswitch-s3` |
| `AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE` | `aegis-killswitch` (дежурные и renewer) | S3-ключ записи объекта kill switch | до ротации | перечитывается на каждый запрос | документ без подписи дежурных отвергается; возможны перезапись и отказ в обслуживании | вне Vault | — |
| `AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE` | `aegis-killswitch` (дежурные и renewer) | S3-ключ записи объекта kill switch | до ротации | перечитывается на каждый запрос | документ без подписи дежурных отвергается; возможны перезапись и отказ в обслуживании | вне Vault | — |
| `AEGIS_KILLSWITCH_S3_SESSION_TOKEN_FILE` | `aegis-killswitch` (дежурные и renewer) | S3-ключ записи объекта kill switch | до ротации | перечитывается на каждый запрос | документ без подписи дежурных отвергается; возможны перезапись и отказ в обслуживании | вне Vault | — |
| `AEGIS_KILLSWITCH_KUBE_TOKEN_FILE` | `aegis-killswitch` | Токен записи ConfigMap kill switch | по выдаче владельцем | перечитывается на каждый запрос | запись во внутренний канал остановки | вне Vault | — |
| `AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE` | intake | S3-ключ выгрузки checkpoint'ов аудита (без Delete) | до ротации | перечитывается на каждый запрос | запись и чтение checkpoint'ов, удалить нельзя (WORM) | Vault KV | `aegis-kv/data/mvp-a/audit-anchor` |
| `AEGIS_AUDIT_S3_SECRET_KEY_FILE` | intake | S3-ключ выгрузки checkpoint'ов аудита (без Delete) | до ротации | перечитывается на каждый запрос | запись и чтение checkpoint'ов, удалить нельзя (WORM) | Vault KV | `aegis-kv/data/mvp-a/audit-anchor` |
| `AEGIS_AUDIT_S3_SESSION_TOKEN_FILE` | intake | S3-ключ выгрузки checkpoint'ов аудита (без Delete) | до ротации | перечитывается на каждый запрос | запись и чтение checkpoint'ов, удалить нельзя (WORM) | Vault KV | `aegis-kv/data/mvp-a/audit-anchor` |
| `AEGIS_AUDIT_S3_ACCESS_KEY_ID_FILE` | `aegis-audit`, оператор | та же пара ключей при ручной проверке | до ротации | перечитывается на каждый запрос | см. выше | Vault KV, вход оператора OIDC; политика вне примеров deploy/ | `aegis-kv/data/mvp-a/audit-anchor` |
| `AEGIS_AUDIT_S3_SECRET_KEY_FILE` | `aegis-audit`, оператор | та же пара ключей при ручной проверке | до ротации | перечитывается на каждый запрос | см. выше | Vault KV, вход оператора OIDC; политика вне примеров deploy/ | `aegis-kv/data/mvp-a/audit-anchor` |
| `AEGIS_AUDIT_S3_SESSION_TOKEN_FILE` | `aegis-audit`, оператор | та же пара ключей при ручной проверке | до ротации | перечитывается на каждый запрос | см. выше | Vault KV, вход оператора OIDC; политика вне примеров deploy/ | `aegis-kv/data/mvp-a/audit-anchor` |
| `-key` | `aegis-killswitch`, дежурные и renewer | Приватные ключи подписи kill switch (флаг, не переменная) | по выдаче владельцем | ротация ключей — через keyring | подпись команды остановки или возобновления | вне Vault, у владельца | — |

Что остаётся вне Vault и почему:

- **Kill switch.** Ключи подписи дежурных и renewer, их S3-ключи записи и kube-токен записи `aegis-killswitch` в Vault не попадают. Внешний канал не должен зависеть от Control Plane: при отказе или взломе Vault остановка должна работать. Read-only S3-пара intake для kill switch хранится в Vault; если Vault недоступен, intake не стартует и уходит в fail-closed, что допустимо для fail-safe.
- **Токен Kubernetes API intake** — projected SA token, его выдаёт kubelet, не Vault.

Переменные `*_TOKEN`, `*_KEY` без суффикса `_FILE` (значение секрета прямо в окружении) в коде не допускаются: `TestNoSecretValueEnv`.

## 4. Доставка секретов

Vault Agent запускается **init-контейнером** с `exit_after_auth: true`:

1. входит по projected-токену своего контейнера с audience `vault`;
2. записывает файлы в общий tmpfs (`emptyDir: {medium: Memory}`), права `0400`;
3. завершается.

Так токена Vault нет ни у процесса intake, ни где-либо в поде после старта: нет sink, listener и api_proxy, projected-токен с audience `vault` смонтирован только в контейнер агента. Файлы с правами `0400` читает только владелец, поэтому у агента и intake должен быть одинаковый `runAsUser`. Фрагмент пода — в [intake-deploy.md](../04-operations/intake-deploy.md), раздел «Секреты: Vault Agent».

Почему не иначе:

- **Постоянный sidecar** дал бы автоматическую ротацию, но ценой живого токена Vault в поде 24/7. Три секрета из шести и так читаются один раз; остальные статичны. Ротация — rolling restart.
- **CSI-провайдер** отклонён: это DaemonSet, который входит в Vault от имени чужих подов, и у него шире права.

## 5. Меры по Vault (T-36)

- **Kubernetes auth.** Роль привязана к одному ServiceAccount и одному namespace, `audience: vault`, `token_ttl ≤ 5m`, `token_max_ttl ≤ 10m` ([`deploy/vault/roles/`](../../deploy/vault/roles/)).
- **Политика на каждую identity**, только `read` на точные пути, без glob ([`deploy/vault/policies/`](../../deploy/vault/policies/)).
- **Нет sink, listener и api_proxy.** Токен с audience `vault` только в контейнере агента.
- **Response wrapping** (`-wrap-ttl`) для ручной передачи секретов между людьми при начальной загрузке и для unseal/recovery-материалов.
- **Два audit device:** файл и внешний syslog/SIEM. Vault отказывает в запросах, если не пишется ни один, — это fail-closed.
- **Алерты:** запись в `sys/policy/*`, `sys/policies/*`, `auth/*/role/*`, `sys/auth/*`, `sys/audit/*`, `sys/mounts/*`; выпуск root-токена (`sys/generate-root-token/*`) и смена ключей (`sys/rotate/*`) — оба пути пишутся в audit (проверено на стенде для generate-root); узел sealed дольше N минут (N — решение SRE; надёжный сигнал — под не Ready, потому что readiness-проба `bao status` у sealed даёт код 2; `sys/metrics` по умолчанию выключен — `prometheus is not enabled`, нужен блок `telemetry`, а для sealed-узла ещё `unauthenticated_metrics_access`, на стенде это не включалось); попытки unseal на sealed-узле в audit не попадают (аудит недоступен, пока хранилище запечатано), только в лог сервера; чтение `aegis-kv/data/mvp-a/*` не той сущностью; всплеск `permission denied` и неудачных входов.
- **HA:** integrated storage Raft на 3 или 5 узлах, зашифрованные снапшоты, отдельный namespace и узлы; NetworkPolicy: к Vault ходят только поды агентов и CI-применитель.
- **Unseal: Shamir, 3 доли** (по одной у `limpjungle`, `Oltix146`, `trix13371`), порог 2. При `init` доли и root-токен шифруются PGP-ключами держателей (`pgp_keys`, `root_token_pgp_key`); доли вводятся только через stdin (`key=-`) или запрос с `port-forward`, не в argv и не в историю shell. После рестарта узел остаётся sealed, пока не введены две доли. Решено 11.11.2026 (на утверждении Security, `trix13371`), обоснование — §9.
- **Root-токен** отзывается сразу после начальной настройки. При Shamir доли unseal — одновременно кворум `generate-root` (break-glass) и `rotate/root` (rekey при смене держателя): 3 держателя, порог 2. В OpenBao 2.7.2 `sys/generate-root-token/*` требует токена (безтокенный `sys/generate-root/*` отвечает 405), поэтому нужен заранее выданный токен-инициатор с правом только на эти пути (проверено на стенде; политика и его выдача — часть церемонии init, хранение — как у долей).
- **Изменения только через Git.** Политики и роли меняются только из `deploy/vault/` через PR с четырьмя глазами. Ни у одного человека нет записи в `sys/policy`, кроме break-glass через generate-root с кворумом. Расхождение живой конфигурации с Git ловит периодическая сверка (`vault policy read` против Git) — это инфраструктура.
- **Политика `aegis-audit-operator`** (чтение `aegis-kv/data/mvp-a/audit-anchor` оператором после входа через OIDC) описана здесь без файла: применяется отдельно, вне примеров `deploy/`.

CI-применитель с правом записи политик — новый корень доверия: [ci-four-eyes-risks.md](../07-governance/ci-four-eyes-risks.md), риск 29.

## 6. RT-18

**Изменение политики, роли или auth method Vault, отключение audit device одним человеком.**

Pass: прямая запись отклонена (`permission denied`); изменение возможно только через PR с двумя одобрениями; на любую попытку срабатывает алерт audit device.

RT-18 выполняется после развёртывания Vault; в Этапе 0a он заменяет RT-17.

## 7. KMS для аудита

Выбор не сделан. Два пути:

- **Vault Transit.** Ключ `ed25519`, `exportable=false`, формат цепочки не меняется. Но процессу понадобится токен Vault: это ломает свойство «нет токена в поде», потребует sidecar и отдельной политики `transit/sign`, а значит пересмотра T-36.
- **Yandex KMS.** ECDSA P-256, `ChainFormat = 4`, сначала верификаторы. IAM-токен — через федерацию сервисных аккаунтов.

До выбора ключ подписи лежит в Vault KV и доставляется файлом. Это лучше, чем сейчас (аудит доступа, политика по identity), но T-23 (KMS/HSM) не закрывает. После выбора меняется строка `AEGIS_AUDIT_KEY_FILE` в §3.

## 8. Триггеры пересмотра SPIRE

Любое из условий, и в любом случае до пилота L2:

- второй процесс Aegis с сетевым каналом между компонентами;
- права на запись;
- Cluster Agent;
- etcd или Temporal в контуре.

## 9. Vault или OpenBao

**Решение 10.11.2026: OpenBao** (MPL 2.0 — без согласования лицензии с legal). Конфигурация, пути и JSON совместимы с Vault; на dev-стенде ([`deploy/vault/dev/`](../../deploy/vault/dev/)) файлы из `deploy/vault/` одинаково работают в OpenBao 2.7.2 и Vault 2.0.4. Имена «Vault», `vault.*` в конфигурации агента и каталог `deploy/vault/` остаются: это формат, а не продукт.

- **Vault** под BSL 1.1: внутреннее использование разрешено, нужно подтверждение legal. В сборке Yandex есть auto-unseal через Yandex KMS.
- **OpenBao** под MPL 2.0, нативного seal для Yandex KMS нет.

### Unseal

**Решено 11.11.2026 (на утверждении Security, `trix13371`): Shamir 3/2** — 3 доли, порог 2, Raft на 3 узлах, без второго OpenBao и без HSM. Боевые values — [`deploy/vault/server/openbao-ha.yaml`](../../deploy/vault/server/openbao-ha.yaml) (блока `seal` нет), стенд — `deploy/vault/dev/run-ha.sh`.

| Вариант | Итог |
|---|---|
| **Shamir** | Выбран: лучшая безопасность (ключ не хранится нигде, кроме людей), без кода и без зависимости от Yandex Cloud. Цена: после рестарта узла нужны двое из трёх; рестарт одного узла кластер переживает (узел sealed до unseal), рестарт всех — всё sealed, новые поды intake не стартуют, работающие продолжают |
| Transit seal | Новый корень доверия (токен в Secret) и второй кластер, который сам запечатан по Шамиру; без seal-кластера нет доступа. [openbao.org/docs/configuration/seal/transit](https://openbao.org/docs/configuration/seal/transit/) |
| PKCS#11 | Встроенный `pkcs11` убран в 2.7.0 ([CHANGELOG](https://github.com/openbao/openbao/blob/main/CHANGELOG.md)); Yandex Cloud HSM доступен только через KMS API |
| Static | Ключ лежит рядом с данными — для T-36 не годится |
| KMS-плагин Yandex | Тип плагина `kms` есть с 2.6.0 ([CHANGELOG](https://github.com/openbao/openbao/blob/main/CHANGELOG.md)), плагина для Yandex нет; собственный Go-плагин — код и новый корень доверия. Запасной путь миграции |

Снижение цены Shamir: Raft 3, PodDisruptionBudget `maxUnavailable: 1`, `OnDelete` (поды обновляются по одному с unseal после каждого), отдельный пул узлов без автообновлений, алерт на sealed-узел. Нюансы OpenBao 2.7.2, найденные на стенде: audit device объявляются в конфигурации (создание через API закрыто флагом `unsafe_allow_api_audit_creation`, CVE-2025-54997); версию не понижать (2.6.4 и 2.7.1 добавили аудит generate-root и rekey); новые узлы Raft сначала non-voter и повышаются автопилотом через 10–30 с.

**Миграция Shamir → auto-unseal** штатная: доли становятся recovery-ключами. Триггеры перехода — §10, п. 16.

**Связь с §7.** Shamir не создаёт второго OpenBao, поэтому «Vault Transit для аудита» в §7 — по-прежнему основной кластер и токен в поде; если для аудита выберут Yandex KMS, IAM-федерация пригодится и будущему KMS-плагину.

## 10. Что осталось нерешённым (на 09.11.2026, обновлено 10.11.2026)

| № | Вопрос | Что сделать | Важность | Зависит от |
|---|---|---|---|---|
| 1 | ~~Vault или OpenBao (§9)~~ Выбран OpenBao (10.11.2026). ~~Способ unseal~~ Решено 11.11.2026 (на утверждении Security, `trix13371`): Shamir 3/2, Raft 3 (§9); проверено на HA-стенде `deploy/vault/dev/run-ha.sh` | Утверждение Security при ревью PR | Высокая | — |
| 2 | Развёртывание | OpenBao в HA (Raft 3, Shamir 3/2), два audit device и алерты (§5), Kubernetes auth, применение политик из `deploy/vault/` CI-применителем, периодическая сверка расхождений с Git, отзыв root-токена, церемония init: PGP-ключи трёх держателей, токен-инициатор generate-root | **Блокер shadow** (T-36 — P1) | п. 1 (утверждение) |
| 3 | Загрузка секретов | Загрузить секреты intake в `aegis-kv/data/mvp-a/…` с response wrapping при передаче между людьми | **Блокер shadow** | п. 2 |
| 4 | RT-18 (§6) | Прогнать после развёртывания, результат — в отчёт red-team | **Блокер shadow** | п. 2 |
| 5 | ~~Отсутствующий путь в KV~~ | Проверено 10.11.2026 на dev-стенде ([`deploy/vault/dev/`](../../deploy/vault/dev/), OpenBao 2.7.2 и Vault 2.0.4): и нет пути, и нет ключа — init-контейнер завершается с ошибкой, intake не запускается, пустого файла нет. Без предела повторов агент ждал отсутствующий путь ~5 минут (12 попыток); в конфигурацию добавлен `vault.retry.num_retries: 3` — отказ за секунды, повторы делает Kubernetes (CrashLoopBackOff) | Решено | — |
| 6 | ~~Временный каталог агента~~ | Проверено 10.11.2026 на dev-стенде ([`deploy/vault/dev/`](../../deploy/vault/dev/), OpenBao 2.7.2 и Vault 2.0.4): агенту с `exit_after_auth` записываемый `/tmp` не нужен, `readOnlyRootFilesystem: true` работает без дополнительного тома | Решено | — |
| 7 | ~~Права на файлы секретов~~ | Проверено 10.11.2026 на dev-стенде ([`deploy/vault/dev/`](../../deploy/vault/dev/), OpenBao 2.7.2 и Vault 2.0.4): файлы `0400`, владелец 10001; intake с тем же `runAsUser` читает все девять файлов; токенов Vault и SA по умолчанию в контейнере intake нет | Решено | — |
| 8 | Токены Alertmanager и Prometheus | Код считает их необязательными, а шаблоны агента с `error_on_missing_key` требуют оба секрета в KV — иначе под не стартует. Решить: загружать всегда или сделать шаблоны условными | Средняя | — |
| 9 | Адреса в конфигурации агента | `vault.address` и `vault.ca_cert` в `deploy/vault/agent/aegis-intake.json` — условные (`https://vault.vault.svc:8200`, `/vault/ca/ca.pem`); подставить реальные | Средняя | п. 2 |
| 10 | KMS для подписи аудита (§7) | Vault Transit требует живого токена в поде (sidecar с api_proxy) — противоречит init-режиму, потребует пересмотра мер T-36; Yandex KMS — `ChainFormat = 4`. До выбора T-23 открыт, ключ в KV | **Блокер shadow** (T-23) | Решение Security |
| 11 | Ротация | В init-режиме ротация только rolling restart; при недоступном Vault новый под не стартует. Пересмотреть, если понадобится непрерывная ротация (sidecar → пересмотр T-36) | Низкая | — |
| 12 | Политика оператора `aegis-audit` | Описана в §3 без файла в `deploy/vault/`; добавить файл политики и вход OIDC при развёртывании | Низкая | п. 2 |
| 13 | Тест инвентаризации | Соответствие «переменная — потребитель» кодом не подтверждается: тест сверяет имена переменных и носитель, но не то, какой бинарь их читает | Низкая | — |
| 14 | Ошибка в конфигурации агента (найдена на стенде 10.11.2026) | `auto_auth.method` был объектом — агент не загружал конфигурацию вообще («one and only one "method" block is required»), а тест инвентаризации закреплял эту форму. Исправлено: `method` — список из одного блока, тест проверяет форму и `num_retries` | Решено | — |
| 15 | RTO полного рестарта и доступность держателей | Рестарт всех узлов требует двух из трёх держателей; на стенде полный рестарт с unseal занимает около 2 минут — 122 с до успешного входа агента (см. [README](../../deploy/vault/README.md#ha-стенд)), в бою добавится время связи с людьми. Определить допустимый RTO и график дежурств держателей | Высокая | Решение SRE и Security |
| 16 | Триггеры перехода на auto-unseal (KMS-плагин Yandex) | Любое из условий: больше 2 полных рестартов в месяц; нужен RTO меньше согласованного в п. 15; появился четвёртый человек-держатель (кворум 2 из 3 перестаёт покрывать отпуск и болезнь) | Низкая | п. 15 |
| 17 | Транспорт второго audit device в SIEM | Второй audit device пишет в stdout (сборщик логов); stdout не делает аудит fail-closed при отказе SIEM — выбрать транспорт (syslog/сокет) и зафиксировать, что при отказе SIEM запись не блокируется | Средняя | п. 2 |
