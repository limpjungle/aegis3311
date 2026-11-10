# Vault/OpenBao: политика, роль и конфигурация агента для intake

Решение и инвентаризация секретов — [identity-secrets-mvp-a.md](../../docs/02-security/identity-secrets-mvp-a.md). Каталог защищён правилом четырёх глаз (`deploy/`). Файлы — JSON: его принимают и Vault, и OpenBao. Тест `cmd/aegis-ci/secrets_inventory_test.go` проверяет их против инвентаризации и против кода.

| Файл | Что это |
|---|---|
| `policies/aegis-intake.json` | Политика: только `read` на точные пути KV v2 для intake |
| `roles/aegis-intake.json` | Роль Kubernetes auth: один ServiceAccount, один namespace, audience `vault`, TTL ≤ 5m / 10m |
| `agent/aegis-intake.json` | Vault Agent для init-контейнера: `exit_after_auth`, шаблоны с правами `0400`, без sink, listener, api_proxy и cache |
| `server/openbao-ha.yaml` | Боевые values чарта openbao/openbao 0.30.7: Raft 3, TLS, Shamir 3/2 (блока `seal` нет), два audit device в конфигурации, `OnDelete`, PDB `maxUnavailable: 1`, образ по digest. Проверяет `cmd/aegis-ci/openbao_ha_test.go` |
| `dev/run-ha.sh` | HA-стенд: ставит эти values на minikube и проверяет init, unseal, рестарты и break-glass |
| `policies/bg-init.json` | Политика токена-инициатора break-glass (`generate-root`, `rotate-keys`), без `delete`; не intake-политика, проверяется `TestBreakGlassInitiatorPolicy` |
| `dev/lib.sh` | Общие функции стенда для `run.sh` и `run-ha.sh` |

## Dev-стенд

`dev/run.sh openbao` или `dev/run.sh vault` поднимает minikube (профиль `aegis-vault-dev`, драйвер docker), ставит сервер Helm-чартом в dev-режиме (`dev/values-*.yaml`, версии чартов и digest образов закреплены), применяет политику, роль и конфигурацию агента из этого каталога и проверяет:

- под по фрагменту из [intake-deploy.md](../../docs/04-operations/intake-deploy.md) («Секреты: Vault Agent», `dev/pod-template.yaml`): все файлы `0400`, читаются под тем же `runAsUser` при `readOnlyRootFilesystem`, токенов Vault и SA в контейнере intake нет;
- нет ключа в секрете и нет пути в KV — init-контейнер падает по ожидаемой причине (ошибка конфигурации агента не засчитывается);
- токен роли `aegis-intake` читает только свои пути; запись в KV, `sys/policy`, роли auth, отключение secrets/auth/audit — `permission denied`; вход по токену с audience не `vault` отклоняется.

Dev-режим: in-memory, без TLS, root-токен `root`, секреты фиктивные; для стенда в конфигурации агента меняется только адрес сервера. Образы скачиваются на хосте по digest и загружаются в minikube (DNS внутри узла может не работать). kind не используется: на ядре 7.2 узел `kindest/node:v1.37.0` не поднимал control plane. `dev/run.sh down` удаляет стенд.

Последний прогон 11.11.2026: OpenBao 2.7.2 и Vault 2.0.4 — 0 провалов (после выноса общих функций в `dev/lib.sh`).

## HA-стенд

`dev/run-ha.sh` (down: `dev/run-ha.sh down`) ставит боевые values ([`server/openbao-ha.yaml`](server/openbao-ha.yaml)) с оверлеем стенда (`dev/values-openbao-ha.yaml`: без anti-affinity, тома 1Gi) в namespace `openbao-ha` и каждый раз начинает с нуля. Одноразовые CA (TLS) и три PGP-ключа «держателей» живут во временном каталоге и удаляются при выходе. Проверяется:

- до init: три пода Running, sealed, не Ready; init возвращает 3 доли и root, зашифрованные PGP; одна доля — progress 1/2, битая доля отвергается, две — unsealed;
- `raft list-peers`: 3 voter и один leader, ровно 2 audit device, секреты по TLS (`BAO_CACERT`), отзыв root (повторный запрос — 403);
- рестарт одного пода и удаление лидера: под возвращается sealed, `secrets-ok` проходит, после unseal узел снова в кластере; рестарт всех узлов: все sealed, новый под intake не стартует (init-контейнер повторяет вход, под Pending), после unseal двумя долями на каждом данные Raft на месте; потеря кворума;
- уже работающий `intake-long` не перезапускается ни на одном шаге;
- break-glass: `generate-root` одной долей не завершается, двумя выпускает токен (`-decode -otp`), запись есть в audit, токен отзывается.

Состояние (шифртекст ответа `init`) — в `${XDG_RUNTIME_DIR:-$HOME/.cache}/aegis-vault-dev/openbao-ha`, не в репозитории; долей и токенов на диске нет, в вывод они не попадают. Образы скачиваются на хосте по digest и загружаются в minikube.

Последний прогон 11.11.2026: OpenBao 2.7.2, Raft 3, Shamir 3/2 — 0 провалов. Замеренный полный рестарт (удаление всех трёх подов, unseal двумя долями на каждом, скриптом): кластер готов за 98 с, `secrets-ok` успешен через 122 с (время людей-держателей в бою добавится). Особенности 2.7.2, найденные на стенде: агент при недоступном сервере повторяет вход с backoff и не завершается (под Pending, intake не запущен); для HA-стенда агент ходит на сервис `openbao-active`; `sys/generate-root-token/*` требует токена; `sys/metrics` по умолчанию выключен; `podManagementPolicy: Parallel` обязателен (иначе при Shamir остальные поды не создаются).

Процедуры (в бою, вводит человек-держатель; доля читается с запросом или из stdin, не из argv):

- **Unseal узла:** две разные доли, `bao operator unseal` на каждом поде (через `kubectl exec -it` или `port-forward` и TLS с проверкой CA); после первой доли `progress 1/2`.
- **Смена держателя (rotate-keys):** `bao operator rotate-keys -init -key-shares=3 -key-threshold=2 -pgp-keys=<ключи нового состава>` токеном `bgi` (хранится зашифрованно у держателей, см. [§5](../../docs/02-security/identity-secrets-mvp-a.md#5-меры-по-vault-t-36)); затем двое текущих держателей по очереди вводят свои доли (`sys/rotate/root/update`, `key=-` через stdin); после второй доли выдаются 3 новые доли, зашифрованные PGP, старые перестают действовать. На стенде проверено: одна доля — progress 1/2 и не завершает, `bgi` отменить процедуру не может (403), вторая доля завершает. Незавершённая попытка пропадает при смене лидера.
- **Обновление подов (`OnDelete`):** по одному, начиная со standby; после удаления пода дождаться sealed, ввести две доли, убедиться в `list-peers` (3 voter) и только затем следующий под; лидер — последним.
- **Break-glass:** `bgi` запускает `bao operator generate-root -init`, двое держателей вводят доли (`sys/generate-root-token/update`, `key=-` через stdin), зашифрованный токен расшифровывается OTP (токен и OTP не передавать в argv); итоговый токен отзывается сразу после использования, в audit остаются записи `sys/generate-root-token`. `bgi` не может отменить начатую процедуру (нет `delete`).
- **Сверка перед вводом доли (обязательно для break-glass и смены держателя):** `bgi` может начать процедуру с чужими параметрами (чужие PGP-ключи или OTP, одна доля с порогом 1). Вводите долю только в попытку, начатую вами или подтверждённым по отдельному каналу инициатором, и перед вводом сверьте `-status`: `nonce`, для `rotate-keys` — New Shares 3, New Threshold 2 и отпечатки PGP ровно текущего состава. Расхождение — не вводить, сбросить попытку сменой лидера, сообщить Security ([§5](../../docs/02-security/identity-secrets-mvp-a.md#5-меры-по-vault-t-36)).
- **Потеря `bgi`** (истёк, утёк, утрачен): новый выдать нечем, пока не включены безтокенные эндпоинты. Процедура — в [§5](../../docs/02-security/identity-secrets-mvp-a.md#5-меры-по-vault-t-36) (PR с четырьмя глазами, временный `disable_unauthed_generate_root_endpoints = false`, рестарт с unseal, `generate-root`, новый `bgi`, возврат флага). Флаги `disable_unauthed_*` в боевых values не включать (CVE-2026-5807); тест `TestOpenBaoHANoUnauthedEndpoints` это проверяет. Адрес сервера для агента — сервис `openbao-active` (SAN сертификата должен его содержать), не основной `openbao`.

## Применение

Перед применением на рабочем Vault/OpenBao обязательно проверить на dev-экземпляре (`vault server -dev`): вход по тестовому токену ServiceAccount, чтение разрешённых путей, `permission denied` на остальных.

```sh
vault policy write aegis-intake policies/aegis-intake.json
vault write auth/kubernetes/role/aegis-intake @roles/aegis-intake.json
vault agent -config=agent/aegis-intake.json   # внутри init-контейнера пода
```

Применяет только CI-применитель после PR с четырьмя глазами; прямая запись политик людьми запрещена (RT-18). Расхождение живой конфигурации с Git ловит периодическая сверка `vault policy read aegis-intake`. Политика `aegis-audit-operator` описана в документе решения и здесь не хранится.
