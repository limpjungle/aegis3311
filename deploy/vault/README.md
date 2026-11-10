# Vault/OpenBao: политика, роль и конфигурация агента для intake

Решение и инвентаризация секретов — [identity-secrets-mvp-a.md](../../docs/02-security/identity-secrets-mvp-a.md). Каталог защищён правилом четырёх глаз (`deploy/`). Файлы — JSON: его принимают и Vault, и OpenBao. Тест `cmd/aegis-ci/secrets_inventory_test.go` проверяет их против инвентаризации и против кода.

| Файл | Что это |
|---|---|
| `policies/aegis-intake.json` | Политика: только `read` на точные пути KV v2 для intake |
| `roles/aegis-intake.json` | Роль Kubernetes auth: один ServiceAccount, один namespace, audience `vault`, TTL ≤ 5m / 10m |
| `agent/aegis-intake.json` | Vault Agent для init-контейнера: `exit_after_auth`, шаблоны с правами `0400`, без sink, listener, api_proxy и cache |

## Dev-стенд

`dev/run.sh openbao` или `dev/run.sh vault` поднимает minikube (профиль `aegis-vault-dev`, драйвер docker), ставит сервер Helm-чартом в dev-режиме (`dev/values-*.yaml`, версии чартов и digest образов закреплены), применяет политику, роль и конфигурацию агента из этого каталога и проверяет:

- под по фрагменту из [intake-deploy.md](../../docs/04-operations/intake-deploy.md) («Секреты: Vault Agent», `dev/pod-template.yaml`): все файлы `0400`, читаются под тем же `runAsUser` при `readOnlyRootFilesystem`, токенов Vault и SA в контейнере intake нет;
- нет ключа в секрете и нет пути в KV — init-контейнер падает по ожидаемой причине (ошибка конфигурации агента не засчитывается);
- токен роли `aegis-intake` читает только свои пути; запись в KV, `sys/policy`, роли auth, отключение secrets/auth/audit — `permission denied`; вход по токену с audience не `vault` отклоняется.

Dev-режим: in-memory, без TLS, root-токен `root`, секреты фиктивные; для стенда в конфигурации агента меняется только адрес сервера. Образы скачиваются на хосте по digest и загружаются в minikube (DNS внутри узла может не работать). kind не используется: на ядре 7.2 узел `kindest/node:v1.37.0` не поднимал control plane. `dev/run.sh down` удаляет стенд.

Последний прогон 10.11.2026: OpenBao 2.7.2 и Vault 2.0.4 — 0 провалов.

## Применение

Перед применением на рабочем Vault/OpenBao обязательно проверить на dev-экземпляре (`vault server -dev`): вход по тестовому токену ServiceAccount, чтение разрешённых путей, `permission denied` на остальных.

```sh
vault policy write aegis-intake policies/aegis-intake.json
vault write auth/kubernetes/role/aegis-intake @roles/aegis-intake.json
vault agent -config=agent/aegis-intake.json   # внутри init-контейнера пода
```

Применяет только CI-применитель после PR с четырьмя глазами; прямая запись политик людьми запрещена (RT-18). Расхождение живой конфигурации с Git ловит периодическая сверка `vault policy read aegis-intake`. Политика `aegis-audit-operator` описана в документе решения и здесь не хранится.
