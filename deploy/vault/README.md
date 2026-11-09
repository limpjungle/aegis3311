# Vault/OpenBao: политика, роль и конфигурация агента для intake

Решение и инвентаризация секретов — [identity-secrets-mvp-a.md](../../docs/02-security/identity-secrets-mvp-a.md). Каталог защищён правилом четырёх глаз (`deploy/`). Файлы — JSON: его принимают и Vault, и OpenBao. Тест `cmd/aegis-ci/secrets_inventory_test.go` проверяет их против инвентаризации и против кода.

| Файл | Что это |
|---|---|
| `policies/aegis-intake.json` | Политика: только `read` на точные пути KV v2 для intake |
| `roles/aegis-intake.json` | Роль Kubernetes auth: один ServiceAccount, один namespace, audience `vault`, TTL ≤ 5m / 10m |
| `agent/aegis-intake.json` | Vault Agent для init-контейнера: `exit_after_auth`, шаблоны с правами `0400`, без sink, listener, api_proxy и cache |

## Применение

Перед применением на рабочем Vault/OpenBao обязательно проверить на dev-экземпляре (`vault server -dev`): вход по тестовому токену ServiceAccount, чтение разрешённых путей, `permission denied` на остальных.

```sh
vault policy write aegis-intake policies/aegis-intake.json
vault write auth/kubernetes/role/aegis-intake @roles/aegis-intake.json
vault agent -config=agent/aegis-intake.json   # внутри init-контейнера пода
```

Применяет только CI-применитель после PR с четырьмя глазами; прямая запись политик людьми запрещена (RT-18). Расхождение живой конфигурации с Git ловит периодическая сверка `vault policy read aegis-intake`. Политика `aegis-audit-operator` описана в документе решения и здесь не хранится.
