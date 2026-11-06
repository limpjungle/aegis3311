# Политики OPA/Rego

- `aegis/autonomy/matrix.rego` — матрица автономности (architecture.md §4.4), запрещённые имена действий, самопроверка инвариантов (prod не выше staging, R3 не выше L1);
- `aegis/pep/guards.rego` — запреты (`deny`) и понижения уровня (`caps`): kill switch, подтверждение «не остановлен», error budget, деградационный режим, lease, человек в инциденте, circuit breaker, rate limit, cooldown;
- `aegis/pep/decision.rego` — итог `data.aegis.pep.decision`: определён всегда, при любой аномалии входа — `deny` и `L0`.

Форма и величина действия (каталог, границы, цель) проверяются в Go; политика получает нужные поля каталога во входе и не дублирует арифметику.

## Ревью

Изменения идут через PR с тестами `*_test.rego` (владелец домена + SRE-лид). Изменение любого не-тестового `.rego` меняет `policy_bundle_digest`. Список `forbidden_patterns` должен совпадать с `catalog.ForbiddenPatterns` (`TestForbiddenPatternsSync`).

## Проверка

```
go test ./internal/policyengine                                   # Rego-тесты через tester + строгая компиляция
go run github.com/open-policy-agent/opa@v1.22.2 test policy -v    # CLI без установки
go run github.com/open-policy-agent/opa@v1.22.2 check --strict policy
```

## Dry-run PEP

```
go run ./cmd/aegis-pep dry-run < {"proposal": <action из ответа v2>, "context": {...}}
```
