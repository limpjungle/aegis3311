# Каталог действий (машиночитаемый)

Записи `actions/<name>.yaml` — источник истины для PEP. Человекочитаемое описание и обоснование — [docs/03-autonomy/action-catalog.md](../docs/03-autonomy/action-catalog.md).

## Формат

Поля как в §1 action-catalog.md, с отличиями ради машинной обработки:

- `targets.kinds` — всегда список; `targets: {same_as: <действие>}` берёт цели у другой записи (ссылку разрешает загрузчик, цикл — ошибка);
- предусловия и проверки постусловий — объекты `{id, description}`;
- параметры: `chosen_by: model` (выбирает LLM, нужен `enum`) или `chosen_by: catalog` (вычисляет код);
- величину вычисляет Go-правило: `step: [{param, when?, rule, expr}]`, границы — `bounds.rule`. Формулы в YAML **не интерпретируются**, `expr`, `minimum`, `maximum` — текст для ревью;
- правила шага зеркалят `eval/golden-synthetic/generate.py`; расхождение ловит `TestGoldenSetCrossCheck`;
- инварианты проверяет `Catalog.Validate` (lease обязателен, `error_budget_exhausted: allowed` и `degraded_mode: allowed` только у R1, у R3 — `forbidden` и `frozen` и т. д.).

## Ревью

Процесс — §4 action-catalog.md: владелец домена и SRE-лид; новое действие стартует с L0; изменение каталога меняет `catalog_digest` в вердиктах PEP.

## Проверка

```
go test ./internal/catalog ./internal/step ./internal/pep
```
