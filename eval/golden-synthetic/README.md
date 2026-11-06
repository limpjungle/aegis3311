# Синтетический golden-набор AegisOps (MVP)

Описание, назначение и правила использования — [docs/05-testing/golden-set.md](../../docs/05-testing/golden-set.md).

## Файлы

| Файл | Назначение |
|---|---|
| `generate.py` | Детерминированный генератор кейсов (только стандартная библиотека Python) |
| `score.py` | Подсчёт метрик по ответам модели, с 95%-ми ДИ Уилсона |
| `selftest.py` | Самопроверка генератора и скоринга |
| `run.py` | Раннер: прогоняет набор через OpenRouter и пишет ответы в формате `score.py` (только стандартная библиотека) |
| `profiles.json` | Модель, параметры генерации, бюджеты, ретраи и профили endpoint'ов |
| `test_run.py` | Тесты раннера (`unittest`, mock-сервер на 127.0.0.1, без сети) |
| `schema/answer.schema-v2.json` | JSON Schema ответа модели, формат v2 (активная) — для structured outputs |
| `schema/answer.schema.json` | Схема формата v1, хранится для истории |
| `prompt/system-v3.md` | Системный промпт для формата v2 (активный, с 06.11.2026; какой промпт активен — указано в `data/manifest.json`) |
| `prompt/system-v2.md` | Промпт формата v1, хранится для истории |
| `prompt/system-v1.md` | Предыдущая версия промпта, хранится для истории (`prompt_history` в manifest) |
| `data/probe-v2.jsonl` | Набор для ежедневной пробы и eval endpoint'ов, формат v2 (480 кейсов, активный) |
| `data/dev-v2.jsonl` | Отдельный набор для отладки промптов, формат v2 (113 кейсов, другой seed) |
| `data/probe-v1.jsonl`, `data/dev-v1.jsonl` | Те же кейсы в формате v1 (величину выбирала модель), хранятся для истории |
| `test_format_v2.py` | Тесты формата v2, правил шага и метрики `decision_agreement` |
| `data/manifest.json` | Версии, seed'ы и SHA-256 наборов и промпта |

## Команды

```bash
python3 selftest.py                                        # проверка генератора и скоринга
python3 generate.py --set probe --out data/probe-v2.jsonl  # пересоздать набор v2 (хеш должен совпасть с manifest.json)
python3 generate.py --set probe --format v1 --out /tmp/p1.jsonl  # воспроизвести набор v1 байт в байт
python3 score.py --cases data/probe-v2.jsonl --pred predictions.jsonl --ref reference.jsonl --out report.json  # decision_agreement — основная метрика пробы
```

## Запуск раннера

```bash
python3 run.py --profile inceptron-fp8 --set probe --dry-run          # без сети и ключа: тело запроса, оценка токенов и стоимости
export OPENROUTER_API_KEY=...                                              # только через окружение (или OPENROUTER_API_KEY_FILE)
python3 run.py --profile inceptron-fp8 --set dev --limit 10           # небольшой пробный прогон
python3 run.py --profile inceptron-fp8 --set probe                    # -> runs/<profile>/probe-<run_id>.jsonl (+ .meta.json)
python3 run.py --profile inceptron-fp8 --set probe --resume runs/inceptron-fp8/probe-<run_id>.jsonl
python3 run.py --profile inceptron-fp8 --set probe --reference        # эталон -> refs/<profile>/probe-v2-<дата>-<run_id>.jsonl (версия — из файла набора), 0444
python3 -B -m unittest -v test_format_v2 test_run test_run_audit test_run_fixes  # все тесты (без сети)
```

Коды выхода: 0 — все кейсы получили окончательный ответ; 2 — отказ (конфиг, целостность, безопасность, нет ключа, файл существует);
3 — прогон прерван (бюджет, провайдер не совпал, 401/402/403/404); 4 — есть неокончательные ошибки, нужен `--resume`.

Каждый запрос несёт `zdr: true`, `data_collection: deny`, `allow_fallbacks: false` и `require_parameters: true`; раннер не отправляет
ничего, если профиль или готовое тело запроса этого не содержит, а URL API не равен `https://openrouter.ai/api/v1/chat/completions`
(для тестов допустим `http://127.0.0.1:...`). Перед разбором ответа сверяется поле `provider`; несовпадение останавливает прогон.
Потолок контекста — 64 000 токенов, бюджет по умолчанию — 2 USD на прогон (поднят с 1 USD 06.11.2026) (`--max-usd`/`--max-tokens-total` могут его только уменьшить).

`--resume` сверяет с исходным прогоном профиль, модель, `generation`, набор ID и хеши набора, промпта, схемы, `profiles.json` (`config`) и `run.py` (`runner`).
Поэтому после правки `run.py` или `profiles.json` старый прогон продолжить нельзя (`ConfigError`, exit 2): начните новый.

Профиль `wafer-nvfp4`: OpenRouter не позволяет подтвердить тег endpoint'а (`wafer/us` или `wafer/nvfp4`) в ответе, поэтому закреплены
провайдер и квантование; `endpoint_label` — утверждённый резервный `wafer/us`, а цены для бюджета взяты по худшему из двух endpoint'ов
($0,054 / $0,20 за 1M токенов). Профили (поле `role` в `profiles.json`): `inceptron-fp8` — основной (Inceptron, `inceptron/fp8`, с 06.11.2026), `wafer-nvfp4` — резерв,
`open-inference-fp4` — выведен 06.11.2026 по результатам eval на `probe` и оставлен только для воспроизведения сравнения
(для эталона и ежедневной пробы его не использовать). Профиль без заполненных `only`, `endpoint_label`, `expected_provider_names`
и цен раннер запускать откажется. Худшая оценка стоимости `probe` на Inceptron — ≈ $1,25 (при `max_tokens` на каждом кейсе), фактическая — ≈ $0,48;
бюджет на прогон поднят до $2 06.11.2026, чтобы эталон не останавливался на середине.

Тесты не ходят в сеть: используются mock-сервер на `127.0.0.1` и поддельный транспорт; обращение к любому другому хосту в тестах — ошибка.

### Выходные файлы раннера

`<out>.jsonl` — одна строка на попытку обработки кейса, только дозапись; для `score.py` важны `id`, `answer`, `error`. Поля:
`id, endpoint, answer, error, final, status` (`ok | schema_invalid | invalid_json | truncated | refusal | content_filter | provider_mismatch | http_error | transport_error | context_ceiling | context_ceiling_actual | budget_skipped`),
`schema_errors, run_id, profile, model_requested, model_reported, provider_actual, generation_id, usage, cost_usd, charged_tokens, est_input_tokens,
latency_ms, latency_total_ms, attempts, http_status, finish_reason, request_sha256, raw_content, ts`.
`final: false` — кейс будет отправлен заново при `--resume`; при дубликатах id `score.py` берёт последнюю строку.
`<out>.meta.json` — паспорт прогона (профиль, хеши набора/промпта/схемы/раннера/конфига, итоги, `providers_seen`, статус, причина прерывания).
Эталон после успешного завершения сжимается до одной строки на id и становится доступным только для чтения.

## Формат ответов для `score.py`

Одна строка JSONL на кейс:

```json
{"id": "GS-probe-RB-001-pool_undersized-050", "endpoint": "inceptron/fp8", "answer": { ... }, "error": null}
```

`answer` — объект по `schema/answer.schema.json` или `null`, если модель не ответила (тогда в `error` — причина). Отсутствующие и невалидные ответы засчитываются как неверные по всем метрикам.

## Правило для раннера

Модели отправляется **только поле `input`** кейса. Поля `id`, `variant`, `slice`, `meta` и `expected` содержат ответ и в запрос не попадают.
