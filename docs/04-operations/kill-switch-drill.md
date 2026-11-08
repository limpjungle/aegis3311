# Runbook: учение kill switch (gate G0)

> Статус: Этап 0a, MVP-A. Устройство — [architecture.md](../00-overview/architecture.md) §2.2, развёртывание — [intake-deploy.md](intake-deploy.md) («Kill switch»), угроза — T-22 в [threat-model.md](../02-security/threat-model.md). Критерий G0 — [gates.md](../07-governance/gates.md): замерено время остановки всех изменяющих действий, включая out-of-band путь.

## Роли ([RACI](../07-governance/raci.md))

| Роль | Кто | Что делает на учении |
|---|---|---|
| Оператор платформы (R) | Дежурный `oncall-1` | Активирует остановки (`stop`), готовит `release`, ведёт протокол |
| SRE-лид (A) | Дежурный `oncall-2` | Второй ключ при снятии (`cosign -publish`), утверждает результат |
| Владелец сервиса (C) | Представитель тестового сервиса | Подтверждает, что тестовый алерт не затрагивает прод |
| Security (C) | — | Проверяет упражнения 5–7 (пороги подписей, подавление) |
| Аудитор (I) | — | Получает `aegis-audit verify` и таблицу результатов |

## Предусловия

1. Стенд — `staging` либо прод с тестовым сервисом в реестре intake; `kill_switch.cluster` совпадает с кластером стенда.
2. **TTL run на учении — 5 минут** (`release -ttl 5m`, `renew.ttl` в конфигурации CLI `5m`, `renew.slot` `1m` либо ручной запуск); боевой TTL — 6 часов.
3. `aegis-killswitch status -config ks.json -cluster CLUSTER` зелёный: оба канала `fresh`, `confirmation: oncall` либо `renewer`, `stopped: false`.
4. NTP на хостах дежурных, renewer и intake (`latency_ms` и свежесть зависят от часов; допуск `max_skew` 2 мин).
5. У дежурных и renewer есть: ключи подписи, файлы `AEGIS_KILLSWITCH_KUBE_TOKEN_FILE`, `AEGIS_KILLSWITCH_S3_ACCESS_KEY_ID_FILE`, `AEGIS_KILLSWITCH_S3_SECRET_KEY_FILE`, конфигурация CLI `ks.json`.
6. Тестовый алерт, который intake берёт в работу (метки `namespace`, `service` из реестра), можно поднять и погасить по требованию.
7. `aegis-intake` работает, журнал (`stderr`) и цепочка аудита доступны.
8. Bootstrap пройден (упражнение 0), подключены `/metrics` intake (`metrics_listen`) и `aegis-killswitch check` во внешнем стеке мониторинга ([intake-deploy.md](intake-deploy.md), «Kill switch», шаг 7): после каждого `stop` проверяйте не только событие в цепочке, но и `check` (`stopped`/`reason`) и `aegis_intake_killswitch_stopped` — три источника должны сойтись.

Фиксация времени: перед каждым упражнением запишите время публикации (UTC, до секунды). После — `latency_ms` из события цепочки:

```
aegis-audit verify -chain CHAIN -pub AUDIT.pub -id CHAIN_ID
jq -c 'select(.record.schema=="aegisops/killswitch-event/v1")|.record' CHAIN | tail -5
```

Для каждого упражнения проверяется запись о тестовом алерте: `llm.mode=off`, `llm.reason=mode_off`, `model=null`, `intake.sources` заполнен (сбор продолжался), `kill_switch.state` соответствует остановке.

## Упражнения

**0. Bootstrap (новая цепочка или стенд без истории).** Проводится на чистой цепочке до остальных упражнений.
1. Подготовьте `release` двумя дежурными **до** старта intake и опубликуйте его в оба канала (свежий run с `issued_at` раньше будущего старта).
2. Запустите intake. Ожидается событие `kill_switch_engaged` с `bootstrap=true`, `from=none`, `stop_watermark` ≈ время старта; журнал `kill_switch_bootstrap`; в `/metrics` `aegis_intake_killswitch_bootstrap_awaiting_release 1`, `aegis_intake_killswitch_stopped 1`, `reason=no_confirmation`. Тестовый алерт даёт запись `llm.mode=off`: release, выпущенный до старта, **не действует** (проверка защиты от повтора старого документа).
3. Подготовьте новый release (`release`, затем `cosign -publish`) уже после старта: `issued_at` позже `stop_watermark`. Ожидается `kill_switch_released`, `from=stopped`, `bootstrap_awaiting_release 0`, `check` — `ok`; алерт снова даёт `hybrid`.
4. Рестарт intake: повторного bootstrap нет (в цепочке есть `stop_watermark`).

**1. Остановка по кластеру только во внешнем канале (out-of-band).**
`aegis-killswitch stop -config ks.json -key oncall-1.pem -cluster CLUSTER -channels oob`. Ожидается: на ближайшем опросе (≤ 10 с + таймаут чтения) событие `kill_switch_engaged`, `state.reason=cluster`, `channels[oob]` — `fresh/stop`, `channels[configmap]` — не остановка. Поднять тестовый алерт: запись `llm.mode=off`.

**2. Остановка только в ConfigMap (in-band).** Сначала снять (упражнение 5). Затем `stop ... -cluster CLUSTER -channels configmap`. Ожидания те же, канал `configmap`.

**3. Глобальная остановка в оба канала.** `stop -key oncall-1.pem -global`. Ожидается `state.reason=global`, `read_back_match=true` в выводе по обоим каналам, остановка всех intake, читающих эти каналы.

**4. Запрет типа действия.** Документ в каналах — полное состояние: он заменяет предыдущий. Поэтому `stop -action workload.restart` одной подписью **останавливает intake по `no_confirmation`** (у одноподписного action-документа нет подтверждения «не остановлен»; то же верно для `stop -cluster` чужого кластера одной подписью). Рабочий путь, который оставляет LLM в `hybrid`: первый дежурный `stop -key oncall-1.pem -action workload.restart -ttl 5m -out action.json`, второй `cosign -key oncall-2.pem -in action.json -publish` (две подписи oncall: ограничение и подтверждение). Ожидается: `llm.mode=hybrid`, в вердикте PEP для `workload.restart` причина `kill_switch` (cap L1), `state.actions=["workload.restart"]`. Дополнительно зафиксируйте одноподписный вариант: остановка с `reason=no_confirmation`.

**5. Снятие двумя ключами.**
1. `release -key oncall-1.pem -ttl 5m -out release.json` — ничего не публикуется (проверить: статус каналов не изменился).
2. Передать `release.json` второму дежурному. `cosign -key oncall-1.pem -in release.json -publish` тем же ключом — **отказ** (код 1). `publish -in release.json` с одной подписью — **отказ**.
3. Второй дежурный: `cosign -key oncall-2.pem -in release.json -publish` — публикация в оба канала, `read_back_match=true`. Сводка в stderr (эффект, `issued_at`, ttl, подписанты, `content_sha256`) сверяется голосом с первым дежурным.
4. Ожидается `kill_switch_released`, `from=stopped`; тестовый алерт снова даёт `llm.mode=hybrid`.
5. Публикуйте release **в оба канала**: release в один канал не снимает stop, лежащий в другом (любой свежий stop держит остановку). `publish`/`cosign -publish` отказывают, если канал не читается или в нём stop не старше release.
6. Release старше последнего stop (подготовлен до `stop`) — `publish` отказывает с подсказкой подготовить новый.

**6. Подавление остановки.**
a) Подавление ответом канала: запишите в ConfigMap мусор (или документ с неверной подписью) и запретите чтение объекта политикой bucket (ответ 403). Канал отвечает, но валидного документа нет — кэш сбрасывается сразу, подтверждения нет, цель останавливается (`no_confirmation`) на ближайшем опросе; в журнале `kill_switch_channel` с классом (`invalid`, `bad_signature`, `http_403`). Затем восстановите каналы релизом (упр. 5).
b) Только транспорт: закройте от intake оба канала (сетевая политика) — подтверждение сохраняется в кэше **не дольше TTL** (5 мин на учении), затем `no_confirmation` и `llm.mode=off`. Зафиксировать момент истечения и время события.

**7. Продление.**
1. При действующем stop `aegis-killswitch renew -key renewer-a.pem` — **отказ** (код 1), `renew -key renewer-b.pem` — отказ.
2. Снять остановку (упр. 5). Затем `renew -key renewer-a.pem` — `waiting_peer` (подпись сохранена в `renew/<слот>/`), состояние intake не меняется. `renew -key renewer-b.pem` — `published`; повтор любым — `up_to_date`.
3. Остановить renewer и дождаться трети TTL: в журнале intake `kill_switch_confirmation_expiring`; по истечении TTL — `no_confirmation`. Параллельно наблюдайте мониторинг: `check` уходит в `warning` (возраст подтверждения больше `-warn-age`; на учении задайте `-warn-age`/`-crit-left` под TTL 5 м, например `-warn-age 3m -crit-left 2m`), затем в `critical`; у intake `aegis_intake_killswitch_liveness_confirmed` падает в 0 по истечении подтверждения, срабатывают `KillSwitchRenewalMissed`/`KillSwitchConfirmationExpiring`. Вывод `renew` показывает `peers`: `missing` — коллега ещё не подписал, `http_403` — нет прав на чтение подписи.

**8. Stop из будущего (рассинхрон часов).** На машине дежурного сдвиньте часы на +10 минут (или `stop` с готовым документом, подписанным заранее) и опубликуйте `stop -cluster CLUSTER`. Ожидается: stop **применяется** (intake остановлен, `reason=cluster`), в журнале событие с `future_trigger=true`, `latency_ms` отрицательный; `stop_watermark` не изменился, документ канала в `check` помечен `future`. Затем `release` с нормальными часами: если `issued_at` релиза не новее будущего stop, `publish` не откажет, а напечатает предупреждение «stop … из будущего» — release снимает остановку, потому что W не сдвинут. Документ с `issued_at` дальше 24 часов в будущем отбрасывается целиком (остановки нет, канал с ошибкой `future`).

## Результаты

| № | Упражнение | Время публикации (UTC) | Время события `applied_at` | `latency_ms` | Критерий | Итог |
|---|---|---|---|---|---|---|
| 1 | stop, кластер, oob | | | | ≤ poll + timeout (≈ 15 с) | |
| 2 | stop, кластер, configmap | | | | то же | |
| 3 | stop, global, оба канала | | | | то же | |
| 4 | действие `workload.restart` | | | — | cap `kill_switch`, LLM работает | |
| 5 | снятие двумя ключами | | | | `released`, один ключ/одна подпись отказ | |
| 6a | подавление: порча + deny | | | | остановка на ближайшем опросе | |
| 6b | подавление: только транспорт | | | | остановка не позже TTL | |
| 7 | продление, отказ при stop | | | — | отказ; `waiting_peer` → `published`; check `warning` → `critical` | |
| 0 | bootstrap | | | — | release до старта не действует; после старта снимает | |
| 8 | stop из будущего | | | отрицательный | применён, W не сдвинут, release снимает | |

**Критерий G0:** остановка (упражнения 1–3) — не позже `poll_interval + request_timeout` (по умолчанию 10 с + 5 с) после публикации в любом из каналов; для 6b — не позже TTL. `latency_ms` на отдельных intake может превышать критерий при рассинхроне часов — сначала проверьте NTP.

## Запасные пути

- Часы дежурного: на машине дежурного обязателен NTP. `stop` с `issued_at` в будущем дальше `max_skew` (2 мин), но не дальше 24 часов, intake применяет, не сдвигая водяные знаки; дальше 24 часов — отбрасывает целиком (остановка не сработает); проверьте `date -u` перед публикацией.
- Нет CLI или ключей-файлов: `aegis-killswitch stop ... -out stop.json` на офлайн-машине, затем `kubectl apply` (ConfigMap `kill-switch`, ключ `document` — байты файла) либо загрузка файла в объект `kill-switch.json` через консоль хранилища. Документ подписан заранее, права на запись нужны только на канал.
- Один канал недоступен: публикуйте с `-channels` исправного; остановка действует по любому свежему stop.
- Intake не реагирует: проверьте журнал (`kill_switch_channel` с классом), `aegis-killswitch status`, часы и `max_skew`.
