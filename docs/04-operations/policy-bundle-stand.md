# Runbook: включение `policy_bundle.required: true` на стенде

> Статус: Этап 0a, MVP-A. Закрывает строку «`policy_bundle.required: true` у intake» в [stage-0a-status.md](../01-planning/stage-0a-status.md) (п. 3, T-24) и п. 7 [чек-листа включения](../07-governance/ci-four-eyes.md#чек-лист-включения). Поведение секции описано в [intake-deploy.md](intake-deploy.md) («Пример конфигурации», `policy_bundle`), порядок обновления — в [migrations.md](migrations.md) п. 8 (staging) и п. 10 (prod).

## Что должно получиться

На стенде работает `aegis-intake serve`, в секции `policy_bundle` стоит `required: true`, в журнале есть `policy_bundle_verified`. Негативная проверка показала, что с неподходящим bundle intake не стартует (код 2).

Начиная с этой сборки, в `prod-cloud-hybrid` и `prod-baremetal` без секции или с `required: false` intake не стартует на этапе разбора конфигурации. В `staging` включение идёт в два шага, а `required: true` держится только на конфиге.

## Предусловия

1. Определено `environment` стенда (`staging` или prod-окружение). От него зависит порядок шагов ниже.
2. Есть релиз `v*`, собранный из коммита main с этим изменением. Релиз `v0.1.0` собран раньше: секцию он понимает, но обязательности в prod не содержит. Для prod сначала выпустите новый `v*`.
3. Есть доступ к хосту или поду intake, к его конфигурации и журналу (stderr, JSON по строке на событие).
4. Ключ аудита intake и ключи kill switch отличаются от ключей bundle. Если они пересекаются, intake выходит с кодом 2 при любом `required`.

## Шаги

### 1. Артефакты из одного релиза

Бинарь и `policy-bundle.json` берутся из **одного** релиза `v*`: `release.yml` кладёт туда bundle, который подходит к содержимому этой сборки.

```
TAG=v0.1.1                      # релиз с этим изменением
gh release download "$TAG" -p aegis-intake -p policy-bundle.json -p SHA256SUMS -D /tmp/aegis-$TAG
cd /tmp/aegis-$TAG && sha256sum -c --ignore-missing SHA256SUMS
```

Провенанс и SBOM проверяются по [ci-four-eyes.md](../07-governance/ci-four-eyes.md) §9.

### 2. Проверка bundle до выкладки

Из рабочей копии репозитория на коммите тега:

```
git checkout "$TAG"
go run ./cmd/aegis-ci bundle verify -in /tmp/aegis-$TAG/policy-bundle.json -keys deploy/policy-bundle/keys.json
# bundle ok: sequence N, commit …, PR #…, одобрили …
```

Код 0 означает, что подпись и одобрения в порядке, а содержимое bundle совпадает с тем, что встроено в сборку из дерева тега. Поле `commit` может указывать на более ранний коммит с тем же содержимым политик, это нормально, поэтому `-commit` здесь не передаётся. Запишите `sequence`, `commit` и `PR` из вывода: они понадобятся в шаге 5. Если команда отказывает, на хост такой bundle не кладите.

### 3. Файлы на хосте

```
install -m 0644 /tmp/aegis-$TAG/policy-bundle.json /etc/aegis/policy-bundle.json
install -m 0644 deploy/policy-bundle/keys/ci-policy-signing.pub /etc/aegis/keys/ci-policy-signing.pub
install -m 0644 deploy/policy-bundle/keys/break-glass.pub      /etc/aegis/keys/break-glass.pub
```

Ключи берутся из `deploy/policy-bundle/keys/` того же коммита. Это открытые ключи, секретов среди них нет. Если intake работает в поде, положите те же файлы в ConfigMap или том, смонтированный по этим путям.

### 4. Секция в конфигурации

```json
"policy_bundle": {"path": "/etc/aegis/policy-bundle.json", "required": true,
  "keys": [{"path": "/etc/aegis/keys/ci-policy-signing.pub", "issuer": "ci/policy-signing"},
           {"path": "/etc/aegis/keys/break-glass.pub", "issuer": "ci/break-glass"}]}
```

- **Prod-окружение.** Сразу `required: true`. Порядок такой: сначала файлы и секция, потом новый бинарь ([migrations.md](migrations.md) п. 10). Без секции новый бинарь не запустится.
- **Staging.** Сначала `required: false`, перезапуск, затем шаг 5. Если в журнале `policy_bundle_verified`, поставьте `required: true` и перезапустите ещё раз.

### 5. Проверка журнала

После перезапуска `aegis-intake serve`:

```
# под: kubectl logs …; хост: journalctl -u … ; либо файл stderr
… | jq -c 'select(.msg | startswith("policy_bundle"))'
```

Ожидается ровно одна запись `policy_bundle_verified`, а `sequence`, `commit` и `pr` в ней совпадают с шагом 2. Записей `policy_bundle_missing` и `policy_bundle_unverified` быть не должно. Intake продолжает работать и принимает инциденты.

### 6. Негативная проверка (заодно готовит RT-11, [ci-four-eyes.md](../07-governance/ci-four-eyes.md) §10)

1. Временно укажите в `path` несуществующий файл и перезапустите. Ожидается код выхода 2 до приёма инцидентов, новых записей в цепочке аудита нет.
2. Только в prod-окружении: временно поставьте `required: false`. Ожидается код 2 с ошибкой конфигурации, в тексте упоминается `required` и T-24.
3. Верните рабочую конфигурацию и повторите шаг 5.

## Откат

- Staging: верните `required: false`, intake запустится с предупреждением `policy_bundle_unverified`.
- Prod: ослабить проверку конфигурацией нельзя. Положите подходящий bundle из того же релиза, что и бинарь, либо откатите бинарь вместе с его `policy-bundle.json`.

## Фиксация результата

В [stage-0a-status.md](../01-planning/stage-0a-status.md) зачеркните строку п. 3 таблицы блокеров с пометкой «Сделано ДД.ММ.ГГГГ: стенд `<environment>`, `required: true`, `policy_bundle_verified` (sequence N, commit …)». В строке п. 3 таблицы пунктов и в порядке работ оставьте только RT-11 и проверку бинарного релиза.
