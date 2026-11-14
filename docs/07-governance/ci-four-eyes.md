# CI, четыре глаза и подписанный policy bundle

> Статус: Этап 0a, MVP-A. Закрывает механизмами T-24 (инсайдер меняет политику, каталог, матрицу или реестр LLM) и подпись артефактов платформы ([stage-0a-status.md](../01-planning/stage-0a-status.md) п. 3 и 8). **Пока угроза T-24 не закрыта:** правила GitHub применены, ключ создан, [genesis-bundle](https://github.com/limpjungle/aegis3311/releases/tag/policy-bundle-1) и [второй bundle](https://github.com/limpjungle/aegis3311/releases/tag/policy-bundle-2) опубликованы. До shadow остаются включение `policy_bundle.required: true` на стенде (в prod-окружениях оно обязательно сборкой) и RT-11 по [чек-листу](#чек-лист-включения).

Сводка рисков, допущений и непроверенного в бою — [ci-four-eyes-risks.md](ci-four-eyes-risks.md).

Репозиторий `limpjungle/aegis3311` публичный и личный (владелец — пользователь, не организация): команд нет, в CODEOWNERS только логины, одобрения засчитываются только от пользователей с правом write. Rulesets, environments с обязательными ревьюерами и artifact attestations доступны бесплатно.

## 1. Что защищаем

Решения агента определяет не только Rego. Защищённые пути ([`.github/four-eyes.json`](../../.github/four-eyes.json)):

| Что | Пути |
|---|---|
| Данные, которые агент встраивает в бинарь | `policy/`, `catalog/`, `eval/golden-synthetic/` (реестр LLM `profiles.json`, промпт, схема ответа, `data/manifest.json`, `assets.go`) |
| Код, определяющий решения | `internal/pep/`, `policyengine/`, `catalog/`, `step/`, `dataclass/`, `masker/`, `openrouter/`, `routersvc/`, `routerstate/`, `llmrouter/`, `killswitch/`, `audit/`, `intake/`, `pyjson/`, `strictjson/`, `digest/`, `promtext/`; все исполняемые `cmd/aegis-*/` (intake, pep, llmrouter, audit, killswitch) |
| Сама защита и сборка | `internal/bundle/`, `internal/foureyes/`, `internal/sbom/`, `cmd/aegis-ci/`, `.github/`, `deploy/`, `go.mod`, `go.sum`, `scripts/pin-actions.sh` |
| Документы с нормативным значением | `docs/03-autonomy/`, `docs/02-security/data-classes.md`, `docs/02-security/identity-secrets-mvp-a.md` |

Весь код и встраиваемые файлы, попадающие в бинари, защищены; это проверяет `TestBuildDepsProtected` (`cmd/aegis-ci/protected_deps_test.go`: `go list -deps` для `cmd/aegis-*` под linux/amd64 плюс листинг каталогов пакетов). В `eval/golden-synthetic/` правила заданы точными путями (glob в правилах нет, каталог целиком не защищён из-за `require: security` у `profiles.json` и частых коммитов эталонов). Новый файл сборки там требует правила в four-eyes.json и CODEOWNERS в том же PR, иначе красная проверка `go`. Остаточный риск: при обходе ruleset'а администратором файл без правила пройдёт с `changed=false` (риск 2). Python-тесты eval и прочие документы не защищены.

Для `internal/dataclass/`, `internal/masker/`, `eval/golden-synthetic/profiles.json`, `docs/02-security/data-classes.md` и `docs/02-security/identity-secrets-mvp-a.md` обязательно одобрение группы `security` (`require`).

## 2. Три слоя

**(а) Ruleset на main** ([rulesets/main.json](rulesets/main.json)): два одобрения, обязательное ревью владельцев кода (CODEOWNERS), сброс одобрений при новом push, одобрение после последнего push, разрешение обсуждений, только squash-merge, линейная история, обязательные проверки `go`, `race`, `eval`, `four-eyes` на актуальной базе, `bypass_actors: []`. Ruleset защищает от случайности и от обычных прав; администратор его отключить может (§7).

**(б) Правило групп.** GitHub считает «два одобрения», но не знает, что они должны быть из разных групп и что автор или соавтор не может одобрять. Это делает `aegis-ci foureyes` ([four-eyes.yml](../../.github/workflows/four-eyes.yml)) по `.github/four-eyes.json`: проверка `four-eyes` обязательна для PR. Это ранний отказ и удобство. **Доверия к нему нет:** код проверяющего берётся из самого PR, и его можно изменить в этом PR.

**(в) Источник доверия — подпись bundle на main.** [policy-bundle.yml](../../.github/workflows/policy-bundle.yml) срабатывает на каждый push в main и заново, по правилам и коду из коммита предыдущего подписанного bundle, проверяет одобрения слитого PR и цепочку коммитов. Только после этого job `sign` в environment `policy-signing` (обязательный ревьюер, запрет самоодобрения, только ветка main; ключ — секрет environment) подписывает манифест. Проверяющий (`aegis-ci`) для подписи **собирается из коммита предыдущего bundle (B0)** и запускается против дерева проверяемого коммита S: изменение кода проверки в S (в том числе в `cmd/aegis-ci`, `internal/foureyes`, `internal/bundle`) на проверку S не влияет. Файлы workflow, напротив, берутся из S. Поэтому при обходе ruleset'а администратором, который может изменить и сам `policy-bundle.yml`, сборка проверяющего из B0 не защищает: единственный барьер — ручное подтверждение ревьюером environment `policy-signing` (плюс публичная запись Rekor через attestation, плюс KMS на этапе 1). Обход без подписи оставляет коммит без bundle: релиз из него не собирается ([release.yml](../../.github/workflows/release.yml)), а у агента с `required: true` такой бинарь не стартует. Для genesis предыдущего bundle нет, и проверяющий собирается из S (неизбежно; genesis делается вручную, §5). Коммит B0 берётся из релиза, но принимается только после привязки к истории main и к тегу (§5, п. 0).

**Теги.** `rulesets/tags.json` запрещает обновление и удаление тегов `v*` и `policy-bundle-*`, но **не** запрещает создание: при `bypass_actors: []` правило `creation` остановило бы и сам workflow (релиз создаёт тег от `GITHUB_TOKEN`), а ограничить создание тегов только Actions в личном репозитории нельзя (не подтверждено: проверить при применении настроек). Поэтому защита от подделанных релизов и тегов — не ruleset, а привязка B0 к main (§5, п. 0) и проверка подписи ключами из B0.

**Инструкция ревьюеру environment `policy-signing`.** Перед подтверждением откройте сводку job'а `plan`: он печатает `git diff --stat B0 S -- .github cmd/aegis-ci internal/foureyes internal/bundle`. Подтверждайте, только если эти пути не менялись в коммите S без отдельного PR с четырьмя глазами. Проверка вручную: `git diff --stat <B0> <S> -- .github cmd/aegis-ci internal/foureyes internal/bundle` (B0 — поле `commit` в `policy-bundle.json` последнего релиза `policy-bundle-N`). Сомневаетесь в коммите — отклоняйте запуск: подпись не будет выпущена, цепочка чинится по §5.

## 3. Правило групп

[`.github/four-eyes.json`](../../.github/four-eyes.json):

```json
{"schema":"aegisops/four-eyes/v1","min_approvals":2,"min_groups":2,
 "groups":{"policy-owners":["limpjungle"],"sre-leads":["limpjungle"],"security":["limpjungle"]},
 "excluded":["dependabot[bot]","github-actions[bot]","aegis-agent[bot]"],
 "protected":[{"path":"policy/","groups":["policy-owners","sre-leads","security"],"require":[]},
              {"path":"eval/golden-synthetic/profiles.json","groups":["policy-owners","sre-leads","security"],"require":["security"]}]}
```

(сокращено; полный список путей — в файле). `path` — каталог с завершающим `/` или точный файл, без glob и без пересечений (проверяет `foureyes.Load`). Одно правило на `.github/` покрывает и сам `four-eyes.json`, и `CODEOWNERS`, и workflow.

Одобрение засчитывается, если: последнее ревью человека — `APPROVED` (учитываются `APPROVED`, `CHANGES_REQUESTED`, `DISMISSED`; `COMMENTED` игнорируется), оно дано на текущий head PR, пользователь — `User`, не автор PR, не из `excluded`, не автор и не коммиттер ни одного коммита PR и входит в группу, допустимую для **всех** затронутых правил. Нужно не меньше `min_approvals` разных людей, которых можно назначить в `min_groups` разных групп так, чтобы покрыть все группы из `require`; действующий `CHANGES_REQUESTED` от члена допустимой группы — отказ.

Группы и роли ([raci.md](raci.md) §4): `policy-owners` — оператор платформы, `sre-leads` — SRE-лид, `security` — security. Ревьюер environment `policy-signing` — отдельный человек (security или SRE-лид), не автор слияния. Identity агента (`aegis-agent[bot]`) в `excluded` и ни в одной группе.

**Состав групп (09.11.2026):** `policy-owners` — `limpjungle` (SRE-лид, он же пока оператор платформы); `sre-leads` — `limpjungle`, `Oltix146`; `security` — `trix13371`. У всех троих право write подтверждено, в CODEOWNERS все три логина. Автор PR одобрять не может; два одобрения из двух разных групп набираются при любом авторе: PR от `limpjungle` — `Oltix146` (sre-leads) и `trix13371` (security); PR от `Oltix146` — `limpjungle` и `trix13371`; PR от `trix13371` — `limpjungle` (policy-owners) и `Oltix146` (sre-leads). Для путей с `require: security` (`profiles.json`, `dataclass/`, `masker/`, `data-classes.md`, `identity-secrets-mvp-a.md`) обязательно одобрение `trix13371`, поэтому PR от него в эти пути не сливается — нужен второй участник `security`.

## 4. Policy bundle

Формат `aegisops/policy-bundle/v1` ([`internal/bundle`](../../internal/bundle/manifest.go)), канонический JSON (`pyjson.Canonical`), публикуется как `policy-bundle.json` в релизе `policy-bundle-N`:

| Поле | Смысл |
|---|---|
| `sequence` | Монотонный номер, 1 у genesis |
| `repository`, `commit`, `prev_commit` | Репозиторий, коммит main, коммит предыдущего bundle (`null` только при `sequence` 1) |
| `files[]` | Все встроенные в бинарь файлы: путь от корня репозитория и sha256 |
| `digests` | `policy_bundle_digest` (как в вердикте PEP), `catalog_digest`, `llm_assets_digest` |
| `approvals` | PR, автор, `head_sha`, одобрившие (логин, группа, id ревью) |
| `signatures[]` | От 1 до 4: `key_id`, `issuer`, `sig` (ed25519) |

Подписывается сообщение `схема \0 канонический манифест без подписей \0 key_id \0 issuer`. Проверка (`bundle.Verify`): строгий разбор (неизвестные поля, дубли ключей и `null` вместо массива — отказ), структура, **каждая** подпись известна и валидна (запятнанный bundle отвергается целиком), одобрения: не меньше двух разных логинов (без учёта регистра), никто не автор, не меньше двух групп. Затем `Verified.Matches` сверяет файлы и дайджесты с содержимым, встроенным в бинарь (или лежащим на диске при подписи).

Bundle покрывает **данные**, а не код: код, определяющий решения, защищён ruleset'ом, правилом групп, цепочкой (§5) и провенансом бинаря (§9).

Ключ подписи — ed25519, как у kill switch (офлайн, stdlib, без Sigstore на стороне агента). Прозрачность даёт провенанс `actions/attest-build-provenance` на `policy-bundle.json` (keyless, Rekor). Ключ лежит в секрете environment; KMS — этап 1 (T-23). Открытый ключ — в [`deploy/policy-bundle/keys.json`](../../deploy/policy-bundle/keys.json) (массив `{path, issuer}`, пути относительно файла; сейчас пуст, и `plan`/`release` честно падают с «нет ключей подписи»).

## 5. Цепочка B0 → S

`aegis-ci bundle plan` для коммита S на main (бинарь `aegis-ci` собран из коммита B0, дерево — S):

0. **Привязка B0 к main до любого кода из B0 или S** (только `git` и `jq` в workflow, шаг «Привязка B0 к main и к тегу»). Релиз и тег `policy-bundle-N` может создать любой пользователь с правом write, поэтому `commit` из неподписанного файла сам по себе не доверие. B0 принимается, только если: он предок (или равен) родителя S **и** предок `origin/main` — на main без двух одобрений код не попадает (ruleset, §2а), значит код в B0 прошёл четыре глаза; тег `policy-bundle-N` (с разыменованием аннотированного) указывает именно на B0 (релиз создаётся с `--target` = коммит bundle). Это главный якорь доверия: поддельный релиз с вредоносным коммитом на побочной ветке отвергается до сборки. Остаточный эффект подделки тегов — отказ в обслуживании (тег с наибольшим номером на неверном коммите останавливает цепочку; чинится удалением тега администратором).
1. Предыдущий bundle (B0, из релиза с наибольшим `policy-bundle-N`) проверяется `bundle.Verify` по **ключам из коммита B0** (`git show B0:deploy/policy-bundle/keys.json` и файлы ключей, `-prev-keys`), а не из S; на `-genesis` предыдущего нет. Ключи для подписи и проверки **нового** bundle — из S (`-keys`): смена ключа — изменение защищённого `deploy/`, она проходит четыре глаза; при ротации новый bundle подписывается новым ключом, а следующий `plan` проверит его ключами из коммита этого bundle (где новый ключ уже есть). Повторный прогон (Re-run) старого коммита после того, как выпущен bundle более нового, отвергается привязкой: перезапускайте по порядку коммитов.
2. Правила four-eyes берутся из коммита B0 (`git show B0:.github/four-eyes.json`), а не из S: PR не может ослабить правила, по которым его же проверяют. При genesis — из S, с пометкой в выводе.
3. Защищённые файлы S и B0 одинаковы — подписывать нечего (`changed=false`).
4. Защищённые файлы S^ (родитель) и B0 совпадают, иначе «изменение защищённых путей без подписи (коммиты между B0 и S^)»: цепочка разорвана.
5. S — слитый squash-коммит единственного PR (`GET /commits/S/pulls`: `merged`, `merge_commit_sha == S`, база `main`), иначе «push в обход PR».
6. Защищённые файлы S и head PR (`git fetch origin refs/pull/N/head`) совпадают.
7. Одобрения PR оцениваются по правилам из B0 для путей, изменённых между S^ и S.
8. Строится манифест (`sequence = prev + 1`), запись `unsigned.json`.

Цепочка требует squash-merge (ruleset разрешает только его). Не работает без неё: merge-коммит и rebase-merge рвут соответствие «коммит main = слитый PR».

**Слияние в main — по одному, пока идёт подпись.** Группа `concurrency` держит один выполняющийся и один ожидающий прогон, третий push отменяет ожидающий. Любое слияние, в том числе незащищённое, может отменить ожидающий прогон защищённого коммита и разорвать цепочку. Правило: после слияния PR, меняющего защищённые пути, ничего не сливать, пока его прогон `policy-bundle` не завершён (выпущен `policy-bundle-N` или `changed=false`). Если прогон отменён — «Починка разрыва» (Re-run по порядку). Merge queue — кандидат на этап 1.

**Починка разрыва.** Если коммит пропущен (прогон отменён, workflow был выключен, bundle не выпущен), следующий `plan` падает по п. 4. Варианты: (1) перезапустить упавшие прогоны `policy-bundle` (Re-run в интерфейсе Actions) строго по порядку коммитов — каждый использует свой SHA; (2) если коммит нельзя подписать (одобрений не было), откатить его PR-ом `git revert`, после чего защищённые файлы вернутся к B0 и п. 3 даст `changed=false`; (3) break-glass (§6).

**Genesis никогда не выбирается автоматически.** По push `policy-bundle.yml` ищет предыдущий bundle двумя способами (теги `policy-bundle-*` после `git fetch --tags` и все страницы `gh api --paginate .../releases`), требует их совпадения (тег без релиза, релиз без тега и нечисловой номер — отказ) и берёт наибольший номер. Если bundle нет, job падает: «нет предыдущего bundle: genesis только через workflow_dispatch с genesis=true». Процедура genesis: (1) PR, меняющий защищённый путь (естественно — `deploy/policy-bundle/keys.json` с открытым ключом), с двумя одобрениями из разных групп; (2) после слияния владелец запускает workflow `policy-bundle` вручную на main (`gh workflow run policy-bundle.yml -f genesis=true -f confirm=genesis`); workflow проверяет, что тегов `policy-bundle-*` нет, иначе отказ; (3) ревьюер environment подтверждает подпись. Правила four-eyes и проверяющий при genesis берутся из S (предыдущего bundle нет), поэтому genesis — самый уязвимый момент: проверьте diff защитного кода глазами.

## 6. Break-glass

Ручная подпись нужна, если цепочку нельзя починить штатно или недоступен CI. Правила: ключ break-glass — отдельный, в `keys.json` под issuer `ci/break-glass`, хранится офлайн у двух хранителей, у одного человека целиком не бывает; подписывают двое вместе. Порядок: заявка в issue (что, почему, коммит); `go run ./cmd/aegis-ci bundle plan` локально с `GH_TOKEN` на чтение, либо ручной манифест для подтверждённого PR; `aegis-ci bundle sign -issuer ci/break-glass`; публикация релиза `policy-bundle-N`; запись в журнал решений и ручной алерт Security (проверка, что подпись не штатная, — в audit log GitHub и по issuer'у в bundle). Использование break-glass без заявки — инцидент безопасности.

## 7. Модель угроз администратора

В MVP-A **администратор репозитория — корень доверия**. Он может отключить ruleset, изменить workflow, environments и ревьюеров. Что это ему даёт и чего не даёт:

- слить код в main в обход одобрений — может, но подписи не будет: `plan` отказывает («в обход PR» или одобрения недостаточны), следующие коммиты ломаются до отката (п. 4 цепочки), сборка из такого коммита не проходит проверку bundle, а intake с `required: true` не стартует;
- изменить `policy-bundle.yml` (в том числе сам шаг сборки проверяющего из B0), чтобы подписать без проверки, — может: файлы workflow берутся из S, и сборка проверяющего из B0 от этого не защищает (она защищает от изменения кода проверки без изменения workflow). Единственный барьер здесь — ручное подтверждение ревьюера environment `policy-signing` (другой человек, самоодобрение запрещено), который обязан проверить, что в коммите S не менялись `.github/`, `cmd/aegis-ci/`, `internal/foureyes/`, `internal/bundle/` без отдельного четырёхглазого PR (сводка `plan`, §2). Дополнительно: аттестация bundle оставляет публичную запись в Rekor (изменённый workflow виден постфактум); подпись ключом в KMS с отдельными правами — этап 1;
- прочитать секрет ключа подписи — нет (секреты environment только записываются), но может запустить в job'е код, который его использует: см. предыдущий пункт.

Остаточные риски (отражены в [threat-model.md](../02-security/threat-model.md) §7.2): два одобривших из одной группы могут изменить workflow и тем обойти сборку проверяющего из B0 (ревьюер environment — барьер); проверяющий и правила four-eyes при genesis берутся из S; если S добавляет новый встроенный набор файлов (новая строка в `sources()`), проверяющий из B0 его не включит, и такой bundle не пройдёт сверку с деревом S — это отказ, а не обход; агент в MVP-A не сравнивает `sequence` с ранее виденным: откат на старый подписанный bundle не отличим, если содержимое сборки совпадает с ним (монотонность, TTL и отзыв — MVP-B, T-21); число коммитов в PR от 250 — отказ (предел API GitHub), а соавторы, указанные только трейлером `Co-authored-by`, проверке не видны; bundle покрывает данные, а не код; цепочка требует squash; в MVP-A администратор — корень доверия; в prod-окружениях обязательность проверки у агента зашита в сборку (секция `policy_bundle` с `required: true` — иначе код 2), в staging её можно выключить.

## 8. Настройки GitHub (команды)

Решение 08.11.2026: файлы в репозитории есть; применяет владелец после чек-листа. **Применено 09.11.2026:** только squash-merge (`allow_merge_commit` и `allow_rebase_merge` = false, `delete_branch_on_merge` = true); environments `policy-signing` (только ветка `main`) и `release` (только теги `v*`) с ревьюерами `trix13371` и `Oltix146` и `prevent_self_review`; immutable releases включены (`gh api repos/limpjungle/aegis3311/immutable-releases` → `enabled: true`; `gh release create` с файлами загружает ассеты до публикации, поэтому совместим). Затем создан секрет `POLICY_BUNDLE_SIGNING_KEY` и применены ruleset'ы: `main: четыре глаза` (id 26882802) и `теги релизов и policy bundle` (id 26882804), оба `active`, `bypass_actors: []`; `integration_id` 15368 сверен по check run'ам `go`, `race`, `eval` коммита `5030477`. С этого момента прямой push в `main` невозможен, в том числе владельцу.

```bash
# Ruleset main и теги (тела — в репозитории)
gh api -X POST repos/limpjungle/aegis3311/rulesets --input docs/07-governance/rulesets/main.json
gh api -X POST repos/limpjungle/aegis3311/rulesets --input docs/07-governance/rulesets/tags.json

# integration_id обязательных проверок (15368 — GitHub Actions); сверить по реальному check run
gh api repos/limpjungle/aegis3311/commits/<sha>/check-runs --jq '.check_runs[] | [.name, .app.id] | @tsv'

# Environment policy-signing: ревьюер, запрет самоодобрения, только ветка main
gh api users/<login-ревьюера> --jq .id
gh api -X PUT repos/limpjungle/aegis3311/environments/policy-signing --input - <<'JSON'
{"prevent_self_review":true,"reviewers":[{"type":"User","id":<id>}],
 "deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api -X POST repos/limpjungle/aegis3311/environments/policy-signing/deployment-branch-policies --input - <<'JSON'
{"name":"main","type":"branch"}
JSON

# Environment release: только теги v*
gh api -X PUT repos/limpjungle/aegis3311/environments/release --input - <<'JSON'
{"prevent_self_review":true,"reviewers":[{"type":"User","id":<id>}],
 "deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}
JSON
gh api -X POST repos/limpjungle/aegis3311/environments/release/deployment-branch-policies --input - <<'JSON'
{"name":"v*","type":"tag"}
JSON

# Ключ подписи bundle
# офлайн; приватный ключ — вне репозитория, открытый — в deploy/policy-bundle/keys/
go run ./cmd/aegis-ci bundle keygen -priv ~/aegis-keys/policy-ci.key -pub deploy/policy-bundle/keys/ci-policy-signing.pub
gh secret set POLICY_BUNDLE_SIGNING_KEY --env policy-signing < ~/aegis-keys/policy-ci.key
shred -u ~/aegis-keys/policy-ci.key
```

Закрепление версий actions: `scripts/pin-actions.sh owner/repo vX.Y.Z` печатает `owner/repo@<sha> # vX.Y.Z` (только чтение). Обновляет их Dependabot ([dependabot.yml](../../.github/dependabot.yml)); PR проходят те же проверки. Входы actions v7/v8 (`persist-credentials`, `go-version-file`, `cache`, `subject-path`, `sbom-path`) при первом прогоне сверьте с документацией каждого action: версии выбраны без запуска.

Инварианты workflow'ов проверяет `go test ./cmd/aegis-ci` (`workflows_test.go`): закрепление по SHA с комментарием версии, `pull_request_target` нигде, у каждого job'а `timeout-minutes` и явные `permissions`, запись только в `policy-bundle.yml/sign` и `release.yml/publish`, секрет ключа только в `policy-bundle.yml/sign`, `persist-credentials: false`, значения событий не попадают в `run:`. `codeowners_test.go` проверяет соответствие CODEOWNERS и `four-eyes.json`. Изменяя защищённый путь, меняйте обе записи вместе.

## 9. Проверка артефактов

Релиз `vX.Y.Z` содержит пять бинарей linux/amd64 (`aegis-intake`, `aegis-llmrouter`, `aegis-pep`, `aegis-audit`, `aegis-killswitch`), SBOM CycloneDX 1.5 (`dist/sbom/<имя>.cdx.json`, свой генератор по `debug/buildinfo`), `SHA256SUMS` и `policy-bundle.json`. Образов нет: подпись образов Sigstore cosign отложена до их появления (не путать с `aegis-killswitch cosign` — вторая подпись документа kill switch).

```bash
# Провенанс SLSA бинаря (Sigstore, GitHub attestations)
gh attestation verify dist/bin/aegis-intake --repo limpjungle/aegis3311 \
  --signer-workflow limpjungle/aegis3311/.github/workflows/release.yml

# Аттестация SBOM
gh attestation verify dist/bin/aegis-intake --repo limpjungle/aegis3311 \
  --signer-workflow limpjungle/aegis3311/.github/workflows/release.yml \
  --predicate-type https://cyclonedx.org/bom

# Офлайн: скачать аттестации и корень доверия, затем проверить без сети
gh attestation download dist/bin/aegis-intake --repo limpjungle/aegis3311
gh attestation trusted-root > trusted_root.jsonl
gh attestation verify dist/bin/aegis-intake --repo limpjungle/aegis3311 \
  --bundle sha256-<digest>.jsonl --custom-trusted-root trusted_root.jsonl

# Sigstore cosign (флаги сверьте с `cosign verify-blob-attestation --help`: в этой среде cosign не запускался)
cosign verify-blob-attestation --bundle sha256-<digest>.jsonl \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/limpjungle/aegis3311/.github/workflows/release.yml@refs/tags/v' \
  --type slsaprovenance1 dist/bin/aegis-intake

# Подписанный bundle и его соответствие содержимому сборки (из каталога репозитория на том же коммите)
go run ./cmd/aegis-ci bundle verify -in dist/policy-bundle.json -keys deploy/policy-bundle/keys.json [-commit <sha>]
```

Флаги `gh attestation` сверены с `gh attestation verify --help` (gh 2.103). `--signer-workflow` можно дополнить `--source-ref refs/tags/vX.Y.Z`.

## 10. Процедура RT-11

Цель: изменение политики с одним одобрением или в обход ревью не даёт подписанный bundle ([threat-model.md](../02-security/threat-model.md) §7.1). Автотесты (`internal/bundle`, `internal/foureyes`, `cmd/aegis-ci`, `cmd/aegis-intake`) проверяют логику без GitHub; ручной прогон проверяет сами настройки. Выполняется после применения настроек и genesis-bundle, на ветке-песочнице, с реальными двумя аккаунтами (автор, ревьюер):

1. PR с изменением `policy/aegis/autonomy/matrix.rego` от автора; одно одобрение ревьюера. Ожидается: проверка `four-eyes` красная, слияние заблокировано ruleset'ом.
2. Попытка слить администратором в обход (`bypass_actors: []`): ожидается отказ GitHub.
3. Администратор временно отключает ruleset и пушит изменение защищённого файла напрямую (или сливает PR с одним одобрением), затем включает ruleset обратно. Ожидается: `policy-bundle.yml` падает на `plan` («в обход PR» или одобрения недостаточны), релиз `policy-bundle-N` не создан; следующие слияния падают с «изменение защищённых путей без подписи».
4. Тег `v*` на этом коммите: `release.yml` падает на шаге «Подписанный policy bundle этого коммита».
5. Сборка `aegis-intake` из этого коммита с `required: true` и последним подписанным bundle: код 2, `policy_bundle_unverified` не выводится, intake не принимает инциденты.
6. Откат: `git revert` (через PR с двумя одобрениями) возвращает защищённые файлы к последнему подписанному состоянию; цепочка восстановлена (§5). Результат и ссылки на прогоны записать в отчёт red-team.

## Чек-лист включения

Порядок обязателен; пока он не пройден, T-24 **не закрыт**:

1. Добавить collaborators с правом write: минимум двое, помимо владельца, из разных ролей.
2. Заполнить группы в `.github/four-eyes.json` и `.github/CODEOWNERS` (PR; пока один логин — слияние возможно только владельцем, это допустимо один раз).
3. Сгенерировать ключ подписи офлайн (`aegis-ci bundle keygen`), добавить открытый ключ в `deploy/policy-bundle/keys.json` и break-glass-ключ у двух хранителей.
4. Создать секрет `POLICY_BUNDLE_SIGNING_KEY` в environment `policy-signing`; ревьюеру environment выдать инструкцию из §2 (diff защитного кода между B0 и S).
5. Применить ruleset'ы и environments (§8), сверить `integration_id`.
6. Получить genesis-bundle: PR из п. 3 с двумя одобрениями, затем ручной запуск `policy-bundle` с `genesis=true` и `confirm=genesis` (§5) → релиз `policy-bundle-1`.
7. Положить `policy-bundle.json` и открытый ключ на хост intake, добавить секцию `policy_bundle`: в prod сразу `required: true` (сборка иначе не стартует), в staging двухшагово: `required: false`, убедиться в журнале `policy_bundle_verified`, затем `required: true` (runbook [policy-bundle-stand.md](../04-operations/policy-bundle-stand.md); [intake-deploy.md](../04-operations/intake-deploy.md), [migrations.md](../04-operations/migrations.md)).
8. Пройти RT-11 вручную (§10).
