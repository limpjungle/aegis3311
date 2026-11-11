# Сетевые политики intake: default-deny и egress (T-17)

Решение и обоснование — [intake-deploy.md](../../docs/04-operations/intake-deploy.md), раздел «Сеть». Каталог защищён правилом четырёх глаз (`deploy/`). Тест `cmd/aegis-ci/netpol_test.go` (`TestIntakeNetworkPolicy`) разбирает манифесты строго по структуре и сверяет их с точной таблицей разрешённых направлений.

| Файл | Объекты |
|---|---|
| `networkpolicy.yaml` | `NetworkPolicy` `aegis-system-default-deny` (ingress и egress всего namespace `aegis-system`) и `aegis-intake-metrics` (скрейп 9464 только из Prometheus). Egress-правил здесь нет намеренно |
| `cilium-egress.yaml` | `CiliumNetworkPolicy` `aegis-intake-egress`: весь egress intake — DNS с фильтром имён, OpenBao :8200, Alertmanager :9093, Prometheus :9090, `kube-apiserver`, toFQDNs `openrouter.ai` и `storage.yandexcloud.net` (:443) с фильтром SNI (`serverNames` равен имени) |
| `dev/run-netpol.sh` | Dev-стенд на minikube с Cilium |

## Требования к кластеру

- **CNI — Cilium (решено 11.11.2026)**, полный список требований (создание кластера Yandex MK8s, домен, NodeLocal DNS, число узлов) — [intake-deploy.md](../../docs/04-operations/intake-deploy.md), «Сеть».
- **Cilium ≥ 1.13**: поле `serverNames` появилось в 1.13. Версия Cilium в Yandex MK8s в документации не названа (в примере — 1.12.9); проверка: `kubectl explain ciliumnetworkpolicy.spec.egress.toPorts.serverNames`. Без поля `kubectl apply --dry-run=server` отклонит политику, а default-deny останется (fail-closed).
- L7-прокси (`enable-l7-proxy`; `cilium-dbg status`: `Proxy Status: OK`), встроенный Envoy достаточен. Без Cilium `CiliumNetworkPolicy` не применится (нет CRD).
- Домен кластера `cluster.local`; NodeLocal DNS не используется.

## Применение

Применяет только CI-применитель после PR; до применения обязателен `kubectl apply --dry-run=server -f deploy/intake/`. Порядок: сначала `cilium-egress.yaml`, затем `networkpolicy.yaml`.

В каталоге допустимы только `*.yaml`, `README.md` и `dev/`: `kubectl apply -f deploy/intake/` применит и `.yml`/`.json`, а тест их бы не проверил, поэтому `TestIntakeNetworkPolicy` падает на любом постороннем файле.

Что поменять под бой:

- namespace OpenBao в `cilium-egress.yaml` (сейчас `vault`) — синхронно с `vault.address` в [`../vault/agent/aegis-intake.json`](../vault/agent/aegis-intake.json); тест сверяет их;
- порт API-сервера (маркер `# kube-api-port`): 443 у Yandex Managed Kubernetes, у self-hosted обычно 6443.

## Dev-стенд

`dev/run-netpol.sh` (режим `internet` — с реальным openrouter.ai; `down` удаляет стенд): minikube (профиль `aegis-netpol-dev`, драйвер docker, `--cni=false`) и Cilium 1.20.4 из Helm-чарта (`l7Proxy=true`, `envoy.enabled=false` — встроенный Envoy агента; образы закреплены по digest и загружаются с хоста; установка — общая функция `start_cluster_cilium` в [`../vault/dev/lib.sh`](../vault/dev/lib.sh)). Внешние OpenRouter и S3 — контейнеры nginx с TLS (образ `nginx:1.30.6-alpine`, digest `sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311`; одноразовый сертификат с SAN `openrouter.ai`, `storage.yandexcloud.net`, `evil.example` в `${XDG_RUNTIME_DIR:-$HOME/.cache}/aegis-netpol-dev`), «чужой» хост — busybox; все в сети профиля (identity `world`), их имена добавлены в CoreDNS. Применяются манифесты из Git (меняется только порт по маркеру `# kube-api-port`). Под intake — с `dnsConfig ndots:1`, как в бою. Проверяется из пода с меткой `app=aegis-intake` против контрольного пода без политик; до политик те же TLS-варианты из контрольного пода проходят все:

- разрешено: DNS кластера, OpenBao :8200, Alertmanager :9093, Prometheus :9090, API-сервер; TLS с SNI `openrouter.ai` на IP OpenRouter и с SNI `storage.yandexcloud.net` на IP S3 после DNS-запроса;
- запрещено: прямой IP внешней цели до DNS-запроса; **тот же IP под другим именем** (SNI `evil.example` на IP OpenRouter); TLS без SNI; не-TLS на :443; SNI `openrouter.ai` на IP S3 (SNI сверяется по правилу IP); «чужое» имя (`REFUSED`), `example.com` (`REFUSED`), порты 80, OpenBao :8201, чужие поды и порты (grafana, prometheus :9091, `shop/app`), kube-dns :9153, kubelet :10250, под без метки intake;
- ingress: Prometheus → intake :9464 проходит, остальные порты и источники — нет;
- контроль самого стенда: loopback `aegis-other:8080` и `intake:9464` после политик (kubectl exec и curl исправны); сбой `kubectl exec` (код 2) — это FAIL «стенд: exec не выполнился», а не «запрещено».

Через Envoy TCP-соединение с адресом внешней цели устанавливается всегда, отказ по SNI приходит сбросом после ClientHello, поэтому SNI проверяется по таймингам curl: отказ засчитывается, только если TCP установлен (`time_connect > 0`), а TLS не завершён (`time_appconnect == 0`, curl 35/56); DNS-ошибка, connect refused и L3-дроп (6/7/28) не принимаются за отказ по SNI. Код curl попадает в PASS-сообщение.

Запасной вариант, если встроенный Envoy не заработает: `envoy.enabled=true` (образ `quay.io/cilium/cilium-envoy:v1.39.5-1792733054-8c73b2816bc8239e27f1fd53b271884688137459@sha256:547ab45f6092f681d9f54f3be9fa8fb1e705c9c5dc2df388efe3a52aa6965629`, `envoy.image.useDigest=false`, `envoy.image.pullPolicy=IfNotPresent`, `load_one` образа) либо `minikube start -p aegis-netpol-dev --cni=cilium`.

Последний прогон 11.11.2026: Cilium 1.20.4 (чарт 1.20.4, встроенный Envoy — запасной вариант не понадобился), Kubernetes 1.35.1, minikube 1.38.1 — `./run-netpol.sh`: 54 PASS, 0 провалов (`Proxy Status: OK`; SNI `openrouter.ai` → IP OpenRouter проходит, `evil.example` → тот же IP, без SNI, не-TLS на :443 и `openrouter.ai` → IP S3 отклонены; до политик те же шесть TLS-вариантов проходят все; loopback-контроль `aegis-other` и `intake` проходит). `./run-netpol.sh internet`: 0 провалов, 2 SKIP (из узла minikube нет выхода в интернет, реальный openrouter.ai и `example.com` не проверены). Время полного прогона с нуля около 8 мин.

Особенность стенда: `curl telnet://` на установленном соединении не завершается, поэтому «есть соединение» определяется по `time_connect > 0` (дроп политикой — `0`, curl 28).
