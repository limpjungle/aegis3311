#!/usr/bin/env bash
# Dev-стенд: minikube (драйвер docker, без CNI) + Cilium из Helm-чарта; применяет deploy/intake/{cilium-egress,networkpolicy}.yaml
# и проверяет разрешённые и запрещённые направления из пода с меткой app=aegis-intake (T-17; docs/04-operations/intake-deploy.md, «Сеть»).
# Только для стенда: поды-цели — busybox httpd, внешние OpenRouter/S3 — nginx с TLS (SAN: openrouter.ai, storage.yandexcloud.net,
# evil.example), «чужой» хост — busybox; всё это docker-контейнеры в сети профиля (identity world), их имена добавлены в CoreDNS стенда.
# toFQDNs работает по IP, serverNames добавляет проверку SNI в ClientHello (встроенный Envoy Cilium, без терминации TLS).
#
#   ./run-netpol.sh             поднять стенд и прогнать проверки (без интернета)
#   ./run-netpol.sh internet    то же + реальный openrouter.ai (записи CoreDNS убираются; без интернета на хосте проверки SKIP)
#   ./run-netpol.sh down        удалить профиль minikube и контейнеры-цели
# Запасной вариант, если Cilium не поднимается из загруженных образов: `minikube start --cni=cilium` (см. README).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
intake_dir=$(cd "$here/.." && pwd)
cluster=aegis-netpol-dev
ctx=$cluster
mode=${1:-}
st=${XDG_RUNTIME_DIR:-$HOME/.cache}/aegis-netpol-dev   # сертификат и nginx.conf фейков
fakes="netpol-fake-openrouter netpol-fake-s3 netpol-fake-evil"
case "$mode" in
  ""|internet) ;;
  down) docker rm -f $fakes >/dev/null 2>&1 || true; minikube delete -p "$cluster"; rm -rf "$st"; exit 0 ;;
  *) echo "использование: $0 [internet|down]" >&2; exit 2 ;;
esac

source "$here/../../vault/dev/lib.sh"   # k, fails, pass, fail, skip, busybox, load_one, start_cluster_cilium, apply_netpols, wait_cilium_ready

curl_img=curlimages/curl:8.17.0;                         curl_digest=sha256:935d9100e9ba842cdb060de42472c7ca90cfe9a7c96e4dacb55e79e560b3ff40
nginx_img=nginx:1.30.6-alpine;                           nginx_digest=sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311

# --- кластер и Cilium ------------------------------------------------------------------------------------------
start_cluster_cilium
load_one "$curl_img" "$curl_digest"
load_one "$busybox" "$busybox_digest"

# --- внешние цели вне кластера (identity world) -----------------------------------------------------------------
docker rm -f $fakes >/dev/null 2>&1 || true
docker pull -q "$nginx_img@$nginx_digest" >/dev/null
rm -rf "$st"; mkdir -p -m 700 "$st"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=fake \
  -addext subjectAltName=DNS:openrouter.ai,DNS:storage.yandexcloud.net,DNS:evil.example \
  -keyout "$st/tls.key" -out "$st/tls.crt" 2>/dev/null
cat > "$st/nginx.conf" <<'EOF'
events {}
http { server { listen 80; listen 443 ssl; ssl_certificate /tls/tls.crt; ssl_certificate_key /tls/tls.key; location / { return 200 "ok\n"; } } }
EOF
chmod 644 "$st/tls.key"   # nginx в контейнере читает ключ не от владельца; ключ одноразовый, каталог 700
fake_tls() { # $1 — имя контейнера; печатает его IP
  docker run -d --network "$cluster" --name "$1" -v "$st/nginx.conf:/etc/nginx/nginx.conf:ro" -v "$st:/tls:ro" "$nginx_img@$nginx_digest" >/dev/null
  docker inspect -f "{{(index .NetworkSettings.Networks \"$cluster\").IPAddress}}" "$1"
}
fake() { # $1 — имя контейнера, остальное — порты httpd
  local n=$1; shift
  local cmd='mkdir /w; echo ok >/w/index.html;'
  for p in "$@"; do cmd="$cmd httpd -p $p -h /w;"; done
  docker run -d --network "$cluster" --name "$n" "$busybox@$busybox_digest" sh -c "$cmd sleep 1d" >/dev/null
  docker inspect -f "{{(index .NetworkSettings.Networks \"$cluster\").IPAddress}}" "$n"
}
ip_or=$(fake_tls netpol-fake-openrouter)
ip_s3=$(fake_tls netpol-fake-s3)
ip_evil=$(fake netpol-fake-evil 443)
node_ip=$(minikube -p "$cluster" ip)

# CoreDNS: имена внешних целей (в режиме internet — настоящие openrouter.ai и S3 через forward).
coredns_hosts() { # $@ — строки "IP имя"
  local cf
  cf=$(k -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' | grep -vE 'openrouter\.ai|storage\.yandexcloud\.net|evil\.aegis\.test')
  if [ "$#" -gt 0 ]; then
    local blk="" l; for l in "$@"; do blk="$blk        $l"$'\n'; done
    if grep -q 'hosts {' <<<"$cf"; then
      cf=$(awk -v blk="$blk" '/^ *hosts \{/ && !d { print; printf "%s", blk; d=1; next } { print }' <<<"$cf")
    else
      cf=$(awk -v blk="$blk" '/^ *forward / && !d { print "    hosts {"; printf "%s", blk; print "        fallthrough"; print "    }"; d=1 } { print }' <<<"$cf")
    fi
  fi
  k -n kube-system create configmap coredns --from-literal=Corefile="$cf" --dry-run=client -o yaml | k apply -f - >/dev/null
  k -n kube-system rollout restart deploy/coredns >/dev/null
  k -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null
}
coredns_hosts "$ip_or openrouter.ai" "$ip_s3 storage.yandexcloud.net" "$ip_evil evil.aegis.test"

# --- поды-цели и клиенты -------------------------------------------------------------------------------------------
vault_ns=$(jq -r '.vault.address | capture("^https://[^.]+\\.(?<ns>[^.]+)\\.svc").ns' "$intake_dir/../vault/agent/aegis-intake.json")
for ns in aegis-system "$vault_ns" monitoring shop nettest; do
  k delete ns "$ns" --ignore-not-found --wait >/dev/null
  k create ns "$ns" >/dev/null
done

# Под: busybox (httpd на портах) + curl; Service с теми же портами (политика действует на порт пода после DNAT).
# ndots1=1 перед вызовом — dnsConfig ndots:1 (как в боевом поде intake: openrouter.ai без завершающей точки уходит в DNS как есть).
mkpod() { # $1 ns, $2 имя, $3 метки "k=v,k=v", $4... порты httpd
  local ns=$1 name=$2 labels=$3 l; shift 3
  local cmd='mkdir -p /w; echo ok >/w/index.html;'
  for p in "$@"; do cmd="$cmd httpd -p $p -h /w;"; done
  {
    echo "apiVersion: v1"; echo "kind: Pod"
    echo "metadata:"; echo "  name: $name"; echo "  namespace: $ns"; echo "  labels:"; echo "    tgt: $name"
    for l in ${labels//,/ }; do echo "    \"${l%%=*}\": \"${l#*=}\""; done
    echo "spec:"; echo "  terminationGracePeriodSeconds: 0"
    [ -z "${ndots1:-}" ] || echo "  dnsConfig: {options: [{name: ndots, value: \"1\"}]}"
    echo "  containers:"
    echo "    - {name: bb, image: $busybox, imagePullPolicy: IfNotPresent, command: [sh, -c, \"$cmd sleep 1d\"]}"
    echo "    - {name: curl, image: $curl_img, imagePullPolicy: IfNotPresent, command: [sleep, 1d]}"
  } | k apply -f - >/dev/null
  if [ "$#" -gt 0 ]; then
    {
      echo "apiVersion: v1"; echo "kind: Service"; echo "metadata: {name: $name, namespace: $ns}"
      echo "spec:"; echo "  selector: {tgt: $name}"; echo "  ports:"
      for p in "$@"; do echo "    - {name: p$p, port: $p, targetPort: $p}"; done
    } | k apply -f - >/dev/null
  fi
}
mkpod "$vault_ns" openbao-fake "app.kubernetes.io/name=openbao,component=server" 8200 8201
mkpod monitoring alertmanager "app.kubernetes.io/name=alertmanager" 9093
mkpod monitoring prometheus "app.kubernetes.io/name=prometheus" 9090 9091
mkpod monitoring grafana "app.kubernetes.io/name=grafana" 3000
mkpod shop app "app=shop" 8080
mkpod aegis-system aegis-other "app=aegis-other" 8080
ndots1=1 mkpod aegis-system intake "app=aegis-intake" 9464 8080
mkpod nettest probe "app=probe"
for ns in "$vault_ns" monitoring shop nettest aegis-system; do k -n "$ns" wait --for=condition=Ready pod --all --timeout=180s >/dev/null; done

# TCP из пода: 0 — соединение установлено (time_connect > 0), 1 — нет (дроп политикой — 0, curl 28), 2 — сбой kubectl exec или вывод не число.
tcp() { # $1 ns, $2 под, $3 хост, $4 порт
  local t
  t=$(k -n "$1" exec "$2" -c curl -- sh -c "curl -s -o /dev/null -w '%{time_connect}' --connect-timeout 3 --max-time 4 telnet://$3:$4 </dev/null 2>/dev/null; true" 2>/dev/null) || return 2
  [[ $t =~ ^[0-9]+\.[0-9]+$ ]] || return 2
  ! [[ $t =~ ^0+\.0+$ ]]
}
expect_conn() { # $1 описание, остальное — аргументы tcp
  local d=$1 rc=0; shift
  tcp "$@" || rc=$?
  case $rc in 0) pass "$d" ;; 1) fail "$d: соединения нет" ;; *) fail "стенд: exec не выполнился: $d" ;; esac
}
expect_noconn() {
  local d=$1 rc=0; shift
  tcp "$@" || rc=$?
  case $rc in 1) pass "$d" ;; 0) fail "$d: соединение есть" ;; *) fail "стенд: exec не выполнился: $d" ;; esac
}
# curl из пода с произвольными аргументами: код возврата curl в $crc (99 — сбой kubectl exec), тайминги соединения в $ctc (TCP) и $cta (TLS):
# 0 — этап не завершён. TLS не проверяется (-k): проверяется только допуск политикой.
crl() { # $1 ns, $2 под, остальное — аргументы curl
  local ns=$1 pod=$2 out; shift 2
  ctc=0 cta=0
  out=$(k -n "$ns" exec "$pod" -c curl -- sh -c "curl -sk -o /dev/null -w 't=%{time_connect} %{time_appconnect}\n' --connect-timeout 3 --max-time 6 $*; echo rc=\$?" 2>/dev/null) || { crc=99; return; }
  if [[ $out =~ t=([0-9.]+)\ ([0-9.]+)[[:space:]]+rc=([0-9]+)$ ]]; then
    ctc=${BASH_REMATCH[1]} cta=${BASH_REMATCH[2]} crc=${BASH_REMATCH[3]}
  elif [[ $out =~ rc=([0-9]+)$ ]]; then crc=${BASH_REMATCH[1]}
  else crc=99; fi
}
nonzero() { ! [[ $1 =~ ^0*\.?0*$ ]]; }  # время curl отлично от нуля
# $1 — ok | fail | tls_fail | dns_fail, $2 описание, остальное — аргументы crl.
#   fail      — отказ при установленном TCP (не DNS и не L3-дроп);
#   tls_fail  — TCP установлен, TLS не завершён (отказ на этапе ClientHello): иначе проверка SNI ничего не доказывает (DNS 6, connect 7, дроп 28);
#   dns_fail  — curl 6 (имя не резолвится).
expect_curl() {
  local want=$1 d=$2; shift 2
  crl "$@"
  local t="curl $crc, tcp=$ctc tls=$cta"
  case "$crc:$want" in
    99:*) fail "стенд: exec не выполнился: $d" ;;
    0:ok) pass "$d ($t)" ;;
    0:*) fail "$d: запрос прошёл ($t)" ;;
    *:ok) fail "$d: curl завершился с кодом $crc" ;;
    6:dns_fail) pass "$d ($t)" ;;
    *:dns_fail) fail "$d: ожидался отказ DNS (curl 6), $t" ;;
    *:tls_fail) if nonzero "$ctc" && ! nonzero "$cta"; then pass "$d ($t)"; else fail "$d: отказ не на TLS-этапе ($t; DNS/connect/timeout)"; fi ;;
    *:fail) if nonzero "$ctc"; then pass "$d ($t)"; else fail "$d: отказ без установленного TCP ($t)"; fi ;;
  esac
}
# Пять вариантов TLS к одному IP: SNI заданного имени, чужой SNI, без SNI, не-TLS на 443. $1 ok|fail для всех сразу не годится — зовутся по одному.
sni_curl() { # $1 ok|tls_fail, $2 описание, $3 ns, $4 под, $5 SNI, $6 IP
  expect_curl "$1" "$2" "$3" "$4" --resolve "$5:443:$6" "https://$5/"
}
dns() { k -n "$1" exec "$2" -c bb -- nslookup "$3" 2>&1 || true; }
svc() { echo "$1.$2.svc.cluster.local."; }  # имя Service с точкой на конце

# Запрещённые направления: "ns pod хост порт описание"; контроль — от probe до политик (недоступно и там — ошибка стенда).
deny_table=(
  "aegis-system intake $ip_evil 443 |чужой хост (IP_EVIL:443)"
  "aegis-system intake openrouter.ai. 80 |openrouter.ai:80"
  "aegis-system intake $ip_s3 80 |S3 (IP:80)"
  "aegis-system intake $(svc openbao-fake "$vault_ns") 8201 |OpenBao:8201 (Raft)"
  "aegis-system intake $(svc grafana monitoring) 3000 |grafana:3000"
  "aegis-system intake $(svc prometheus monitoring) 9091 |prometheus:9091"
  "aegis-system intake $(svc app shop) 8080 |shop/app:8080"
  "aegis-system intake $(svc aegis-other aegis-system) 8080 |aegis-other:8080"
  "aegis-system aegis-other $(svc app shop) 8080 |aegis-other (без метки intake) -> shop/app:8080"
  "aegis-system intake $(svc kube-dns kube-system) 9153 |kube-dns:9153"
  "aegis-system intake $node_ip 10250 |kubelet узла :10250"
)
echo "== до политик"
expect_conn "до политик intake -> shop/app:8080 доступен" aegis-system intake "$(svc app shop)" 8080
for row in "${deny_table[@]}"; do
  spec=${row%%|*}; read -r _ _ host port <<<"$spec"
  expect_conn "контроль до политик: probe достаёт ${row#*|}" nettest probe "$host" "$port"
done
expect_conn "контроль до политик: probe достаёт IP_OR:443" nettest probe "$ip_or" 443
# TLS-варианты до политик (из probe) все проходят; иначе проверки SNI после политик ничего не доказывают.
sni_curl ok "контроль до политик: TLS SNI openrouter.ai -> IP_OR" nettest probe openrouter.ai "$ip_or"
sni_curl ok "контроль до политик: TLS SNI evil.example -> IP_OR" nettest probe evil.example "$ip_or"
expect_curl ok "контроль до политик: TLS без SNI -> IP_OR" nettest probe "https://$ip_or/"
expect_curl ok "контроль до политик: не-TLS на :443 -> IP_OR" nettest probe --resolve "openrouter.ai:443:$ip_or" "http://openrouter.ai:443/"
sni_curl ok "контроль до политик: TLS SNI storage.yandexcloud.net -> IP_S3" nettest probe storage.yandexcloud.net "$ip_s3"
sni_curl ok "контроль до политик: TLS SNI openrouter.ai -> IP_S3" nettest probe openrouter.ai "$ip_s3"

# --- применение политик --------------------------------------------------------------------------------------------
apply_netpols "$intake_dir"
wait_cilium_ready k8s:app=aegis-intake || fail "стенд: endpoint intake не готов"
sleep 5
api_port=$(k -n default get endpoints kubernetes -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null)
echo "== разрешено (API-сервер: порт $api_port)"
dns aegis-system intake kubernetes.default.svc.cluster.local. | grep -q 'Address.*[0-9]' && pass "DNS: kubernetes.default.svc.cluster.local" || fail "DNS: kubernetes.default.svc.cluster.local"
expect_conn "OpenBao :8200" aegis-system intake "$(svc openbao-fake "$vault_ns")" 8200
expect_conn "Alertmanager :9093" aegis-system intake "$(svc alertmanager monitoring)" 9093
expect_conn "Prometheus :9090" aegis-system intake "$(svc prometheus monitoring)" 9090
code=$(k -n aegis-system exec intake -c curl -- curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 3 https://kubernetes.default.svc.cluster.local./version 2>/dev/null) || code=000
[ "$code" != 000 ] && pass "API-сервер: HTTP $code" || fail "API-сервер недоступен"
# Контроль источников после политик: loopback работает (kubectl exec и curl исправны), поэтому отказы ниже — это политика, а не сбой стенда.
expect_conn "aegis-other: loopback :8080 (exec и curl исправны)" aegis-system aegis-other 127.0.0.1 8080
expect_conn "intake: loopback :9464 (exec и curl исправны)" aegis-system intake 127.0.0.1 9464
# toFQDNs: прямой IP до DNS-запроса запрещён, после DNS-запроса имени — разрешён.
expect_noconn "прямой IP_OR до DNS запрещён" aegis-system intake "$ip_or" 443
dns aegis-system intake openrouter.ai. | grep -q "$ip_or" && pass "DNS: openrouter.ai -> IP_OR" || fail "DNS: openrouter.ai не вернул IP_OR"
dns aegis-system intake storage.yandexcloud.net. | grep -q "$ip_s3" && pass "DNS: storage.yandexcloud.net -> IP_S3" || fail "DNS: storage.yandexcloud.net не вернул IP_S3"
# DNS-запросы выше обязательны: toFQDNs пускает IP только после резолва имени из пода (без них --resolve даст L3-дроп, curl 28/7, похожий на «отказ»).
# serverNames: SNI сверяется в ClientHello. TCP-соединение с Envoy устанавливается всегда, отказ — сброс после ClientHello (curl 35 и др.): tls_fail требует tcp>0 и tls=0.
echo "== SNI"
sni_curl ok "SNI openrouter.ai -> IP_OR проходит" aegis-system intake openrouter.ai "$ip_or"
sni_curl tls_fail "SNI evil.example -> IP_OR (тот же IP, чужое имя) отклонён" aegis-system intake evil.example "$ip_or"
expect_curl tls_fail "TLS без SNI -> IP_OR отклонён" aegis-system intake "https://$ip_or/"
expect_curl fail "не-TLS на :443 -> IP_OR отклонён" aegis-system intake --resolve "openrouter.ai:443:$ip_or" "http://openrouter.ai:443/"
sni_curl ok "SNI storage.yandexcloud.net -> IP_S3 проходит" aegis-system intake storage.yandexcloud.net "$ip_s3"
sni_curl tls_fail "SNI openrouter.ai -> IP_S3 отклонён (SNI сверяется по правилу IP)" aegis-system intake openrouter.ai "$ip_s3"

echo "== запрещено"
dns aegis-system intake evil.aegis.test. | grep -q REFUSED && pass "evil.aegis.test -> REFUSED" || fail "evil.aegis.test не REFUSED"
dns nettest probe evil.aegis.test. | grep -q "$ip_evil" && pass "контроль: probe получает IP_EVIL" || fail "стенд: probe не резолвит evil.aegis.test"
dns aegis-system intake example.com. | grep -q REFUSED && pass "example.com -> REFUSED" || fail "example.com не REFUSED"
for row in "${deny_table[@]}"; do
  spec=${row%%|*}; read -r ns pod host port <<<"$spec"
  expect_noconn "${row#*|}: запрещено" "$ns" "$pod" "$host" "$port"
done

echo "== ingress"
intake_ip=$(k -n aegis-system get pod intake -o jsonpath='{.status.podIP}')
expect_conn "prometheus -> intake:9464" monitoring prometheus "$intake_ip" 9464
expect_noconn "probe -> intake:9464 запрещено" nettest probe "$intake_ip" 9464
expect_noconn "prometheus -> intake:8080 запрещено" monitoring prometheus "$intake_ip" 8080

if [ "$mode" = internet ]; then
  echo "== internet"
  coredns_hosts
  crl nettest probe https://openrouter.ai/api/v1/models
  if [ "$crc" = 0 ]; then
    expect_curl ok "intake -> https://openrouter.ai/api/v1/models" aegis-system intake https://openrouter.ai/api/v1/models
    expect_curl dns_fail "intake -> https://example.com отказ" aegis-system intake https://example.com
  else
    skip "intake -> https://openrouter.ai: probe не достаёт интернет (curl $crc)"
    skip "intake -> https://example.com: probe не достаёт интернет"
  fi
fi

echo "провалов: $fails"
[ "$fails" -eq 0 ]
