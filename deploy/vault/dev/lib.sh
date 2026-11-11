# Общие функции стенда (source из run.sh, run-ha.sh и deploy/intake/dev/run-netpol.sh). Ожидает переменные: here, cluster, ctx, image, cli.
k() { kubectl --context "$ctx" "$@"; }
fails=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; fails=$((fails + 1)); }

start_cluster() {
  minikube status -p "$cluster" >/dev/null 2>&1 || minikube start -p "$cluster" --driver=docker --cpus=2 --memory=4096 >/dev/null
}

# Образы: хост скачивает по digest и загружает в minikube; в кластере — по тегу с IfNotPresent, без реестра
# (DNS внутри узла minikube может не работать, а digest при `minikube image load` теряется).
busybox=busybox:1.37.0; busybox_digest=sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
load_images() { # $1 — образ с тегом, $2 — его digest
  local ref tag
  for ref in "$1@$2" "$busybox@$busybox_digest"; do
    docker pull -q "$ref" >/dev/null
    tag=${ref%@*}; docker tag "$ref" "$tag"
    [ "$(docker inspect --format '{{index .RepoDigests 0}}' "$tag")" = "${tag%:*}@${ref#*@}" ] || { echo "digest $tag не совпал" >&2; exit 1; }
    minikube -p "$cluster" image load "$tag" >/dev/null
  done
}

# --- запуск пода и ожидание исхода -------------------------------------------------------------------------------
start_pod() { # $1 — имя пода, $2 — сколько секунд intake держит под после проверки (по умолчанию 0)
  k -n aegis-system delete pod "$1" --ignore-not-found --wait >/dev/null
  sed -e "s|__NAME__|$1|" -e "s|__AGENT_IMAGE__|$image|" -e "s|__CLI__|$cli|" -e "s|__HOLD__|${2:-0}|" "$here/pod-template.yaml" | k apply -f - >/dev/null
}
run_pod() { # $1 — имя пода
  start_pod "$1"
  local phase="" i
  for i in $(seq 1 120); do
    phase=$(k -n aegis-system get pod "$1" -o jsonpath='{.status.phase}')
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep 2
  done
  echo "$phase"
}
agent_log() { k -n aegis-system logs "$1" -c vault-agent 2>&1 | tail -n "${2:-5}"; }
# Сбой засчитывается, только если под упал и причина в логе агента — ожидаемая, а не, например, ошибка конфигурации.
expect_fail() { # $1 — под, $2 — название, $3 — regex причины; фаза — в $phase
  local log; log=$(k -n aegis-system logs "$1" -c vault-agent 2>&1 | tail -n 40)
  if [ "$phase" != Failed ]; then fail "$2: фаза $phase (Succeeded — пустой файл прошёл бы дальше)"
  elif grep -qiE 'error loading configuration' <<<"$log"; then fail "$2: агент упал на конфигурации, а не на секрете"
  elif grep -qiE "$3" <<<"$log"; then pass "$2: init-контейнер упал по ожидаемой причине, intake не запущен"
  else fail "$2: под упал, но причина неожиданная"; fi
  grep -iE 'error|fail' <<<"$log" | tail -n 3 | cut -c1-300 | sed 's/^/      /' || true
}

# Фиктивные секреты intake в KV; нужна функция srv (CLI от root-токена).
put_all() {
  srv kv put aegis-kv/mvp-a/intake/openrouter api_key=dev-openrouter >/dev/null
  srv kv put aegis-kv/mvp-a/intake/masker key=dev-masker >/dev/null
  srv kv put aegis-kv/mvp-a/intake/audit-signing key=dev-audit-signing >/dev/null
  srv kv put aegis-kv/mvp-a/intake/alertmanager token=dev-alertmanager >/dev/null
  srv kv put aegis-kv/mvp-a/intake/prometheus token=dev-prometheus >/dev/null
  srv kv put aegis-kv/mvp-a/intake/killswitch-s3 access_key_id=dev-ks-id secret_key=dev-ks-secret >/dev/null
  srv kv put aegis-kv/mvp-a/audit-anchor access_key_id=dev-anchor-id secret_key=dev-anchor-secret >/dev/null
  srv kv put aegis-kv/mvp-a/other secret=not-for-intake >/dev/null
}

# --- Cilium (режим cilium в run-ha.sh и run-netpol.sh в deploy/intake/dev) -----------------------------------------
skip() { echo "SKIP  $*"; }

cilium_ver=1.20.4
cilium_img=quay.io/cilium/cilium:v$cilium_ver;             cilium_digest=sha256:20fe92e4c86641233a450098c158d2d29085f3419931ab6bf681d2485dedf16e
operator_img=quay.io/cilium/operator-generic:v$cilium_ver; operator_digest=sha256:7a7a3489dc66ad67e420d285c8a8d2e169b0957ad15e120f593d27081bf38d82

# Образ с тегом и digest (хост скачивает по digest, в кластере — по тегу с IfNotPresent: digest при `minikube image load` теряется).
load_one() { # $1 — образ с тегом, $2 — digest
  docker pull -q "$1@$2" >/dev/null
  docker tag "$1@$2" "$1"
  [ "$(docker inspect --format '{{index .RepoDigests 0}}' "$1")" = "${1%:*}@$2" ] || { echo "digest $1 не совпал" >&2; exit 1; }
  minikube -p "$cluster" image load "$1" >/dev/null
}

# minikube без CNI + Cilium из Helm-чарта (встроенный Envoy в агенте, l7Proxy); образы закреплены по digest и загружаются с хоста.
# Без `Proxy Status: OK` стенд останавливается: L7-политики (DNS-фильтр, serverNames) без прокси не работают.
start_cluster_cilium() {
  minikube status -p "$cluster" >/dev/null 2>&1 || \
    minikube start -p "$cluster" --driver=docker --network-plugin=cni --cni=false --cpus=2 --memory=4096 >/dev/null
  load_one "$cilium_img" "$cilium_digest"
  load_one "$operator_img" "$operator_digest"
  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm upgrade --install cilium cilium/cilium --kube-context "$ctx" --version "$cilium_ver" -n kube-system \
    --set operator.replicas=1 --set ipam.mode=kubernetes --set image.useDigest=false --set operator.image.useDigest=false \
    --set image.pullPolicy=IfNotPresent --set operator.image.pullPolicy=IfNotPresent --set envoy.enabled=false --set l7Proxy=true >/dev/null
  k -n kube-system rollout status ds/cilium --timeout=300s >/dev/null
  k -n kube-system rollout status deploy/cilium-operator --timeout=300s >/dev/null
  k wait --for=condition=Ready node --all --timeout=180s >/dev/null
  k -n kube-system rollout status deploy/coredns --timeout=180s >/dev/null
  echo "== Cilium $cilium_ver"
  local cstat
  cstat=$(k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg status 2>&1) || true
  if grep -q 'Proxy Status:.*OK' <<<"$cstat"; then pass "Proxy Status: OK"
  else fail "Proxy Status не OK (L7-прокси не работает)"; grep -i 'proxy' <<<"$cstat" | sed 's/^/      /'; echo "провалов: $fails"; exit 1; fi
}

# Применяет манифесты политик из Git (каталоги с *.yaml); меняется только порт API-сервера по маркеру `# kube-api-port`.
# Порядок: dry-run=server для всех, затем cilium-*.yaml, затем остальные (default-deny после правил, иначе поды изолированы).
apply_netpols() { # $1... — каталоги; namespaces в них должны существовать
  local api_port tmp d f i=0 o args=()
  api_port=$(k -n default get endpoints kubernetes -o jsonpath='{.subsets[0].ports[0].port}' 2>/dev/null)
  tmp=$(mktemp -d)
  for d in "$@"; do
    i=$((i + 1)); mkdir "$tmp/$i"
    for f in "$d"/*.yaml; do
      o="$tmp/$i/$(basename "$f")"
      sed "s/\(port: \"\)443\(\" # kube-api-port\)/\1$api_port\2/" "$f" > "$o"
      if [ "$api_port" != 443 ] && grep -q 'kube-api-port' "$f" && cmp -s "$o" "$f"; then fail "маркер kube-api-port не найден в $f"; fi
      args+=(-f "$o")
    done
  done
  if k apply --dry-run=server "${args[@]}" >/dev/null; then pass "kubectl apply --dry-run=server"
  else fail "dry-run=server отклонён"; rm -rf "$tmp"; echo "провалов: $fails"; exit 1; fi
  for f in "$tmp"/*/cilium-*.yaml; do k apply -f "$f" >/dev/null; done
  for f in "$tmp"/*/*.yaml; do case "${f##*/}" in cilium-*) ;; *) k apply -f "$f" >/dev/null ;; esac; done
  rm -rf "$tmp"
}

# Ждёт готовности endpoint'а Cilium (политики загружены): $1 — метка вида k8s:app=aegis-intake; до 120 с.
wait_cilium_ready() {
  local st="" _
  for _ in $(seq 1 60); do
    st=$(k -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg endpoint list -o json 2>/dev/null \
         | jq -r --arg l "$1" '[.[] | select(.status.identity.labels | index($l)) | .status.state] | first // ""') || st=""
    [ "$st" = ready ] && return 0; sleep 2
  done
  return 1
}
