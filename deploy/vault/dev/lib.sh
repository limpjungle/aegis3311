# Общие функции стенда (source из run.sh и run-ha.sh). Ожидает переменные: here, cluster, ctx, image, cli.
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
