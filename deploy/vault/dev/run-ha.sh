#!/usr/bin/env bash
# HA-стенд OpenBao: Raft на 3 узлах, TLS, Shamir 3/2 с PGP-шифрованием долей (identity-secrets-mvp-a.md §9, §10, п. 1–2).
# Ставит боевые values (../server/openbao-ha.yaml + оверлей values-openbao-ha.yaml) на minikube, проходит init и unseal
# и проверяет рестарты, потерю кворума и break-glass. Каждый запуск начинается с нуля (helm uninstall + удаление PVC).
# Только для стенда: CA и PGP-ключи одноразовые, секреты фиктивные. Доли и токены не печатаются и не пишутся на диск
# в открытом виде; ввод долей — через stdin, токен — первой строкой stdin (не в argv).
#
#   ./run-ha.sh          поднять стенд и прогнать проверки
#   ./run-ha.sh down     удалить release, PVC и namespace openbao-ha (профиль minikube остаётся)
# Состояние (зашифрованный ответ init) — в ${XDG_RUNTIME_DIR:-$HOME/.cache}/aegis-vault-dev/openbao-ha, не в репозитории.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vault_dir=$(cd "$here/.." && pwd)
cluster=aegis-vault-dev
ctx=$cluster
ns=openbao-ha
image=openbao/openbao:2.7.2; cli=bao
digest=$(grep -A1 '^  openbao)' "$here/run.sh" | grep -oE 'sha256:[0-9a-f]{64}' | head -n1)
chart_ver=0.30.7
addr="https://openbao-active.$ns.svc:8200"   # active-сервис: попадает только на активный узел, sealed-узлы не мешают
# Причины отказа агента: sealed-узел отвечает 503, а когда активного узла нет, у openbao-active нет адресов.
sealed_re='EOF|sealed|503|connection refused|no route to host'
noquorum_re=$sealed_re
state=${XDG_RUNTIME_DIR:-$HOME/.cache}/aegis-vault-dev/openbao-ha
source "$here/lib.sh"

if [ "${1:-}" = down ]; then
  helm uninstall openbao -n "$ns" --kube-context "$ctx" --wait >/dev/null 2>&1 || true
  k delete ns "$ns" --ignore-not-found --wait >/dev/null
  rm -rf "$state"; exit 0
elif [ -n "${1:-}" ]; then
  echo "использование: $0 [down]" >&2; exit 2
fi

work=$(mktemp -d)
trap 'GNUPGHOME="$work/gnupg" gpgconf --kill gpg-agent 2>/dev/null || true; rm -rf "$work"' EXIT
umask 077
rm -rf "$state"; mkdir -p -m 700 "$state"; chmod 700 "${state%/*}"

# --- обёртки над CLI внутри подов ---------------------------------------------------------------------------------
# Токен ($tok) уходит первой строкой stdin и читается в env внутри пода, поэтому не попадает в argv.
_bao() { # $1 — номер пода, дальше аргументы bao; остальной stdin вызывающего уходит в bao
  local n=$1; shift
  k -n "$ns" exec -i "openbao-$n" -c openbao -- sh -c 'IFS= read -r BAO_TOKEN; [ -n "$BAO_TOKEN" ] && export BAO_TOKEN; exec bao "$@"' sh "$@"
}
bao_pod() { printf '%s\n' "${tok:-}" | _bao "$@"; }
bao_pod_in() { { printf '%s\n' "${tok:-}"; cat; } | _bao "$@"; }

# JSON `bao status` (код 2 у sealed — не ошибка); ждёт, пока под начнёт отвечать.
st() { # $1 — номер пода
  local i out
  for i in $(seq 1 30); do
    out=$(k -n "$ns" exec "openbao-$1" -c openbao -- bao status -format=json 2>/dev/null) || true
    if jq -e 'has("initialized")' >/dev/null 2>&1 <<<"$out"; then echo "$out"; return; fi
    sleep 1
  done
  echo '{}'
}
mode() { st "$1" | jq -r 'if .sealed == true then "sealed" elif .sealed == false then (if .is_self == true then "active" else "standby" end) else "down" end'; }
wait_mode() { # $1 — под, $2 — "sealed", "unsealed" (active или standby) или "initialized"; до 120 с
  local i m
  for i in $(seq 1 60); do
    case "$2" in
      initialized) [ "$(st "$1" | jq -r '.initialized')" = true ] && return 0 ;;
      sealed)      [ "$(mode "$1")" = sealed ] && return 0 ;;
      unsealed)    m=$(mode "$1"); [ "$m" = active ] || [ "$m" = standby ] && return 0 ;;
    esac
    sleep 2
  done
  return 1
}
find_leader() { # печатает номер активного пода; ждёт до 120 с
  local i n
  for i in $(seq 1 60); do
    for n in 0 1 2; do [ "$(mode "$n")" = active ] && { echo "$n"; return 0; }; done
    sleep 2
  done
  return 1
}
wait_running() { # $1 — под: ждёт его создания и фазы Running
  local i
  for i in $(seq 1 90); do
    [ "$(k -n "$ns" get pod "openbao-$1" -o jsonpath='{.status.phase}' 2>/dev/null)" = Running ] && return 0
    sleep 2
  done
  return 1
}
active_ready() { # ждёт, пока у openbao-active появится адрес (метка active ставится service_registration)
  local i
  for i in $(seq 1 60); do
    [ -n "$(k -n "$ns" get endpoints openbao-active -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)" ] && return 0
    sleep 2
  done
  return 1
}

# Ввод доли только через stdin (key=-). Доли — в массиве share (в памяти, на диск не пишутся).
unseal_one() { printf %s "$2" | k -n "$ns" exec -i "openbao-$1" -c openbao -- bao write -format=json sys/unseal key=-; }
unseal_quorum() { # $1 — под: две разные доли, для разных подов — разные пары
  unseal_one "$1" "${share[$(($1 % 3))]}" >/dev/null
  unseal_one "$1" "${share[$((($1 + 1) % 3))]}" >/dev/null
}
unseal_all() { # поднимает перечисленные поды и ждёт активный узел
  local n
  for n in "$@"; do wait_mode "$n" initialized; unseal_quorum "$n"; done
  for n in "$@"; do wait_mode "$n" unsealed; done
  find_leader >/dev/null
}

# Команда CLI от текущего токена на активном узле.
srv() { bao_pod "$(find_leader)" "$@"; }
srv_in() { bao_pod_in "$(find_leader)" "$@"; }

# Все ли 3 пода сообщают один и тот же лидер, и это активный под.
leader_ok() { # $1 — номер активного пода
  local n addrs ip
  addrs=$(for n in 0 1 2; do [ "$(mode "$n")" = sealed ] || st "$n" | jq -r '.leader_address'; done | sort -u)
  ip=$(k -n "$ns" get pod "openbao-$1" -o jsonpath='{.status.podIP}')
  [ "$addrs" = "https://$ip:8200" ]
}
peers() { srv operator raft list-peers -format=json | jq -r '.data.config.servers | "\(length) \(map(select(.voter)) | length) \(map(select(.leader)) | length)"'; }
check_peers() { # $1 — подпись; новый узел сначала non-voter, autopilot повышает его через ~10–30 с
  local p i
  for i in $(seq 1 20); do p=$(peers); [ "$p" = "3 3 1" ] && break; sleep 3; done
  [ "$p" = "3 3 1" ] && pass "$1: raft list-peers — 3 voter, один leader" || fail "$1: raft list-peers: '$p' (ожидается '3 3 1')"
}
# Сервер недоступен (все sealed или нет кворума): агент входит с бесконечными повторами (backoff), init-контейнер не завершается,
# под остаётся в Pending и контейнер intake не стартует — fail-closed. Причина — в логе агента, а не ошибка конфигурации.
expect_blocked() { # $1 — под, $2 — название, $3 — regex причины
  start_pod "$1"
  local i log="" init="" ph=""
  for i in $(seq 1 45); do
    log=$(k -n aegis-system logs "$1" -c vault-agent 2>&1 | tail -n 40) || true
    grep -qE 'error authenticating' <<<"$log" && break; sleep 2
  done
  sleep 10
  log=$(k -n aegis-system logs "$1" -c vault-agent 2>&1 | tail -n 40) || true
  ph=$(k -n aegis-system get pod "$1" -o jsonpath='{.status.phase}')
  init=$(k -n aegis-system get pod "$1" -o jsonpath='{.status.initContainerStatuses[0].state.running.startedAt}')
  if [ "$ph" != Pending ] || [ -z "$init" ]; then fail "$2: фаза $ph, init-контейнер не висит в Running"
  elif grep -qiE 'error loading configuration' <<<"$log"; then fail "$2: агент упал на конфигурации, а не на недоступности сервера"
  elif grep -qE 'error authenticating' <<<"$log" && grep -qiE "$3" <<<"$log"; then pass "$2: init-контейнер не может войти (повторы с backoff), под Pending, intake не запущен"
  else fail "$2: под завис, но причина неожиданная"; fi
  grep -iE 'error' <<<"$log" | tail -n 2 | cut -c1-300 | sed 's/^/      /' || true
  k -n aegis-system delete pod "$1" --wait=false >/dev/null
}
secrets_ok() { # $1 — подпись; ожидается Succeeded
  phase=$(run_pod secrets-ok)
  [ "$phase" = Succeeded ] && pass "$1: secrets-ok Succeeded" || { fail "$1: secrets-ok $phase"; agent_log secrets-ok 8; }
}
# Работающий intake (держит файлы в tmpfs) не должен перезапускаться и падать при рестартах OpenBao.
hold_ok() { # $1 — подпись шага
  local ph rc
  ph=$(k -n aegis-system get pod intake-long -o jsonpath='{.status.phase}')
  rc=$(k -n aegis-system get pod intake-long -o jsonpath='{.status.containerStatuses[?(@.name=="intake")].restartCount}')
  [ "$ph" = Running ] && [ "$rc" = 0 ] && pass "$1: intake-long Running, restartCount 0" || fail "$1: intake-long фаза $ph, restartCount '$rc'"
}

echo "== openbao-ha ($image, TLS, Raft 3, Shamir 3/2)"

# --- кластер, TLS и сервер -------------------------------------------------------------------------------------
start_cluster
load_images "$image" "$digest"
helm repo add openbao https://openbao.github.io/openbao-helm >/dev/null 2>&1 || true
helm uninstall openbao -n "$ns" --kube-context "$ctx" --wait >/dev/null 2>&1 || true   # PVC держатся подами, пока те не удалены
k get ns "$ns" >/dev/null 2>&1 || k create ns "$ns" >/dev/null
k -n "$ns" delete pvc --all --wait --timeout=120s >/dev/null
k get ns aegis-system >/dev/null 2>&1 || k create ns aegis-system >/dev/null
k -n aegis-system get sa aegis-intake >/dev/null 2>&1 || k -n aegis-system create sa aegis-intake >/dev/null

# Одноразовый CA и серверный сертификат (в бою — cert-manager или внутренний CA).
tls="$work/tls"; mkdir "$tls"
openssl ecparam -name prime256v1 -genkey -noout -out "$tls/ca-priv.pem"
openssl req -x509 -new -key "$tls/ca-priv.pem" -subj "/CN=aegis-vault-dev CA" -days 2 -out "$tls/ca.pem" \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
openssl ecparam -name prime256v1 -genkey -noout -out "$tls/srv-priv.pem"
openssl req -new -key "$tls/srv-priv.pem" -subj "/CN=openbao" -out "$tls/srv.csr"
san="DNS:openbao,DNS:openbao.$ns,DNS:openbao.$ns.svc,DNS:openbao-active.$ns.svc,DNS:openbao-internal,DNS:*.openbao-internal,DNS:*.openbao-internal.$ns.svc,DNS:localhost,IP:127.0.0.1"
printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' "$san" > "$tls/ext"
openssl x509 -req -in "$tls/srv.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca-priv.pem" -CAcreateserial -days 2 -extfile "$tls/ext" -out "$tls/srv.crt" 2>/dev/null
k -n "$ns" create secret generic openbao-tls --from-file=tls.crt="$tls/srv.crt" --from-file=tls.key="$tls/srv-priv.pem" \
  --from-file=ca.crt="$tls/ca.pem" --dry-run=client -o yaml | k apply -f - >/dev/null
k -n aegis-system create configmap vault-ca --from-file=ca.pem="$tls/ca.pem" --dry-run=client -o yaml | k apply -f - >/dev/null

# Без --wait: до unseal поды не станут Ready (readiness-проба `bao status` даёт код 2 у sealed).
helm upgrade --install openbao openbao/openbao --kube-context "$ctx" --version "$chart_ver" -n "$ns" \
  -f "$vault_dir/server/openbao-ha.yaml" -f "$here/values-openbao-ha.yaml" >/dev/null
for n in 0 1 2; do wait_running "$n"; done

# 1. До init: три пода Running, не инициализированы, sealed, не Ready.
ok=1
for n in 0 1 2; do
  s=$(st "$n"); ready=$(k -n "$ns" get pod "openbao-$n" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
  [ "$(jq -r '"\(.initialized) \(.sealed)"' <<<"$s")" = "false true" ] && [ "$ready" = False ] || { ok=0; echo "      openbao-$n: $(jq -c '{initialized,sealed}' <<<"$s") Ready=$ready"; }
done
[ "$ok" = 1 ] && pass "до init: 3 пода Running, initialized=false, sealed=true, не Ready" || fail "до init: состояние подов неожиданное"

# --- init: три одноразовых PGP-ключа «держателей» ----------------------------------------------------------------
export GNUPGHOME="$work/gnupg"; mkdir -m 700 "$GNUPGHOME"
pgp=()
for i in 1 2 3; do
  uid="holder$i <holder$i@example.invalid>"
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$uid" rsa3072 cert,sign never 2>/dev/null
  fpr=$(gpg --list-keys --with-colons "holder$i@example.invalid" 2>/dev/null | awk -F: '/^fpr/ {print $10; exit}')
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$fpr" rsa3072 encr never 2>/dev/null
  pgp+=("$(gpg --export "$fpr" | base64 -w0)")
done
# Тело init — через stdin: pgp_keys для долей и root_token_pgp_key для root-токена (первый ключ).
initres=$(jq -n --arg a "${pgp[0]}" --arg b "${pgp[1]}" --arg c "${pgp[2]}" \
  '{secret_shares: 3, secret_threshold: 2, pgp_keys: [$a, $b, $c], root_token_pgp_key: $a}' \
  | k -n "$ns" exec -i openbao-0 -c openbao -- bao write -format=json sys/init -)
printf '%s\n' "$initres" > "$state/init.json"   # только зашифрованные доли и root
share=()
for i in 0 1 2; do share+=("$(jq -r ".data.keys_base64[$i]" <<<"$initres" | base64 -d | gpg --batch -d 2>/dev/null || true)"); done
root=$(jq -r '.data.root_token' <<<"$initres" | base64 -d | gpg --batch -d 2>/dev/null || true)
ok=1
[ "$(jq '.data.keys_base64 | length' <<<"$initres")" = 3 ] || ok=0
for i in 0 1 2; do [[ "${share[$i]}" =~ ^[0-9a-f]{66}$ ]] || ok=0; done
[[ "$root" =~ ^(s|hvs)\. ]] || ok=0
# Открытого текста в ответе нет: зашифрованное значение не совпадает с расшифрованным.
for i in 0 1 2; do [ "$(jq -r ".data.keys_base64[$i]" <<<"$initres")" != "${share[$i]}" ] || ok=0; done
[ "$ok" = 1 ] && pass "init: 3 доли и root-токен зашифрованы PGP, расшифровываются (в $state — только шифртекст)" || fail "init: доли или root-токен не расшифровались"
unset initres

# 3. Порог: одна доля — sealed, progress 1, t 2; чужая доля — ошибка; две настоящие — unsealed.
r=$(unseal_one 0 "${share[0]}" | jq -c '.data | {sealed, progress, t}')
[ "$r" = '{"sealed":true,"progress":1,"t":2}' ] && pass "порог: после одной доли sealed, progress 1, t 2" || fail "порог: после одной доли $r"
if out=$(timeout 90 bash -c 'printf %s "$1" | kubectl --context "$2" -n "$3" exec -i openbao-0 -c openbao -- bao write -format=json sys/unseal key=- 2>&1' _ "$(openssl rand -hex 33)" "$ctx" "$ns"); then
  fail "порог: чужая доля принята"
else
  pass "порог: чужая доля отвергнута ($(grep -oE '^\* .*|context deadline exceeded' <<<"$out" | head -n1 | cut -c1-80))"
fi
[ "$(mode 0)" = sealed ] && pass "порог: после чужой доли под sealed" || fail "порог: под не sealed после чужой доли"
bao_pod 0 write -format=json sys/unseal reset=true >/dev/null 2>&1 || true   # на случай, если счётчик не сброшен
unseal_quorum 0
wait_mode 0 unsealed && [ "$(find_leader)" = 0 ] && pass "порог: после двух настоящих долей openbao-0 unsealed и активен" || fail "порог: openbao-0 не поднялся"

# 4. Остальные поды: join через retry_join, затем unseal своей парой долей.
unseal_all 1 2
tok=$root
check_peers "кластер"
n_audit=$(srv audit list -format=json | jq 'length')
[ "$n_audit" = 2 ] && pass "audit list: ровно 2 device (из конфигурации)" || fail "audit list: $n_audit device (ожидается 2)"
leader_ok "$(find_leader)" && pass "sys/leader согласован на всех подах" || fail "sys/leader не согласован"

# --- настройка: то, что в бою делает CI-применитель (от root, до его отзыва) ------------------------------------------
srv secrets enable -path=aegis-kv -version=2 kv >/dev/null
srv auth enable kubernetes >/dev/null
srv write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443 >/dev/null
srv_in policy write aegis-intake - < "$vault_dir/policies/aegis-intake.json" >/dev/null
srv_in write auth/kubernetes/role/aegis-intake - < "$vault_dir/roles/aegis-intake.json" >/dev/null
put_all
# Оператор стенда после отзыва root: только чтение конфигурации Raft и списка audit device. Orphan — иначе отзыв root его снёс бы.
srv_in policy write ops-dev - >/dev/null <<'EOF'
path "sys/storage/raft/configuration" { capabilities = ["read"] }
path "sys/audit" { capabilities = ["read", "sudo"] }
EOF
# Токен-инициатор break-glass (bgi): политика из Git, orphan, periodic 720h, без default-политики и explicit_max_ttl.
srv_in policy write bg-init - < "$vault_dir/policies/bg-init.json" >/dev/null
bgi=$(srv token create -orphan -period=720h -policy=bg-init -no-default-policy -field=token)
ops=$(srv token create -orphan -policy=ops-dev -ttl=3h -field=token)
# bgi: periodic 720h, одна политика bg-init (без default), без explicit_max_ttl и ограничения числа использований; продлевается сам.
bgi_acc=$(tok=$bgi bao_pod 0 token lookup -format=json | jq -r '.data.accessor')
li=$(tok=$bgi bao_pod 0 token lookup -format=json | jq -c '.data | {period, explicit_max_ttl, num_uses, orphan, policies}')
[ "$li" = '{"period":2592000,"explicit_max_ttl":0,"num_uses":0,"orphan":true,"policies":["bg-init"]}' ] && pass "bgi: periodic 720h, explicit_max_ttl 0, orphan, политики только bg-init (без default)" || fail "bgi: lookup-self $li"
tok=$bgi bao_pod 0 token renew -format=json | jq -e '.auth.renewable == true' >/dev/null && pass "bgi: renew-self работает без default-политики" || fail "bgi: renew-self не работает"
jq --arg a "$addr" '.vault.address = $a' "$vault_dir/agent/aegis-intake.json" > "$work/agent.json"   # ca_cert остаётся из Git
k -n aegis-system create configmap aegis-intake-vault-agent --from-file=aegis-intake.json="$work/agent.json" --dry-run=client -o yaml | k apply -f - >/dev/null

# 5. Секреты по TLS через active-сервис; права 0400; вход по роли с проверкой сертификата (BAO_CACERT).
secrets_ok "TLS"
bad=$(k -n aegis-system logs secrets-ok -c intake | awk '/^-/ && $1 != "-r--------" {print}')
[ -z "$bad" ] && pass "права файлов 0400" || fail "права файлов не 0400: $bad"
k -n aegis-system delete pod perms --ignore-not-found --wait >/dev/null
k -n aegis-system apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: perms, namespace: aegis-system}
spec:
  serviceAccountName: aegis-intake
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: cli
      image: $image
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep 300"]
      env: [{name: BAO_ADDR, value: "$addr"}, {name: BAO_CACERT, value: /vault/ca/ca.pem}, {name: HOME, value: /tmp}]
      securityContext: {runAsUser: 10001, runAsNonRoot: true, allowPrivilegeEscalation: false}
      volumeMounts: [{name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true}, {name: vault-ca, mountPath: /vault/ca, readOnly: true}]
  volumes:
    - name: vault-token
      projected: {sources: [{serviceAccountToken: {audience: vault, expirationSeconds: 600, path: token}}]}
    - {name: vault-ca, configMap: {name: vault-ca}}
EOF
k -n aegis-system wait --for=condition=Ready pod/perms --timeout=120s >/dev/null
permsout=$(k -n aegis-system exec perms -- sh -c '
  bao write -field=token auth/kubernetes/login role=aegis-intake jwt=@/var/run/secrets/vault/token > /tmp/t || exit 9
  export BAO_TOKEN=$(cat /tmp/t)
  try() { if bao "$@" >/dev/null 2>/tmp/e; then echo "allowed $*"; else grep -q "permission denied" /tmp/e && echo "denied $*" || { echo "error $*"; head -2 /tmp/e; }; fi; }
  try read aegis-kv/data/mvp-a/intake/openrouter
  try read aegis-kv/data/mvp-a/other
  try kv put aegis-kv/mvp-a/intake/openrouter api_key=x
  try policy write evil /dev/null
' 2>&1 || true)
[ "$(grep -c '^allowed read aegis-kv/data/mvp-a/intake/openrouter$' <<<"$permsout")" = 1 ] && pass "по TLS с BAO_CACERT: чтение разрешённого пути" || fail "по TLS: разрешённый путь не прочитан: $permsout"
for p in "read aegis-kv/data/mvp-a/other" "kv put aegis-kv/mvp-a/intake/openrouter api_key=x" "policy write evil /dev/null"; do
  grep -qx "denied $p" <<<"$permsout" && pass "по TLS: permission denied: $p" || fail "по TLS: должно быть denied: $p"
done
k -n aegis-system delete pod perms --wait=false >/dev/null

# 6. Отзыв root: root-токен больше не работает; дальше — оператор стенда.
bao_pod 0 token revoke -self >/dev/null 2>&1 || true   # токен пока в $tok (root)
if out=$(srv policy list 2>&1); then fail "root после отзыва ещё работает"; else grep -qE '403|permission denied' <<<"$out" && pass "root отозван: запрос root-токеном — 403" || fail "root отозван, но ошибка не 403: $out"; fi
tok=$ops; unset root
check_peers "после отзыва root (токен оператора)"

# 9. Работающий intake: запускается до рестартов и должен пережить их все.
start_pod intake-long 1500
k -n aegis-system wait --for=jsonpath='{.status.phase}'=Running pod/intake-long --timeout=180s >/dev/null
hold_ok "запуск"

# 7. Рестарт одного (standby) пода.
lead=$(find_leader); f=$(((lead + 1) % 3))
k -n "$ns" delete pod "openbao-$f" --wait >/dev/null
wait_running "$f"; wait_mode "$f" sealed
[ "$(mode "$f")" = sealed ] && pass "рестарт openbao-$f: вернулся sealed" || fail "рестарт openbao-$f: не sealed"
secrets_ok "рестарт openbao-$f"
unseal_all "$f"
check_peers "после unseal openbao-$f"
leader_ok "$(find_leader)" && pass "после unseal openbao-$f: sys/leader согласован" || fail "после unseal openbao-$f: sys/leader не согласован"
hold_ok "рестарт одного пода"

# 8. Удаление лидера.
lead=$(find_leader)
k -n "$ns" delete pod "openbao-$lead" --wait >/dev/null
new=""
for i in $(seq 1 60); do
  for n in 0 1 2; do [ "$n" != "$lead" ] && [ "$(mode "$n")" = active ] && new=$n; done
  [ -n "$new" ] && break; sleep 2
done
[ -n "$new" ] && pass "удаление лидера openbao-$lead: новый лидер openbao-$new" || fail "удаление лидера: новый лидер не выбран"
active_ready || true
secrets_ok "после удаления лидера"
wait_running "$lead"; wait_mode "$lead" sealed
unseal_all "$lead"
[ "$(mode "$lead")" = standby ] && pass "старый лидер openbao-$lead после unseal — standby" || fail "старый лидер openbao-$lead: $(mode "$lead")"
check_peers "после возврата старого лидера"
hold_ok "удаление лидера"

# 10. Рестарт всех узлов: все sealed, intake не стартует, после unseal данные на месте.
t0=$(date +%s)
k -n "$ns" delete pod openbao-0 openbao-1 openbao-2 --wait >/dev/null
for n in 0 1 2; do wait_running "$n"; done
for n in 0 1 2; do wait_mode "$n" sealed; done
all=1; for n in 0 1 2; do [ "$(mode "$n")" = sealed ] || all=0; done
[ "$all" = 1 ] && pass "рестарт всех: все три пода sealed" || fail "рестарт всех: не все sealed"
expect_blocked secrets-ok "все узлы sealed: новый под не стартует" "$sealed_re"
hold_ok "все узлы sealed"
unseal_all 0 1 2
t1=$(date +%s)
secrets_ok "после unseal всех"
t2=$(date +%s)
echo "      полный рестарт: до готовности кластера (unseal двумя долями на каждом поде) $((t1 - t0)) с, до успешного secrets-ok $((t2 - t0)) с"
check_peers "после рестарта всех (данные Raft пережили рестарт)"
hold_ok "рестарт всех узлов"

# 11. Потеря кворума: два пода sealed, один unsealed.
lead=$(find_leader); others=(); for n in 0 1 2; do [ "$n" != "$lead" ] && others+=("$n"); done
k -n "$ns" delete pod "openbao-${others[0]}" "openbao-${others[1]}" --wait >/dev/null
for n in "${others[@]}"; do wait_running "$n"; wait_mode "$n" sealed; done
for i in $(seq 1 30); do [ "$(mode "$lead")" != active ] && break; sleep 2; done   # лидер без кворума отдаёт лидерство
expect_blocked secrets-ok "потеря кворума: новый под не стартует" "$noquorum_re"
unseal_all "${others[@]}"
secrets_ok "после восстановления кворума"
hold_ok "потеря кворума"

xor_decode() { # $1 — otp, $2 — encoded_token (base64 без padding): токен = encoded XOR otp; только bash и coreutils
  local b64=$2 i out="" c; local -a bytes
  while [ $(( ${#b64} % 4 )) -ne 0 ]; do b64+="="; done
  mapfile -t bytes < <(printf %s "$b64" | base64 -d | od -An -v -tu1 -w1)
  for i in "${!bytes[@]}"; do
    printf -v c '%02x' $(( bytes[i] ^ $(printf '%d' "'${1:i:1}") ))
    out+=$(printf "\\x$c")
  done
  printf %s "$out"
}
# 12. Break-glass: generate-root кворумом порог 2. В OpenBao 2.7.2 sys/generate-root-token/* требует токена (старый
# безтокенный sys/generate-root/* отвечает 405), поэтому нужен заранее выданный токен-инициатор только с этим правом (bgi).
lead=$(find_leader)
gr=$(tok=$bgi bao_pod "$lead" operator generate-root -init -format=json)
nonce=$(jq -r '.nonce' <<<"$gr"); otp=$(jq -r '.otp' <<<"$gr")
upd() { { printf '%s\n' "$bgi"; printf %s "$1"; } | k -n "$ns" exec -i "openbao-$lead" -c openbao -- sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN; exec bao write -format=json sys/generate-root-token/update key=- nonce="$1"' sh "$nonce"; }
r=$(upd "${share[0]}" | jq -c '.data | {progress, required, complete}')
if jq -e '.progress == 1 and .required == 2 and .complete == false' >/dev/null <<<"$r"; then pass "break-glass: одна доля — generate-root не завершён (progress 1/2)"; else fail "break-glass: после одной доли $r"; fi
# У bgi нет delete: он не может отменить начатую процедуру (та же атака, что CVE-2026-5807); попытка продолжается второй долей.
if out=$(tok=$bgi bao_pod "$lead" operator generate-root -cancel 2>&1); then fail "break-glass: bgi отменил чужую процедуру generate-root"; else grep -q '403' <<<"$out" && pass "break-glass: bgi не может отменить generate-root (403, нет delete)" || fail "break-glass: отмена bgi — не 403: $out"; fi
enc=$(upd "${share[2]}" | jq -r 'if .data.complete then .data.encoded_token else "" end')
if [ -n "$enc" ]; then
  bg=$(xor_decode "$otp" "$enc")   # OTP и зашифрованный токен не уходят в argv, поэтому XOR на хосте
  pass "break-glass: вторая доля — токен выпущен и расшифрован OTP"
  pl=$(tok=$bg bao_pod "$lead" policy list 2>&1 || true)
  grep -qw default <<<"$pl" && pass "break-glass: токен читает sys/policy" || fail "break-glass: токен не читает sys/policy"
  n=$(k -n "$ns" exec "openbao-$lead" -c openbao -- grep -c 'sys/generate-root-token' /openbao/audit/audit.log || true)
  [ "${n:-0}" -gt 0 ] && pass "break-glass: sys/generate-root-token в audit.log активного пода ($n записей)" || fail "break-glass: sys/generate-root-token нет в audit.log"
else
  fail "break-glass: вторая доля не завершила generate-root"
fi
unset enc otp nonce gr

# 12б. Смена ключей (rotate-keys, смена держателя) тем же bgi: одна доля не завершает, отмены у bgi нет, вторая завершает.
ri=$(tok=$bgi bao_pod "$lead" operator rotate-keys -init -key-shares=3 -key-threshold=2 -format=json)
rn=$(jq -r '.nonce' <<<"$ri")
rupd() { { printf '%s\n' "$bgi"; printf %s "$1"; } | k -n "$ns" exec -i "openbao-$lead" -c openbao -- sh -c 'IFS= read -r BAO_TOKEN; export BAO_TOKEN; exec bao write -format=json sys/rotate/root/update key=- nonce="$1"' sh "$rn"; }
r=$(rupd "${share[0]}" | jq -c '.data | {progress, required, complete}')
if jq -e '.progress == 1 and .required == 2 and .complete != true' >/dev/null <<<"$r"; then pass "rotate-keys: одна доля — смена ключей не завершена (progress 1/2)"; else fail "rotate-keys: после одной доли $r"; fi
if out=$(tok=$bgi bao_pod "$lead" operator rotate-keys -cancel 2>&1); then fail "rotate-keys: bgi отменил процедуру"; else grep -q '403' <<<"$out" && pass "rotate-keys: bgi не может отменить процедуру (403, нет delete)" || fail "rotate-keys: отмена bgi — не 403: $out"; fi
if rupd "${share[1]}" | jq -e '.data.complete == true and (.data.keys_base64 | length) == 3' >/dev/null; then pass "rotate-keys: вторая доля завершила смену, выданы 3 новые доли"; else fail "rotate-keys: вторая доля не завершила смену"; fi
unset share rn ri
find_leader >/dev/null && pass "после смены ключей кластер работает, лидер есть" || fail "после смены ключей лидера нет"

# --- завершение -------------------------------------------------------------------------------------------------
tok=$ops bao_pod "$lead" token revoke -self >/dev/null 2>&1 || true
# У bgi нет права revoke-self: отзывает его по accessor токен break-glass (так же — утёкший bgi), затем отзывается и сам этот токен.
tok=$bg bao_pod "$lead" token revoke -accessor "$bgi_acc" >/dev/null 2>&1 || true
tok=$bg bao_pod "$lead" token revoke -self >/dev/null 2>&1 || true
if tok=$bg bao_pod "$lead" policy list >/dev/null 2>&1; then fail "break-glass токен не отозван"; else pass "break-glass токен отозван"; fi
unset bg
# Отозванный (или истёкший) bgi — 403: новый выдать нечем без восстановления (README, «Потеря bgi»).
if out=$(tok=$bgi bao_pod "$lead" operator generate-root -init 2>&1); then fail "отозванный bgi ещё работает"; else grep -q '403' <<<"$out" && pass "отозванный bgi: generate-root -init — 403" || fail "отозванный bgi: не 403: $out"; fi
k -n aegis-system delete pod intake-long --wait=false >/dev/null
echo "== openbao-ha: провалов $fails"
exit $((fails > 0))
