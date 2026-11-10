#!/usr/bin/env bash
# Dev-стенд: minikube (драйвер docker) + OpenBao или Vault в dev-режиме; применяет политику, роль и конфигурацию агента из deploy/vault/
# и проверяет их (identity-secrets-mvp-a.md §10, п. 5–7; permission denied на чужих путях).
# Только для стенда: dev-режим без TLS и с root-токеном "root", секреты — фиктивные.
#
#   ./run.sh openbao|vault        поднять стенд и прогнать проверки
#   ./run.sh down                 удалить профиль minikube
# kind не используется: на ядре 7.2 узел kindest/node:v1.37.0 (kind 0.33) не запускает статические поды control plane.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
vault_dir=$(cd "$here/.." && pwd)
cluster=aegis-vault-dev
ctx=$cluster

product=${1:-}
case "$product" in
  openbao) chart=openbao/openbao; chart_ver=0.30.7; cli=bao
           image=openbao/openbao:2.7.2; digest=sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f ;;
  vault)   chart=hashicorp/vault; chart_ver=0.34.1; cli=vault
           image=hashicorp/vault:2.0.4; digest=sha256:5be49781ecf78bfe775c5309c6a4d9f4e9e040b6c885c99eb2b12fb69855e1a2 ;;
  down)    minikube delete -p "$cluster"; exit 0 ;;
  *)       echo "использование: $0 openbao|vault|down" >&2; exit 2 ;;
esac
ns=$product
addr="http://$product.$product.svc:8200"
source "$here/lib.sh"

# --- кластер и сервер ------------------------------------------------------------------------------------------
start_cluster
load_images "$image" "$digest"
helm repo add openbao https://openbao.github.io/openbao-helm >/dev/null 2>&1 || true
helm repo add hashicorp https://helm.releases.hashicorp.com >/dev/null 2>&1 || true
helm upgrade --install "$product" "$chart" --kube-context "$ctx" --version "$chart_ver" \
  -n "$ns" --create-namespace -f "$here/values-$product.yaml" --wait --timeout 5m >/dev/null
k -n "$ns" wait --for=condition=Ready "pod/$product-0" --timeout=180s >/dev/null

# Команда CLI внутри сервера от root-токена (только для настройки стенда).
srv() { k -n "$ns" exec -i "$product-0" -- env "${cli^^}_ADDR=http://127.0.0.1:8200" "${cli^^}_TOKEN=root" "$cli" "$@"; }

# --- настройка: то, что в бою делает CI-применитель ---------------------------------------------------------------
srv secrets list -format=json | grep -q '"aegis-kv/"' || srv secrets enable -path=aegis-kv -version=2 kv >/dev/null
srv auth list -format=json | grep -q '"kubernetes/"' || srv auth enable kubernetes >/dev/null
srv write auth/kubernetes/config kubernetes_host=https://kubernetes.default.svc:443 >/dev/null
srv policy write aegis-intake - < "$vault_dir/policies/aegis-intake.json" >/dev/null
srv write auth/kubernetes/role/aegis-intake - < "$vault_dir/roles/aegis-intake.json" >/dev/null

put_all

k get ns aegis-system >/dev/null 2>&1 || k create ns aegis-system >/dev/null
k -n aegis-system get sa aegis-intake >/dev/null 2>&1 || k -n aegis-system create sa aegis-intake >/dev/null
# Конфигурация агента из Git; для стенда меняется только адрес dev-сервера (без TLS, поэтому без ca_cert).
jq --arg a "$addr" '.vault.address = $a | del(.vault.ca_cert)' "$vault_dir/agent/aegis-intake.json" > "$here/.agent-$product.json"
k -n aegis-system create configmap aegis-intake-vault-agent --from-file=aegis-intake.json="$here/.agent-$product.json" \
  --dry-run=client -o yaml | k apply -f - >/dev/null
rm -f "$here/.agent-$product.json"

echo "== $product ($image)"

# 1. Все секреты на месте: агент пишет файлы 0400, intake с тем же runAsUser их читает (п. 6, 7).
phase=$(run_pod secrets-ok)
if [ "$phase" = Succeeded ]; then
  pass "все секреты: под завершился, файлы прочитаны под runAsUser 10001 при readOnlyRootFilesystem"
  k -n aegis-system logs secrets-ok -c intake | sed 's/^/      /'
  bad=$(k -n aegis-system logs secrets-ok -c intake | awk '/^-/ && $1 != "-r--------" {print}')
  [ -z "$bad" ] && pass "права файлов 0400" || fail "права файлов не 0400: $bad"
else
  fail "все секреты: фаза пода $phase"; agent_log secrets-ok 20
fi

# 2. Нет ключа внутри секрета (error_on_missing_key): под не должен стартовать (п. 5).
srv kv put aegis-kv/mvp-a/intake/alertmanager wrong_name=x >/dev/null
phase=$(run_pod missing-key)
expect_fail missing-key "нет ключа в секрете" 'no key|missing key|map has no entry|error_on_missing_key|nil'

put_all

# 3. Нет пути в KV целиком (п. 5): ожидаем то же — под не стартует, а не пустой файл.
srv kv metadata delete aegis-kv/mvp-a/intake/prometheus >/dev/null
phase=$(run_pod missing-path)
expect_fail missing-path "нет пути в KV" 'prometheus'

put_all

# 4. Токен роли aegis-intake: разрешённое читается, остальное — permission denied.
permsout=$(mktemp)
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
      env: [{name: ${cli^^}_ADDR, value: "$addr"}, {name: HOME, value: /tmp}]
      securityContext: {runAsUser: 10001, runAsNonRoot: true, allowPrivilegeEscalation: false}
      volumeMounts: [{name: vault-token, mountPath: /var/run/secrets/vault, readOnly: true}, {name: kube-token, mountPath: /var/run/secrets/kube, readOnly: true}]
  volumes:
    - name: vault-token
      projected: {sources: [{serviceAccountToken: {audience: vault, expirationSeconds: 600, path: token}}]}
    - name: kube-token
      projected: {sources: [{serviceAccountToken: {audience: "https://kubernetes.default.svc", expirationSeconds: 600, path: token}}]}
EOF
k -n aegis-system wait --for=condition=Ready pod/perms --timeout=120s >/dev/null
k -n aegis-system exec perms -- sh -c "
  if $cli write auth/kubernetes/login role=aegis-intake jwt=@/var/run/secrets/kube/token >/dev/null 2>&1; then echo 'allowed login-wrong-audience'; else echo 'denied login-wrong-audience'; fi
  $cli write -field=token auth/kubernetes/login role=aegis-intake jwt=@/var/run/secrets/vault/token > /tmp/t || exit 9
  export ${cli^^}_TOKEN=\$(cat /tmp/t)
  try() { if $cli \"\$@\" >/dev/null 2>/tmp/e; then echo \"allowed \$*\"; else grep -q 'permission denied' /tmp/e && echo \"denied \$*\" || { echo \"error \$*\"; head -2 /tmp/e; }; fi; }
  try read aegis-kv/data/mvp-a/intake/openrouter
  try read aegis-kv/data/mvp-a/audit-anchor
  try read aegis-kv/data/mvp-a/other
  try list aegis-kv/metadata/mvp-a
  try kv put aegis-kv/mvp-a/intake/openrouter api_key=x
  try secrets disable aegis-kv
  try auth disable kubernetes
  try policy write evil /dev/null
  try write auth/kubernetes/role/evil token_policies=root
  try audit disable file
  try token create -policy=aegis-intake
" > "$permsout" || true
while read -r verdict rest; do
  case "$rest" in
    "read aegis-kv/data/mvp-a/intake/openrouter"|"read aegis-kv/data/mvp-a/audit-anchor")
      [ "$verdict" = allowed ] && pass "разрешено: $rest" || fail "должно быть разрешено: $rest ($verdict)" ;;
    "token create"*)
      # Дочерний токен с теми же правами политика по умолчанию разрешает; фиксируем, а не валим прогон.
      echo "INFO  $verdict: $rest" ;;
    *) [ "$verdict" = denied ] && pass "permission denied: $rest" || fail "должно быть denied: $rest ($verdict)" ;;
  esac
done < <(grep -E '^(allowed|denied|error) ' "$permsout")
grep -vE '^(allowed|denied|error) ' "$permsout" | sed 's/^/      /' || true
grep -q . "$permsout" || fail "вход по роли aegis-intake не удался"
rm -f "$permsout"
k -n aegis-system delete pod perms --wait=false >/dev/null

echo "== $product: провалов $fails"
exit $((fails > 0))
