#!/usr/bin/env bash
# Самопроверка классификатора curl_verdict без стенда: ./run-netpol.sh selftest (и в CI).
set -euo pipefail
source "$(dirname "$0")/curl-verdict.sh"

bad=0
check() { # want crc ctc cta ожидание
  local v; v=$(curl_verdict "$1" "$2" "$3" "$4")
  if [ "${v%% *}" = "$5" ]; then echo "ok        $1 crc=$2 tcp=$3 tls=$4 -> $v"
  else echo "MISMATCH  $1 crc=$2 tcp=$3 tls=$4 -> $v (ожидалось $5)"; bad=$((bad + 1)); fi
}
check tls_fail 35 0.004 0 pass
check tls_fail 56 0.000351 0.000000 pass
check tls_fail 28 0.004 0.000000 inconclusive   # таймаут при установленном TCP и незавершённом TLS
check tls_fail 28 0 0 fail                      # L3-дроп
check tls_fail 7 0 0 fail
check tls_fail 6 0 0 fail
check tls_fail 35 0 0 fail                      # нет TCP
check tls_fail 35 0.004 0.01 fail               # TLS завершён
check tls_fail 52 0.004 0 inconclusive
check tls_fail 0 0.004 0.01 fail
check fail 56 0.004 0 pass
check fail 52 0.004 0 pass
check fail 28 0.004 0 inconclusive
check fail 7 0 0 fail
check fail 56 0 0 fail
check fail 0 0.004 0 fail
check ok 0 0.004 0.01 pass
check ok 35 0.004 0 fail
check dns_fail 6 0 0 pass
check dns_fail 28 0 0 fail
check tls_fail 99 "" "" fail
check ok 99 "" "" fail
check bogus 0 "" "" fail
check tls_fail 35 "" "" fail                    # пустые тайминги = ноль
if nonzero ""; then echo "MISMATCH  nonzero пустой"; bad=$((bad + 1)); fi
nonzero 0.000351 || { echo "MISMATCH  nonzero 0.000351"; bad=$((bad + 1)); }
nonzero 0.000000 && { echo "MISMATCH  nonzero 0.000000"; bad=$((bad + 1)); }
echo "несовпадений: $bad"
[ "$bad" -eq 0 ]
