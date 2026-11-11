#!/usr/bin/env bash
# Классификатор результата curl для стенда netpol (библиотека для source; без побочных эффектов, функции всегда возвращают 0).
nonzero() { ! [[ ${1:-} =~ ^0*\.?0*$ ]]; }  # время curl (%{time_connect}, например 0.000351) отлично от нуля; пусто = ноль

# curl_verdict WANT CRC CTC CTA — печатает одну строку: pass | fail <причина> | inconclusive <причина>.
#   WANT: ok | fail | tls_fail | dns_fail; CRC — код curl (99 — сбой kubectl exec); CTC/CTA — time_connect/time_appconnect (0 — этап не завершён).
# Код ошибки и этап соединения проверяются вместе:
#   35 — сброс после ClientHello (SNI отклонён Envoy), 56 — сброс при чтении, 52 — Envoy закрыл без ответа;
#   28 — таймаут: ничего не доказывает (отказ неотличим от дропа/зависания) — «неопределённо», а не успех.
curl_verdict() {
  local want=$1 crc=$2 ctc=${3:-} cta=${4:-}
  if [ "$crc" = 99 ]; then echo "fail стенд: exec не выполнился"; return 0; fi
  if [ "$want" = ok ]; then
    if [ "$crc" = 0 ]; then echo pass; else echo "fail curl завершился с кодом $crc"; fi
    return 0
  fi
  if [ "$crc" = 0 ]; then echo "fail запрос прошёл"; return 0; fi
  case $want in
    dns_fail)
      if [ "$crc" = 6 ]; then echo pass; else echo "fail ожидался curl 6"; fi ;;
    tls_fail)
      if ! nonzero "$ctc"; then echo "fail отказ без установленного TCP (DNS/connect/L3-дроп)"
      elif nonzero "$cta"; then echo "fail TLS завершён"
      else
        case $crc in
          35|56) echo pass ;;
          28) echo "inconclusive таймаут на TLS-этапе: отказ не доказан" ;;
          *) echo "inconclusive неожиданный код $crc" ;;
        esac
      fi ;;
    fail)
      if ! nonzero "$ctc"; then echo "fail отказ без установленного TCP"
      else
        case $crc in
          52|56) echo pass ;;
          28) echo "inconclusive таймаут при установленном TCP" ;;
          *) echo "inconclusive неожиданный код $crc" ;;
        esac
      fi ;;
    *) echo "fail неизвестный режим $want" ;;
  esac
  return 0
}
