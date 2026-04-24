#!/bin/sh
DOMAIN="$CERTBOT_DOMAIN"
BASE="/app/tmp/dns"
VAL="$CERTBOT_VALIDATION"
NAME="_acme-challenge.${DOMAIN}"
mkdir -p "$BASE" || exit 1
printf '%s' "$VAL" > "$BASE/$DOMAIN.validation" || exit 1
while [ ! -f "$BASE/$DOMAIN.continue" ]; do sleep 1; done
rm -f "$BASE/$DOMAIN.continue"

# certbot verifies with LE as soon as this hook exits; wait for public DNS first
if command -v dig >/dev/null 2>&1; then
  i=0
  while [ "$i" -lt 180 ]; do
    seen=0
    for NS in 1.1.1.1 8.8.8.8; do
      R=$(dig +short TXT "$NAME" "@$NS" 2>/dev/null | tr -d '\n" ')
      case "$R" in *"$VAL"*) seen=1; break ;; esac
    done
    [ "$seen" -eq 1 ] && exit 0
    i=$((i + 1))
    sleep 2
  done
  echo "dns-auth: TXT for $NAME not visible at 1.1.1.1 / 8.8.8.8 after ~6 min (value must match exactly)" >&2
  exit 1
fi

echo "dns-auth: dig missing; sleeping 60s — install dnsutils in image for reliable DNS-01" >&2
sleep 60
