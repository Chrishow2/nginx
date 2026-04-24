#!/bin/sh
DOMAIN="$CERTBOT_DOMAIN"
BASE="/app/tmp/dns"
rm -f "$BASE/$DOMAIN.validation"
