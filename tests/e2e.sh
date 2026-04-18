#!/usr/bin/env bash
set -euo pipefail

SOCK=/tmp/crypto_gateway_e2e.sock
./bin/crypto_gateway ./configs/devices.conf ./configs/gateway.conf "$SOCK" > /tmp/crypto_gateway_e2e.log 2>&1 &
PID=$!
trap 'kill "$PID" >/dev/null 2>&1 || true; rm -f "$SOCK"' EXIT
sleep 1

REQ='{"request_id":"e2e-1","domain":"pqc","action":"kem_encap","algorithm":"mlkem768","key_ref":"k2","payload":"peer_pub","user_pin":"123456"}'
RESP=$(printf '%s\n' "$REQ" | ./bin/crypto_client "$SOCK")
echo "$RESP" | grep '"status":0' >/dev/null
echo "$RESP" | grep 'SDF_Encap_Kyber' >/dev/null
