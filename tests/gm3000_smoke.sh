#!/usr/bin/env bash
set -euo pipefail
: "${GM3000_SKF_LIB:=./vendor/libgm3000.1.0.so}"
if [ ! -r "$GM3000_SKF_LIB" ]; then
  echo "GM3000_SKF_LIB not readable: $GM3000_SKF_LIB" >&2
  exit 2
fi
make bin/test_runner >/dev/null
printf 'gm3000 smoke: library=%s\n' "$GM3000_SKF_LIB"
cat <<'REQ' | ./bin/crypto_client /tmp/crypto_gateway.sock || true
{"request_id":"gm3000-random","domain":"device","action":"generate_random","payload":"16","device_hint":"gm3000-1","user_pin":"123456"}
REQ
