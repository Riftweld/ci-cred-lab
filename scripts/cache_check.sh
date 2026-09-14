#!/usr/bin/env bash
# ci-cred-lab canary cache persistence probe (CANARY values only).
# The cache survives across runs; this file records whether a canary-derived blob
# written on one run is restored on a later run (cross-run and cross-trigger).
set -uo pipefail
O="out"
mkdir -p "$O"
CAN="${SEMGREP_APP_TOKEN:-}"
CACHE_DIR="cache-canary"

if [ "${CACHE_PRIME:-}" = "push" ] && [ ! -f "$CACHE_DIR/canary.b64" ]; then
  mkdir -p "$CACHE_DIR"
  printf '%s' "$(printf '%s' "$CAN" | base64 -w0)" > "$CACHE_DIR/canary.b64"
fi

{
  echo "restore_hit=${CACHE_HIT:-unknown}"
  echo "matched_key=${CACHE_KEY:-none}"
  if [ -f "$CACHE_DIR/canary.b64" ]; then
    got="$(cat "$CACHE_DIR/canary.b64")"
    echo "cache_file_present=yes file_len=${#got}"
    echo "cache_file_sha12=$(sha256sum "$CACHE_DIR/canary.b64" | cut -c1-12)"
    if [ -n "$CAN" ] && [ "$got" = "$(printf '%s' "$CAN" | base64 -w0)" ]; then
      echo "cache_carries_live_canary=YES decoded_len=$(printf '%s' "$got" | base64 -d | wc -c | tr -d ' ')"
    else
      echo "cache_carries_live_canary=NO"
    fi
  else
    echo "cache_file_present=no"
  fi
} > "$O/cache_proof.txt"

echo "cache probe complete: $(tail -1 "$O/cache_proof.txt")"
