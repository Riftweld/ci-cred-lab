#!/usr/bin/env bash
# workflow_call permission probe: measures which GITHUB_TOKEN capabilities the
# called workflow actually receives under different caller grants. Lab only.
set -uo pipefail
O="${OUT_DIR:-out}"; mkdir -p "$O"
TAG="${1:-tag}"
TOK="${CTX_TOKEN:-}"
hp12(){ printf '%s' "$1" | sha256sum | cut -c1-12; }
REPO="${GITHUB_REPOSITORY}"

push_out=$( (cd "$GITHUB_WORKSPACE" && git push --dry-run origin "HEAD:refs/heads/wcall-probe-$TAG" 2>&1) \
  | tail -2 | sed 's/[A-Za-z0-9_]\{24,\}/<redacted-str>/g' | tr '\n' ' ')

arts=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOK" "https://api.github.com/repos/$REPO/actions/artifacts?per_page=1")

SARIF_JSON=$(printf '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"wfcall-probe-%s","rules":[]}},"results":[]}]}' "$TAG")
SARIF_B64=$(printf '%s' "$SARIF_JSON" | gzip -c | base64 -w0)
body=$(jq -n --arg sha "$GITHUB_SHA" --arg ref "$GITHUB_REF" --arg s "$SARIF_B64" --arg t "wfcall-probe-$TAG" \
  '{commit_sha:$sha,ref:$ref,sarif:$s,tool_name:$t}')
sarif=$(curl -sS -m 30 -o "$O/sarif_$TAG.json" -w '%{http_code}' -X POST \
  -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
  -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/code-scanning/sarifs" -d "$body")

alerts=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $TOK" "https://api.github.com/repos/$REPO/code-scanning/alerts?per_page=1")

line="tag=$TAG token_len=${#TOK} sha12=$(hp12 "$TOK") push_dryrun=[$push_out] actions_read=$arts sec_writes_sarif=$sarif code_alerts_read=$alerts"
echo "$line" | tee -a "$O/wfcall_probe.txt"
