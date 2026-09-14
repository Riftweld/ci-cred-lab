#!/usr/bin/env bash
# Token capability matrix probe (lab only).
# Runs with the job's GITHUB_TOKEN; read probes across lab/owner targets,
# write probes ONLY against our lab repos (SELF + ORGFORK). Token value never printed.
set -uo pipefail

CTX_TOKEN="${CTX_TOKEN:-}"
SELF="${GITHUB_REPOSITORY:-muhammad-luay/ci-cred-lab}"
ORG_FORK="Riftweld/ci-cred-lab"
RUN_ID="${GITHUB_RUN_ID:-0}"
EVENT="${GITHUB_EVENT_NAME:-unknown}"
REF="${GITHUB_REF:-unknown}"
SHA="${GITHUB_SHA:-unknown}"
O="out"; mkdir -p "$O/bodies"
T="$O/matrix.tsv"
: > "$T"

hp12(){ printf '%s' "$1" | sha256sum | cut -c1-12; }
note_from(){ jq -r '.message // empty' "$1" 2>/dev/null | head -c 110 | tr '\t\n' '  '; }
row(){ printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "${4:-}" >> "$T"; }

req(){ # method path outfile [data] -> http code
  local m="$1" p="$2" f="$3" d="${4:-}" code
  if [ -n "$d" ]; then
    code=$(curl -sS -m 30 -o "$f" -w '%{http_code}' -X "$m" \
      -H "Authorization: Bearer $CTX_TOKEN" -H "Accept: application/vnd.github+json" \
      -H "Content-Type: application/json" \
      "https://api.github.com$p" -d "$d" 2>/dev/null || echo ERR)
  else
    code=$(curl -sS -m 30 -o "$f" -w '%{http_code}' -X "$m" \
      -H "Authorization: Bearer $CTX_TOKEN" -H "Accept: application/vnd.github+json" \
      "https://api.github.com$p" 2>/dev/null || echo ERR)
  fi
  printf '%s' "$code"
}

{
  echo "event=$EVENT"
  echo "ref=$REF"
  echo "sha=$SHA"
  echo "token_len=${#CTX_TOKEN}"
  echo "token_sha12=$(hp12 "$CTX_TOKEN")"
  case "$CTX_TOKEN" in ghs_*) echo "token_prefix=ghs";; *) echo "token_prefix=other";; esac
} > "$O/token_meta.txt"

# ---------------- read matrix across targets ----------------
targets=(
  "self|$SELF|public"
  "org_fork|$ORG_FORK|public"
  "org_priv_lab|Riftweld/vdp-hunt|private"
  "org_priv_site|Riftweld/riftweld.com|private"
  "owner_priv|muhammad-luay/vdp-hunt|private"
  "owner_pub|muhammad-luay/Sentinel|public"
)

for t in "${targets[@]}"; do
  IFS='|' read -r tag repo vis <<<"$t"
  f="$O/bodies/repo__$tag.json"
  c=$(req GET "/repos/$repo" "$f")
  row "read_repo" "$tag" "$c" "declared_vis=$vis $(note_from "$f")"
  for probe in contents branches issues pulls workflows workflows_dir runs artifacts; do
    case $probe in
      contents)      p="/repos/$repo/contents";;
      branches)      p="/repos/$repo/branches?per_page=1";;
      issues)        p="/repos/$repo/issues?state=all&per_page=1";;
      pulls)         p="/repos/$repo/pulls?state=all&per_page=1";;
      workflows)     p="/repos/$repo/actions/workflows";;
      workflows_dir) p="/repos/$repo/contents/.github/workflows";;
      runs)          p="/repos/$repo/actions/runs?per_page=1";;
      artifacts)     p="/repos/$repo/actions/artifacts?per_page=1";;
    esac
    f="$O/bodies/${probe}__$tag.json"
    c=$(req GET "$p" "$f")
    row "read_$probe" "$tag" "$c" "$(note_from "$f")"
  done
  for probe in code-scanning-alerts secret-scanning-alerts dependabot-alerts; do
    case $probe in
      code-scanning-alerts)   p="/repos/$repo/code-scanning/alerts?per_page=1";;
      secret-scanning-alerts) p="/repos/$repo/secret-scanning/alerts?per_page=1";;
      dependabot-alerts)      p="/repos/$repo/dependabot/alerts?per_page=1";;
    esac
    f="$O/bodies/${probe}__$tag.json"
    c=$(req GET "$p" "$f")
    row "read_$probe" "$tag" "$c" "$(note_from "$f")"
  done
done

# ---------------- org / installation / identity reads ----------------
orgprobe(){ local name="$1" path="$2" out="$3"
  f="$O/bodies/$out"
  local c; c=$(req GET "$path" "$f")
  row "$name" "org" "$c" "$(note_from "$f")"
}
orgprobe read_org_members         "/orgs/Riftweld/members?per_page=1"        org_members.json
orgprobe read_org_repos           "/orgs/Riftweld/repos?per_page=1"          org_repos.json
orgprobe read_org_public          "/orgs/Riftweld"                          org_public.json
orgprobe read_installation_repos  "/installation/repositories?per_page=1"   inst_repos.json
orgprobe read_user                "/user"                                   user.json
orgprobe read_rate_limit          "/rate_limit"                             rate_limit.json

# ---------------- self-repo admin-ish reads / downloads ----------------
f="$O/bodies/self_actions_permissions.json"; c=$(req GET "/repos/$SELF/actions/permissions" "$f")
row read_actions_permissions self "$c" "$(note_from "$f")"
f="$O/bodies/self_collaborators.json"; c=$(req GET "/repos/$SELF/collaborators?per_page=1" "$f")
row read_collaborators self "$c" "$(note_from "$f")"
f="$O/bodies/self_runners.json"; c=$(req GET "/repos/$SELF/actions/runners" "$f")
row read_runners self "$c" "$(note_from "$f")"

f="$O/bodies/self_runs.json"; c=$(req GET "/repos/$SELF/actions/runs?per_page=3" "$f")
row read_runs_3 self "$c" ""
rid=$(jq -r '.workflow_runs[] | select(.status=="completed") | .id' "$f" 2>/dev/null | head -1)
if [ -n "${rid:-}" ]; then
  code=$(curl -sS -m 60 -L -o /dev/null -w '%{http_code} size=%{size_download}' \
    -H "Authorization: Bearer $CTX_TOKEN" \
    "https://api.github.com/repos/$SELF/actions/runs/$rid/logs" 2>/dev/null || echo ERR)
  row read_run_logs_zip self "$code" "run=$rid"
fi
aid=$(jq -r '.artifacts[0].id // empty' "$O/bodies/artifacts__self.json" 2>/dev/null)
if [ -n "${aid:-}" ]; then
  code=$(curl -sS -m 60 -L -o /dev/null -w '%{http_code} size=%{size_download}' \
    -H "Authorization: Bearer $CTX_TOKEN" \
    "https://api.github.com/repos/$SELF/actions/artifacts/$aid/zip" 2>/dev/null || echo ERR)
  row read_artifact_zip self "$code" "artifact=$aid"
fi

# ---------------- git ref/wiki reads (lab targets) ----------------
for t in "self|$SELF" "org_fork|$ORG_FORK" "org_priv_lab|Riftweld/vdp-hunt" "owner_priv|muhammad-luay/vdp-hunt"; do
  IFS='|' read -r tag repo <<<"$t"
  out=$(GIT_TERMINAL_PROMPT=0 timeout 25 git ls-remote \
    "https://x-access-token:${CTX_TOKEN}@github.com/${repo}.git" 2>&1 | head -1 \
    | sed 's/x-access-token:[^@]*@/x-access-token:<redacted>@/g')
  rc=$?
  row read_git_refs "$tag" "rc=$rc" "$(printf '%s' "$out" | head -c 90 | tr '\t\n' '  ')"
  out=$(GIT_TERMINAL_PROMPT=0 timeout 25 git ls-remote \
    "https://x-access-token:${CTX_TOKEN}@github.com/${repo}.wiki.git" 2>&1 | head -1 \
    | sed 's/x-access-token:[^@]*@/x-access-token:<redacted>@/g')
  rc=$?
  row read_git_wiki "$tag" "rc=$rc" "$(printf '%s' "$out" | head -c 90 | tr '\t\n' '  ')"
done

# ---------------- write probes (SELF + lab fork ONLY) ----------------
f="$O/bodies/write_create_ref_self.json"
c=$(req POST "/repos/$SELF/git/refs" "$f" "{\"ref\":\"refs/heads/token-matrix-probe-$RUN_ID\",\"sha\":\"$SHA\"}")
row write_create_ref self "$c" "$(note_from "$f")"
if [ "$c" = "201" ]; then
  dc=$(req DELETE "/repos/$SELF/git/refs/heads/token-matrix-probe-$RUN_ID" "$O/bodies/write_undo_ref_self.json")
  row write_create_ref_cleanup self "$dc" ""
fi

content=$(printf 'name: probe\non: workflow_dispatch\njobs: {}\n' | base64 -w0)
f="$O/bodies/write_put_workflow_self.json"
c=$(req PUT "/repos/$SELF/contents/.github/workflows/token-matrix-write-probe.yml" "$f" \
  "{\"message\":\"probe\",\"content\":\"$content\",\"branch\":\"main\"}")
row write_put_workflow_file self "$c" "$(note_from "$f")"

f="$O/bodies/write_pr_comment_self.json"
c=$(req POST "/repos/$SELF/issues/2/comments" "$f" '{"body":"token-matrix probe (automated lab; ignore)"}')
row write_pr_comment self "$c" "$(note_from "$f")"

f="$O/bodies/write_pr_review_self.json"
c=$(req POST "/repos/$SELF/pulls/2/reviews" "$f" '{"body":"token-matrix lab probe","event":"APPROVE"}')
row write_pr_review self "$c" "$(note_from "$f")"

f="$O/bodies/write_create_pr_self.json"
c=$(req POST "/repos/$SELF/pulls" "$f" '{"title":"token-matrix probe (lab)","head":"lab/probe-pr","base":"main"}')
row write_create_pr self "$c" "$(note_from "$f")"

f="$O/bodies/write_repo_dispatch_self.json"
c=$(req POST "/repos/$SELF/dispatches" "$f" '{"event_type":"token-matrix-probe"}')
row write_repo_dispatch self "$c" "$(note_from "$f")"

f="$O/bodies/write_workflow_dispatch_self.json"
c=$(req POST "/repos/$SELF/actions/workflows/token-matrix.yml/dispatches" "$f" '{"ref":"main"}')
row write_workflow_dispatch self "$c" "$(note_from "$f")"

if [ -n "${aid:-}" ]; then
  f="$O/bodies/write_delete_artifact_self.json"
  c=$(req DELETE "/repos/$SELF/actions/artifacts/$aid" "$f")
  row write_delete_artifact self "$c" "artifact=$aid $(note_from "$f")"
fi

f="$O/bodies/write_patch_repo_self.json"
c=$(req PATCH "/repos/$SELF" "$f" '{"has_issues":true}')
row write_patch_repo_settings self "$c" "$(note_from "$f")"

f="$O/bodies/write_create_ref_orgfork.json"
c=$(req POST "/repos/$ORG_FORK/git/refs" "$f" "{\"ref\":\"refs/heads/token-matrix-probe-$RUN_ID\",\"sha\":\"$SHA\"}")
row write_create_ref org_fork "$c" "$(note_from "$f")"
if [ "$c" = "201" ]; then
  dc=$(req DELETE "/repos/$ORG_FORK/git/refs/heads/token-matrix-probe-$RUN_ID" "$O/bodies/write_undo_ref_orgfork.json")
  row write_create_ref_cleanup org_fork "$dc" ""
fi

# ---------------- git push dry-runs ----------------
pout=$(cd "$GITHUB_WORKSPACE" && git push --dry-run origin "HEAD:refs/heads/token-matrix-push-probe" 2>&1 | tail -3 \
  | sed 's/[A-Za-z0-9_]\{24,\}/<redacted-str>/g' | tr '\n' ' ' | head -c 160)
rc=$?
row write_git_push_dryrun self "rc=$rc" "$pout"

pout=$(cd "$GITHUB_WORKSPACE" && GIT_TERMINAL_PROMPT=0 git push --dry-run \
  "https://x-access-token:${CTX_TOKEN}@github.com/$ORG_FORK.git" "HEAD:refs/heads/token-matrix-push-probe" 2>&1 | tail -3 \
  | sed 's/x-access-token:[^@]*@/x-access-token:<redacted>@/g; s/[A-Za-z0-9_]\{24,\}/<redacted-str>/g' | tr '\n' ' ' | head -c 160)
rc=$?
row write_git_push_dryrun org_fork "rc=$rc" "$pout"

# ---------------- security-events write (SARIF, lab repo, cleaned) ----------------
SARIF_JSON='{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"token-matrix-canary","rules":[]}},"results":[]}]}'
SARIF_B64=$(printf '%s' "$SARIF_JSON" | gzip -c | base64 -w0)
body=$(jq -n --arg sha "$SHA" --arg ref "$REF" --arg s "$SARIF_B64" \
  '{commit_sha:$sha,ref:$ref,sarif:$s,tool_name:"token-matrix-canary"}')
f="$O/bodies/write_sarif_upload.json"
c=$(req POST "/repos/$SELF/code-scanning/sarifs" "$f" "$body")
sid=$(jq -r '.id // empty' "$f" 2>/dev/null)
row write_sarif_upload self "$c" "id_present=$([ -n "${sid:-}" ] && echo yes || echo no) $(note_from "$f")"
if [ -n "${sid:-}" ]; then
  sleep 6
  f2="$O/bodies/write_sarif_status_$sid.json"
  c2=$(req GET "/repos/$SELF/code-scanning/sarifs/$sid" "$f2")
  row write_sarif_status self "$c2" "status=$(jq -r '.processing_status // empty' "$f2" 2>/dev/null)"
fi
f3="$O/bodies/self_analyses_canary.json"
c3=$(req GET "/repos/$SELF/code-scanning/analyses?tool_name=token-matrix-canary&per_page=10" "$f3")
row read_analyses_canary self "$c3" ""
ids=$(jq -r '.[].id' "$f3" 2>/dev/null | head -5)
for id in $ids; do
  f4="$O/bodies/write_analysis_delete_$id.json"
  dc=$(req DELETE "/repos/$SELF/code-scanning/analyses/$id?confirm_delete=true" "$f4")
  row write_analysis_delete self "$dc" "analysis=$id $(note_from "$f4")"
done

# ---------------- summary ----------------
{
  echo "## Token capability matrix ($EVENT)"
  echo ""
  echo "token_meta: $(tr '\n' ' ' < "$O/token_meta.txt")"
  echo ""
  echo '```'
  column -t -s $'\t' "$T" 2>/dev/null || cat "$T"
  echo '```'
} >> "$GITHUB_STEP_SUMMARY"
echo "matrix rows: $(wc -l < "$T")"
