# ci-cred-lab

Own-infrastructure lab used to measure what a GitHub Actions job exposes to its steps:

- presence/length of job-scope credentials (masked; sha256 prefix only),
- on-disk persisted checkout credential vs the job's `GITHUB_TOKEN` (hash equality),
- `GITHUB_TOKEN` permission set via the GitHub API, push dry-run, and a canary
  code-scanning write attempt (cleaned up),
- outbound egress to an owner-controlled canary listener,
- downstream reachability (public registries / services) and credential-file presence.

All secret material used here is a **canary value**. No real credentials are stored anywhere
in this repo or in the workflow output; probe artifacts contain only presence flags, lengths
and sha256 prefixes, with one deliberate exception: the masking-matrix step prints
**encoded forms of the canary secrets** (base64/hex/reversed/spaced/...) to the run log and
artifact on purpose, to measure which encodings survive GitHub log masking. These are
disposable canary values with no access to anything.

Additional platform probes (clearly labelled, not part of the consumer mirror):
`prt-probe.yml` (pull_request_target semantics; never checks out PR content) and
`sched-probe.yml` (schedule semantics). `mask_matrix.sh` and `cache_check.sh` are
canary-only helpers.
