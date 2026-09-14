# ci-cred-lab

Own-infrastructure lab used to measure what a GitHub Actions job exposes to its steps:

- presence/length of job-scope credentials (masked; sha256 prefix only),
- on-disk persisted checkout credential vs the job's `GITHUB_TOKEN` (hash equality),
- `GITHUB_TOKEN` permission set via the GitHub API, push dry-run, and a canary
  code-scanning write attempt (cleaned up),
- outbound egress to an owner-controlled canary listener,
- downstream reachability (public registries / services) and credential-file presence.

All secret material used here is a **canary value**. No real credentials are stored or
printed anywhere in this repo or in the workflow output; probe artifacts contain only
presence flags, lengths and sha256 prefixes.
