# credsurface

Your AI coding agent inherits every credential your shell can see. AWS keys, GitHub tokens, SSH keys, cloud logins, the API key in your agent config. One bad prompt, one compromised dependency, one over-broad token, and the agent can spend your money, delete your production database, or walk out with your keys. credsurface shows you the whole blast radius before you launch, then launches the agent with the destructive ones removed.

## The pain, with receipts
- Nov 17, 2026: attackers compromised Microsoft's agent-framework PyPI package, versions 1.26.1 and 1.26.2, about 190,000 downloads a month. Both wheels carry a .pth startup hook that runs a credential stealer on every Python start, even when nothing imports the package. It sweeps env vars and credential files, scrapes other processes' environments, and mints fresh identity tokens from Azure and GitHub OIDC endpoints.
- Apr 2026: a Cursor agent deleted a production database and its backups in about 9 seconds, using a Railway API token provisioned for domain management but scoped to the whole account. Newest recoverable backup was three months old.
- Jul 2025: a Replit agent deleted a live production database during a declared code freeze, wiping records for about 1,206 executives and 1,196 companies.
- Dec 2025: an Amazon Kiro agent removed and rebuilt a live environment unsupervised, causing a 13-hour AWS Cost Explorer outage in one China region.
- Oct 8, 2026: Zenity Labs disclosed AgentCorruption, flaws in Amazon Bedrock AgentCore letting a single prompt to one public-facing agent reach the Instance Metadata Service and pull temporary credentials tied to a default execution role.
- The common root cause in the three over-scoped-credential disasters has nothing to do with model quality: the agent inherited credentials far broader than its task needed.

## What it does
- `credsurface audit` enumerates every credential a process launched right now would inherit: env vars matched against credential name patterns, standard credential files (~/.aws/credentials, ~/.ssh private keys, ~/.config/gcloud, ~/.azure, ~/.npmrc, ~/.docker/config.json, .netrc, .git-credentials, .kube/config and more), .env files in the working directory, cloud CLI sessions (aws, gcloud, azure, docker), and credential-bearing keys inside agent config files (.claude/settings.json, .cursor/mcp.json, .vscode/mcp.json).
- Each finding is classified by scope: account-wide, destructive, read-only, unknown, and ranked by blast radius with a total score.
- `credsurface launch` prints a scrubbed environment (destructive and account-wide env vars dropped, the rest kept) as shell export lines, or with --exec runs your command inside it. Default is print-only; --exec must be explicit.
- Never prints a secret value: audit output shows names and masked hints only. Never tests a key against a live service: scope comes from local config only. Never modifies a credential file.
- Exit codes: 0 clean, 1 findings, 2 usage error. --json mode on both commands. --quiet on audit prints only the summary line.

## Demo (run live against the fixtures in fixtures/)

```
$ AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' STRIPE_PUBLISHABLE_KEY='pk_test_examplekey' python3 credsurface.py audit --home fixtures/demo-home --cwd fixtures/demo-cwd
Credential surface: 6 findings, blast radius score 420 (worst: account-wide)
  [ACCOUNT-WIDE] cli-session:aws-cli (aws-session) - AWS CLI has configured credentials (profiles in ~/.aws/credentials)
  [ACCOUNT-WIDE] env:AWS_SECRET_ACCESS_KEY (aws-secret-key) - environment variable matches credential pattern aws-secret-key hint wJal...EY
  [DESTRUCTIVE] agent-config:.claude/settings.json (agent-config) - agent config contains 1 credential-bearing keys: ANTHROPIC_API_KEY
  [DESTRUCTIVE] file:.ssh/id_ed25519 (ssh-private-key) - private key file present, never read
  [UNKNOWN] file:.env (dotenv) - dotenv file with 3 credential-like assignments
  [READ-ONLY] env:STRIPE_PUBLISHABLE_KEY (known-read-only) - environment variable matches credential pattern known-read-only hint pk_t...ey
Scope counts: account-wide=2, destructive=2, unknown=1, read-only=1
```

Exit code 1, findings exist.

```
$ AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' GITHUB_TOKEN='ghp_FAKETOKEN123456' SAFE_VAR=hello python3 credsurface.py launch --home fixtures/demo-home --cwd fixtures/demo-cwd --exec printenv SAFE_VAR GITHUB_TOKEN AWS_SECRET_ACCESS_KEY
hello
```

Only SAFE_VAR survives; printenv exits 1 because the two dropped vars are absent, which is the proof the scrub worked.

## Install and use
- Requires Python 3.10+, stdlib only, no install step: `python3 credsurface.py audit` and `python3 credsurface.py launch --exec <your agent command>`.
- Run audit before every agent session. Put `credsurface launch --exec claude` (or your agent of choice) in front of the agent when you want it to run with least privilege.
- `--home` and `--cwd` override the paths scanned, useful for auditing a project directory or a fixture home.
- The `launch` print and `--json` modes print the VALUES of kept variables, by design: the output is meant to be consumed by a shell or a parent process. Do not paste launch output into a chat log or a ticket.

## What it is not
- It audits and wraps; it does not sandbox. A determined process can still read files the OS lets it read. For real isolation use a VM, a container, or a microVM platform.
- It does not verify whether a key is still valid, and it never calls a cloud API. A revoked key still shows up until you delete it.
- Scope is inferred from the credential type and local config, not from live IAM policy. A key labeled destructive may in reality be scoped down; treat the label as a prompt to check, not a verdict.
- Windows credential stores are not covered. macOS and Linux only.
- It does not find secrets sitting in files beyond the credential paths and .env files listed above. For a full file scan, pair it with agent-secret-scrubber.

## Tests
- 37 tests, `python3 -m unittest discover -s tests`. Fixture home and cwd directories with planted credential files and env vars. Tests assert audit finds each source, classifies scope correctly, never prints a full secret value anywhere in its output, and that launch drops destructive credentials while keeping benign ones, including an --exec test that proves the child process cannot see the dropped vars.
