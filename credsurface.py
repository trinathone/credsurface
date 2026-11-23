#!/usr/bin/env python3
"""credsurface audits the runtime credential surface an AI agent process
would inherit (environment variables, credential files, dotenv files and
agent config files) and wraps launches with a least-privilege environment.
It never prints secret values and never touches a live service.
"""

import argparse
import dataclasses
import json
import os
import re
import sys

VERSION = "0.1.0"

SCOPE_RANK = {"account-wide": 100, "destructive": 70, "read-only": 30, "unknown": 50}
SCOPE_LABELS = ["account-wide", "destructive", "unknown", "read-only"]


def _p(pattern):
    return re.compile(pattern, re.IGNORECASE)


# Case-insensitive regexes on the variable NAME only. First match wins, so
# specific patterns come before the generic *_API_KEY and *_TOKEN ones.
ENV_PATTERNS = [
    (_p(r"^AWS_ACCESS_KEY_ID$"), "aws-access-key-id", "account-wide"),
    (_p(r"^AWS_SECRET_ACCESS_KEY$"), "aws-secret-key", "account-wide"),
    (_p(r"^AWS_SESSION_TOKEN$"), "aws-session-token", "account-wide"),
    (_p(r"^(GITHUB|GH)_TOKEN$"), "github-token", "destructive"),
    (_p(r"^NPM_TOKEN$"), "npm-token", "destructive"),
    (_p(r"^DOCKER_HUB(_.*)?$"), "docker-hub-credential", "destructive"),
    (_p(r"^DOCKER_PASSWORD$"), "docker-password", "destructive"),
    (_p(r"^OPENAI_API_KEY$"), "openai-api-key", "destructive"),
    (_p(r"^ANTHROPIC_API_KEY$"), "anthropic-api-key", "destructive"),
    (_p(r"^STRIPE_.*KEY$"), "stripe-key", "destructive"),
    (_p(r"^SLACK_(BOT_)?TOKEN$"), "slack-token", "destructive"),
    (_p(r"^DATABASE_URL$"), "database-url", "destructive"),
    (_p(r"^.+_DB_URL$"), "database-url", "destructive"),
    (_p(r"^POSTGRES_.*PASSWORD$"), "postgres-password", "destructive"),
    (_p(r"^KUBECONFIG$"), "kubeconfig-pointer", "destructive"),
    (_p(r"^.+_API_KEY$"), "api-key", "unknown"),
    (_p(r"^.+_TOKEN$"), "token", "unknown"),
    (_p(r"^.+_SECRET(_KEY)?$"), "secret", "unknown"),
    (_p(r"^.+_PASSWORD$"), "password", "unknown"),
]

# Publishable keys are read-only by design. Keep this set small and honest.
KNOWN_READONLY = {"STRIPE_PUBLISHABLE_KEY", "GITHUB_READONLY_TOKEN"}

# (path relative to home, kind, scope)
CREDENTIAL_FILES = [
    (".aws/credentials", "aws-credentials", "account-wide"),
    (".aws/config", "aws-config", "unknown"),
    (".ssh/id_ed25519", "ssh-private-key", "destructive"),
    (".ssh/id_rsa", "ssh-private-key", "destructive"),
    (".ssh/id_ecdsa", "ssh-private-key", "destructive"),
    (".ssh/id_dsa", "ssh-private-key", "destructive"),
    (".config/gcloud/credentials.db", "gcloud-credentials", "account-wide"),
    (".config/gcloud/application_default_credentials.json", "gcloud-adc", "account-wide"),
    (".azure/accessTokens.json", "azure-access-tokens", "account-wide"),
    (".azure/azureProfile.json", "azure-profile", "unknown"),
    (".npmrc", "npm-config", "destructive"),
    (".docker/config.json", "docker-config", "destructive"),
    (".netrc", "netrc", "destructive"),
    (".git-credentials", "git-credentials", "destructive"),
    (".config/gh/hosts.yml", "gh-hosts", "destructive"),
    (".config/gh/config.yml", "gh-config", "unknown"),
    (".kube/config", "kubeconfig", "destructive"),
    (".terraformrc", "terraform-config", "unknown"),
    (".pypirc", "pypi-config", "destructive"),
    (".gem/credentials", "gem-credentials", "destructive"),
]

# Searched in the working directory only.
DOTENV_NAMES = (".env", ".env.local", ".env.production")

# (relative path from cwd, kind). Checked only for credential-looking keys
# (apiKey, token, password, secret) in their JSON, never printed.
AGENT_CONFIG_FILES = [
    (".claude/settings.json", "claude-settings"),
    (".cursor/mcp.json", "cursor-mcp"),
    (".vscode/mcp.json", "vscode-mcp"),
    ("mcp.json", "mcp-config"),
]

_DOTENV_LINE = re.compile(r"^[A-Z_][A-Z0-9_]*=", re.MULTILINE)


@dataclasses.dataclass
class Finding:
    source: str  # "env", "file", "cli-session", "agent-config"
    name: str
    kind: str
    scope: str
    detail: str  # human-readable, never a secret value
    hint: str = ""  # masked hint, or "" when not applicable


def mask_value(value):
    """Return a masked hint. Never returns the full value."""
    if len(value) > 8:
        return value[:4] + "..." + value[-2:]
    return "****"


def scan_env(environ):
    findings = []
    for name, value in environ.items():
        kind = scope = None
        if name in KNOWN_READONLY:
            kind, scope = "known-read-only", "read-only"
        else:
            for regex, pkind, pscope in ENV_PATTERNS:
                if regex.match(name):
                    kind, scope = pkind, pscope
                    break
        if kind is None:
            continue
        hint = mask_value(value) if len(value) >= 8 else ""
        findings.append(
            Finding(
                source="env",
                name=name,
                kind=kind,
                scope=scope,
                detail="environment variable matches credential pattern " + kind,
                hint=hint,
            )
        )
    return findings


def scan_credential_files(home):
    findings = []
    for rel, kind, scope in CREDENTIAL_FILES:
        path = os.path.join(home, rel)
        if not os.path.exists(path):
            continue
        if kind == "ssh-private-key":
            detail = "private key file present, never read"
        else:
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            detail = "credential file present (%d bytes)" % size
        findings.append(
            Finding(
                source="file",
                name=rel,
                kind=kind,
                scope=scope,
                detail=detail,
                hint="",
            )
        )
    return findings


def scan_dotenv(cwd):
    findings = []
    for name in DOTENV_NAMES:
        path = os.path.join(cwd, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        count = len(_DOTENV_LINE.findall(text))
        findings.append(
            Finding(
                source="file",
                name=name,
                kind="dotenv",
                scope="unknown",
                detail="dotenv file with %d credential-like assignments" % count,
                hint="",
            )
        )
    return findings


_CREDENTIAL_KEY_RE = re.compile(r"(api[_-]?key|token|password|passwd|secret|auth)", re.IGNORECASE)


def _credential_keys(node, found):
    if isinstance(node, dict):
        for key, value in node.items():
            if (
                isinstance(key, str)
                and _CREDENTIAL_KEY_RE.search(key)
                and isinstance(value, str)
                and value
            ):
                found.append(key)
            _credential_keys(value, found)
    elif isinstance(node, list):
        for item in node:
            _credential_keys(item, found)


def scan_agent_configs(home, cwd):
    findings = []
    seen = set()
    # AGENT_CONFIG_FILES entries are (relpath, kind) with no base, so each
    # path is checked under both the home directory and the working directory.
    for rel, _kind in AGENT_CONFIG_FILES:
        for base in (home, cwd):
            path = os.path.realpath(os.path.join(base, rel))
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            keys = []
            _credential_keys(data, keys)
            if not keys:
                continue
            findings.append(
                Finding(
                    source="agent-config",
                    name=rel,
                    kind="agent-config",
                    scope="destructive",
                    detail="agent config contains %d credential-bearing keys: %s"
                    % (len(keys), ", ".join(keys[:5])),
                    hint="",
                )
            )
    return findings


def scan_cli_sessions(home):
    # These overlap with scan_credential_files on purpose; audit() deduplicates
    # by (source, name), keeping the cli-session entry when both exist.
    findings = []

    def exists(rel):
        return os.path.exists(os.path.join(home, rel))

    if exists(".aws/credentials"):
        findings.append(
            Finding(
                source="cli-session",
                name="aws-cli",
                kind="aws-session",
                scope="account-wide",
                detail="AWS CLI has configured credentials (profiles in ~/.aws/credentials)",
                hint="",
            )
        )
    if exists(".config/gcloud/credentials.db") or exists(
        ".config/gcloud/application_default_credentials.json"
    ):
        findings.append(
            Finding(
                source="cli-session",
                name="gcloud",
                kind="gcloud-session",
                scope="account-wide",
                detail="gcloud has an authenticated account",
                hint="",
            )
        )
    if exists(".azure/accessTokens.json"):
        findings.append(
            Finding(
                source="cli-session",
                name="azure-cli",
                kind="azure-session",
                scope="account-wide",
                detail="Azure CLI has cached access tokens",
                hint="",
            )
        )
    if exists(".docker/config.json"):
        findings.append(
            Finding(
                source="cli-session",
                name="docker-cli",
                kind="docker-session",
                scope="destructive",
                detail="Docker CLI has stored registry credentials",
                hint="",
            )
        )
    return findings


def blast_radius(findings):
    by_scope = {}
    score = 0
    for f in findings:
        by_scope[f.scope] = by_scope.get(f.scope, 0) + 1
        score += SCOPE_RANK.get(f.scope, SCOPE_RANK["unknown"])
    if findings:
        worst = max(by_scope, key=lambda s: SCOPE_RANK.get(s, SCOPE_RANK["unknown"]))
    else:
        worst = "clean"
    return {"total": len(findings), "by_scope": by_scope, "score": score, "worst": worst}


_CLI_DEDUP_KEYS = {
    "aws-cli": [".aws/credentials"],
    "gcloud": [
        ".config/gcloud/credentials.db",
        ".config/gcloud/application_default_credentials.json",
    ],
    "azure-cli": [".azure/accessTokens.json"],
    "docker-cli": [".docker/config.json"],
}


def audit(home, cwd, environ):
    collected = (
        scan_env(environ)
        + scan_credential_files(home)
        + scan_dotenv(cwd)
        + scan_agent_configs(home, cwd)
        + scan_cli_sessions(home)
    )
    unique = {}
    for f in collected:
        if f.source == "cli-session":
            # Replace any colliding file finding for the same credential.
            # A cli-session can map to more than one backing file (gcloud has
            # both credentials.db and application_default_credentials.json).
            replaced = False
            for candidate in _CLI_DEDUP_KEYS.get(f.name, [f.name]):
                key = ("file", candidate)
                if key in unique:
                    if not replaced:
                        unique[key] = f
                        replaced = True
                    else:
                        # Same credential already placed under another backing
                        # file; drop the duplicate key so it appears once.
                        del unique[key]
            if not replaced:
                unique[(f.source, f.name)] = f
        else:
            unique.setdefault((f.source, f.name), f)
    findings = sorted(
        unique.values(),
        key=lambda f: (-SCOPE_RANK.get(f.scope, SCOPE_RANK["unknown"]), f.source, f.name),
    )
    return findings, blast_radius(findings)


def finding_to_dict(f):
    return {
        "source": f.source,
        "name": f.name,
        "kind": f.kind,
        "scope": f.scope,
        "detail": f.detail,
        "hint": f.hint,
    }


def render_human(findings, summary):
    if not findings:
        return (
            "Credential surface: 0 findings, blast radius score 0 (worst: clean)\n"
            "No credentials visible to an agent launched here."
        )
    lines = [
        "Credential surface: %d findings, blast radius score %d (worst: %s)"
        % (summary["total"], summary["score"], summary["worst"])
    ]
    for f in findings:
        line = "  [%s] %s:%s (%s) - %s" % (f.scope.upper(), f.source, f.name, f.kind, f.detail)
        if f.hint:
            line += " hint " + f.hint
        lines.append(line)
    counts = summary["by_scope"]
    pairs = ["%s=%d" % (s, counts[s]) for s in SCOPE_LABELS if counts.get(s, 0) > 0]
    lines.append("Scope counts: " + ", ".join(pairs))
    return "\n".join(lines)


def render_json(findings, summary):
    return (
        json.dumps(
            {"findings": [finding_to_dict(f) for f in findings], "summary": summary},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


# launch drops these scopes, keeps read-only and unknown.
DROPPED_SCOPES = frozenset({"account-wide", "destructive"})


def scrub_env(environ, findings):
    # Only findings with source "env" drop variables. Findings from files or
    # cli-sessions never do: a file is not an env var, so there is nothing to
    # remove from the environment for it.
    dropped = {f.name for f in findings if f.source == "env" and f.scope in DROPPED_SCOPES}
    scrubbed = {name: value for name, value in environ.items() if name not in dropped}
    return scrubbed, sorted(dropped)


def describe_launch(dropped_names, kept_count):
    lines = [
        "Launch environment: dropped %d credential variables, kept %d others."
        % (len(dropped_names), kept_count)
    ]
    if not dropped_names:
        lines.append(
            "  Nothing to drop: no destructive or account-wide credentials in the environment."
        )
    for name in dropped_names:
        lines.append("  dropped " + name)
    return "\n".join(lines)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="credsurface",
        description=(
            "Audit the runtime credential surface an AI agent would inherit, "
            "and launch with a least-privilege environment."
        ),
    )
    parser.add_argument("--version", action="version", version="credsurface " + VERSION)
    sub = parser.add_subparsers(dest="command_name", required=True)

    p_audit = sub.add_parser(
        "audit", help="Audit the credential surface visible to an agent launched here."
    )
    p_audit.add_argument("--home", default=os.path.expanduser("~"), help="home directory to scan")
    p_audit.add_argument("--cwd", default=os.getcwd(), help="working directory to scan")
    p_audit.add_argument("--json", action="store_true", help="output JSON")
    p_audit.add_argument("--quiet", action="store_true", help="print only the summary line")
    p_audit.set_defaults(func=cmd_audit)

    p_launch = sub.add_parser(
        "launch", help="Print a scrubbed environment, or exec a command in it."
    )
    p_launch.add_argument("--home", default=os.path.expanduser("~"), help="home directory to scan")
    p_launch.add_argument("--cwd", default=os.getcwd(), help="working directory to scan")
    p_launch.add_argument("--json", action="store_true", help="output JSON")
    p_launch.add_argument(
        "--exec",
        action="store_true",
        help="actually exec the command instead of printing the environment",
    )
    p_launch.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help=(
            "command to run in the scrubbed environment (requires --exec); "
            "options must come before the command"
        ),
    )
    p_launch.set_defaults(func=cmd_launch)
    return parser


def cmd_audit(args):
    findings, summary = audit(args.home, args.cwd, os.environ)
    if args.json:
        print(render_json(findings, summary))
    elif args.quiet:
        print(render_human(findings, summary).splitlines()[0])
    else:
        print(render_human(findings, summary))
    return 1 if findings else 0


def cmd_launch(args):
    findings, _summary = audit(args.home, args.cwd, os.environ)
    scrubbed, dropped = scrub_env(os.environ, findings)
    # JSON and export output print the VALUES of kept variables by design:
    # launch output is meant to be consumed by a shell or a parent process.
    if args.json:
        print(
            json.dumps(
                {"dropped": dropped, "kept": len(scrubbed), "env": scrubbed},
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    if args.exec:
        if not args.command:
            print("error: launch --exec requires a command", file=sys.stderr)
            return 2
        try:
            os.execvpe(args.command[0], args.command, scrubbed)
        except OSError as exc:
            print("error: cannot exec %s: %s" % (args.command[0], exc.strerror), file=sys.stderr)
            return 2
    print(describe_launch(dropped, len(scrubbed)))
    for name in sorted(scrubbed):
        print("export %s='%s'" % (name, scrubbed[name].replace("'", "'\\''")))
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
