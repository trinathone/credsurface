"""Unit tests for credsurface: scanners, audit, masking and rendering."""

import contextlib
import io
import os
import sys
import json
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from credsurface import (
    audit,
    blast_radius,
    mask_value,
    scan_agent_configs,
    scan_cli_sessions,
    scan_credential_files,
    scan_dotenv,
    scan_env,
    scrub_env,
    render_human,
    render_json,
    describe_launch,
    build_parser,
    main,
    cmd_audit,
    cmd_launch,
    DROPPED_SCOPES,
    Finding,
    SCOPE_RANK,
)


def _write(root, rel, content):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return path


def build_fixture_home():
    tmp = tempfile.TemporaryDirectory()
    home = tmp.name
    _write(home, ".aws/credentials", "[default]\naws_access_key_id = AKIAFAKE\n")
    _write(home, ".ssh/id_ed25519", "FAKE-PRIVATE-KEY-BYTES")
    _write(home, ".config/gcloud/application_default_credentials.json", '{"client_id": "fake"}')
    _write(home, ".npmrc", "//registry.npmjs.org/:_authToken=FAKENPMTOKEN")
    return tmp, home


def build_fixture_cwd():
    tmp = tempfile.TemporaryDirectory()
    cwd = tmp.name
    _write(cwd, ".env", "GITHUB_TOKEN=ghp_FAKE123456\nMY_API_KEY=sk-fake-12345678\nPLAIN=hello\n")
    _write(cwd, ".claude/settings.json", '{"env": {"ANTHROPIC_API_KEY": "sk-ant-fake"}, "other": 1}')
    return tmp, cwd


class TestMaskValue(unittest.TestCase):
    def test_long_value_masked(self):
        value = "wJalrXUtnFEMI1234"
        masked = mask_value(value)
        self.assertNotIn(value, masked)
        self.assertTrue(masked.startswith(value[:4]))
        self.assertTrue(masked.endswith(value[-2:]))

    def test_short_value_fully_masked(self):
        self.assertEqual(mask_value("abc"), "****")

    def test_empty_value(self):
        self.assertEqual(mask_value(""), "****")


class TestScanEnv(unittest.TestCase):
    def test_aws_secret_key_account_wide(self):
        findings = scan_env({"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI12345678"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scope, "account-wide")
        self.assertIn("aws", findings[0].kind)

    def test_github_token_destructive(self):
        findings = scan_env({"GITHUB_TOKEN": "ghp_FAKE1234567890"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scope, "destructive")

    def test_known_readonly_stays_readonly(self):
        findings = scan_env({"STRIPE_PUBLISHABLE_KEY": "pk_test_fakekey123"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].scope, "read-only")

    def test_benign_var_ignored(self):
        findings = scan_env({"PATH": "/usr/bin", "HOME": "/home/x", "EDITOR": "vim"})
        self.assertEqual(findings, [])

    def test_hint_never_full_value(self):
        value = "sk-abcdefgh12345678"
        findings = scan_env({"OPENAI_API_KEY": value})
        self.assertEqual(len(findings), 1)
        self.assertNotIn(value, findings[0].hint)


class TestScanCredentialFiles(unittest.TestCase):
    def setUp(self):
        tmp, self.home = build_fixture_home()
        self.addCleanup(tmp.cleanup)

    def _by_name(self, name):
        matches = [f for f in scan_credential_files(self.home) if f.name == name]
        self.assertEqual(len(matches), 1, name)
        return matches[0]

    def test_finds_aws_credentials(self):
        names = [f.name for f in scan_credential_files(self.home)]
        self.assertIn(".aws/credentials", names)

    def test_finds_ssh_private_key(self):
        finding = self._by_name(".ssh/id_ed25519")
        self.assertEqual(finding.scope, "destructive")
        self.assertIn("private key", finding.detail)
        self.assertIn("never read", finding.detail)

    def test_missing_home_clean(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(scan_credential_files(empty), [])

    def test_file_size_in_detail(self):
        size = os.path.getsize(os.path.join(self.home, ".npmrc"))
        finding = self._by_name(".npmrc")
        self.assertIn(str(size), finding.detail)


class TestScanDotenv(unittest.TestCase):
    def setUp(self):
        tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(tmp.cleanup)

    def test_counts_assignments(self):
        findings = [f for f in scan_dotenv(self.cwd) if f.name == ".env"]
        self.assertEqual(len(findings), 1)
        self.assertIn("3", findings[0].detail)

    def test_no_dotenv_clean(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(scan_dotenv(empty), [])


class TestScanAgentConfigs(unittest.TestCase):
    def setUp(self):
        tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(tmp.cleanup)
        home_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(home_tmp.cleanup)
        self.home = home_tmp.name

    def test_finds_credential_keys(self):
        findings = [
            f for f in scan_agent_configs(self.home, self.cwd) if f.name == ".claude/settings.json"
        ]
        self.assertEqual(len(findings), 1)
        self.assertIn("ANTHROPIC_API_KEY", findings[0].detail)
        self.assertNotIn("sk-ant-fake", findings[0].detail)

    def test_clean_config_no_finding(self):
        with tempfile.TemporaryDirectory() as clean_cwd:
            _write(clean_cwd, ".claude/settings.json", '{"theme": "dark"}')
            findings = scan_agent_configs(self.home, clean_cwd)
            self.assertEqual([f for f in findings if f.name == ".claude/settings.json"], [])


class TestAudit(unittest.TestCase):
    SECRETS = [
        "wJalrXUtnFEMI12345678",
        "ghp_FAKE1234567890",
        "sk-ant-fake",
        "FAKENPMTOKEN",
        "FAKE-PRIVATE-KEY-BYTES",
    ]

    def setUp(self):
        home_tmp, self.home = build_fixture_home()
        self.addCleanup(home_tmp.cleanup)
        cwd_tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(cwd_tmp.cleanup)
        self.environ = {
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI12345678",
            "GITHUB_TOKEN": "ghp_FAKE1234567890",
            "SAFE_VAR": "hello",
        }
        self.findings, self.summary = audit(self.home, self.cwd, self.environ)

    def _pairs(self):
        return [(f.source, f.name) for f in self.findings]

    def test_audit_finds_everything(self):
        pairs = self._pairs()
        expected = [
            ("env", "AWS_SECRET_ACCESS_KEY"),
            ("env", "GITHUB_TOKEN"),
            ("file", ".ssh/id_ed25519"),
            ("file", ".npmrc"),
            ("file", ".env"),
            ("agent-config", ".claude/settings.json"),
        ]
        for pair in expected:
            self.assertIn(pair, pairs)

    def test_audit_dedups_aws_cli(self):
        aws = [f for f in self.findings if f.source == "cli-session" and f.name == "aws-cli"]
        self.assertEqual(len(aws), 1)
        self.assertNotIn(("file", ".aws/credentials"), self._pairs())

    def test_audit_dedups_gcloud(self):
        gcloud = [f for f in self.findings if f.source == "cli-session" and f.name == "gcloud"]
        self.assertEqual(len(gcloud), 1)
        self.assertNotIn(
            ("file", ".config/gcloud/application_default_credentials.json"), self._pairs()
        )

    def test_audit_sorted_by_blast_radius(self):
        ranks = [SCOPE_RANK[f.scope] for f in self.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_audit_never_prints_secret(self):
        human = render_human(self.findings, self.summary)
        as_json = render_json(self.findings, self.summary)
        for secret in self.SECRETS:
            self.assertNotIn(secret, human)
            self.assertNotIn(secret, as_json)

    def test_blast_radius_summary(self):
        summary = blast_radius(self.findings)
        self.assertEqual(summary["total"], len(self.findings))
        self.assertGreater(summary["score"], 0)
        self.assertEqual(summary["worst"], "account-wide")
        self.assertGreaterEqual(summary["by_scope"]["account-wide"], 1)


class TestScrubEnv(unittest.TestCase):
    def setUp(self):
        home_tmp, self.home = build_fixture_home()
        self.addCleanup(home_tmp.cleanup)
        cwd_tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(cwd_tmp.cleanup)
        self.environ = {
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI12345678",
            "GITHUB_TOKEN": "ghp_FAKE1234567890",
            "STRIPE_PUBLISHABLE_KEY": "pk_test_fakekey123",
            "SAFE_VAR": "hello",
            "PATH": "/usr/bin",
        }
        self.findings, self.summary = audit(self.home, self.cwd, self.environ)

    def test_drops_destructive_env_vars(self):
        scrubbed, dropped = scrub_env(self.environ, self.findings)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", scrubbed)
        self.assertNotIn("GITHUB_TOKEN", scrubbed)
        self.assertIn("AWS_SECRET_ACCESS_KEY", dropped)
        self.assertIn("GITHUB_TOKEN", dropped)

    def test_keeps_benign_vars(self):
        scrubbed, _dropped = scrub_env(self.environ, self.findings)
        self.assertEqual(scrubbed["SAFE_VAR"], "hello")
        self.assertEqual(scrubbed["PATH"], "/usr/bin")

    def test_keeps_readonly_vars(self):
        scrubbed, _dropped = scrub_env(self.environ, self.findings)
        self.assertIn("STRIPE_PUBLISHABLE_KEY", scrubbed)

    def test_dropped_sorted(self):
        _scrubbed, dropped = scrub_env(self.environ, self.findings)
        self.assertIsInstance(dropped, list)
        self.assertEqual(dropped, sorted(dropped))

    def test_file_findings_do_not_drop_env(self):
        clean_environ = {"PATH": "/usr/bin", "SAFE_VAR": "hello"}
        findings, _summary = audit(self.home, self.cwd, clean_environ)
        self.assertTrue(any(f.source == "file" for f in findings))
        scrubbed, dropped = scrub_env(clean_environ, findings)
        self.assertEqual(dropped, [])
        self.assertEqual(scrubbed, clean_environ)

    def test_describe_launch_lists_dropped(self):
        text = describe_launch(["GITHUB_TOKEN"], 5)
        self.assertIn("GITHUB_TOKEN", text)
        self.assertIn("dropped 1", text)
        self.assertIn("kept 5", text)


def run_main(argv, env_patch):
    out = io.StringIO()
    err = io.StringIO()
    with mock.patch.dict(os.environ, env_patch, clear=True):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(argv)
    return code, out.getvalue(), err.getvalue()


class TestCliAudit(unittest.TestCase):
    def setUp(self):
        home_tmp, self.home = build_fixture_home()
        self.addCleanup(home_tmp.cleanup)
        cwd_tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(cwd_tmp.cleanup)
        self.env = {
            "GITHUB_TOKEN": "ghp_FAKE1234567890",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI12345678",
            "PATH": "/usr/bin",
        }

    def test_audit_exit_1_with_findings(self):
        code, out, _err = run_main(["audit", "--home", self.home, "--cwd", self.cwd], self.env)
        self.assertEqual(code, 1)
        self.assertIn("GITHUB_TOKEN", out)

    def test_audit_exit_0_clean_home(self):
        with tempfile.TemporaryDirectory() as empty_home, tempfile.TemporaryDirectory() as empty_cwd:
            code, out, _err = run_main(
                ["audit", "--home", empty_home, "--cwd", empty_cwd],
                {"PATH": "/usr/bin", "SAFE": "x"},
            )
        self.assertEqual(code, 0)
        self.assertIn("0 findings", out)

    def test_audit_json_mode(self):
        code, out, _err = run_main(
            ["audit", "--home", self.home, "--cwd", self.cwd, "--json"], self.env
        )
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertIsInstance(data["findings"], list)
        self.assertIsInstance(data["summary"], dict)
        self.assertEqual(data["summary"]["total"], len(data["findings"]))
        self.assertNotIn("ghp_FAKE", out)
        self.assertNotIn("wJalrXUtnFEMI", out)

    def test_audit_quiet_mode(self):
        code, out, _err = run_main(
            ["audit", "--home", self.home, "--cwd", self.cwd, "--quiet"], self.env
        )
        self.assertEqual(code, 1)
        self.assertEqual(len(out.splitlines()), 1)

    def test_version_flag(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("credsurface", out.getvalue())


class TestCliLaunch(unittest.TestCase):
    def setUp(self):
        home_tmp, self.home = build_fixture_home()
        self.addCleanup(home_tmp.cleanup)
        cwd_tmp, self.cwd = build_fixture_cwd()
        self.addCleanup(cwd_tmp.cleanup)
        self.env = {
            "GITHUB_TOKEN": "ghp_FAKE1234567890",
            "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI12345678",
            "SAFE_VAR": "hello",
        }

    def test_launch_print_drops_and_keeps(self):
        code, out, _err = run_main(["launch", "--home", self.home, "--cwd", self.cwd], self.env)
        self.assertEqual(code, 0)
        self.assertIn("dropped GITHUB_TOKEN", out)
        self.assertIn("dropped AWS_SECRET_ACCESS_KEY", out)
        self.assertIn("export SAFE_VAR='hello'", out)
        self.assertNotIn("ghp_FAKE1234567890", out)

    def test_launch_exec_runs_child_without_secrets(self):
        with mock.patch("os.execvpe") as fake_exec:
            run_main(
                ["launch", "--home", self.home, "--cwd", self.cwd, "--exec", "printenv", "SAFE_VAR"],
                self.env,
            )
        fake_exec.assert_called_once()
        call_args = fake_exec.call_args[0]
        self.assertEqual(call_args[0], "printenv")
        self.assertEqual(call_args[1], ["printenv", "SAFE_VAR"])
        scrubbed = call_args[2]
        self.assertNotIn("GITHUB_TOKEN", scrubbed)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", scrubbed)
        self.assertEqual(scrubbed["SAFE_VAR"], "hello")

    def test_launch_exec_without_command_exits_2(self):
        code, _out, err = run_main(
            ["launch", "--home", self.home, "--cwd", self.cwd, "--exec"], self.env
        )
        self.assertEqual(code, 2)
        self.assertIn("requires a command", err)

    def test_launch_json_mode(self):
        code, out, _err = run_main(
            ["launch", "--home", self.home, "--cwd", self.cwd, "--json"], self.env
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("GITHUB_TOKEN", data["dropped"])
        self.assertNotIn("GITHUB_TOKEN", data["env"])
        self.assertEqual(data["env"]["SAFE_VAR"], "hello")


if __name__ == "__main__":
    unittest.main()
