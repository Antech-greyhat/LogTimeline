"""End-to-end tests for the CLI (LogTimeline.main).

These run main() in-process, capturing stdout/stderr and the exit code, so no
subprocess is needed and the tests are portable. The permission-denied case is
simulated by patching ``open`` because real file permissions do not behave the
same across operating systems.
"""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

import LogTimeline

# Paths to the committed sample logs, resolved relative to this test file.
SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "Samples")
NORMAL_LOG = os.path.join(SAMPLES_DIR, "AuthLogNormal.log")
BRUTE_LOG = os.path.join(SAMPLES_DIR, "AuthLogBruteForce.log")
HOSTILE_LOG = os.path.join(SAMPLES_DIR, "AuthLogHostile.log")


def run_cli(argv):
    """Run main(argv), returning (exit_code, stdout_text, stderr_text).

    Handles both the normal "return an int" path and the SystemExit raised by
    --version and by argparse usage errors.
    """
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = LogTimeline.main(argv)
        except SystemExit as exit_error:
            code = exit_error.code if exit_error.code is not None else 0
    return code, out.getvalue(), err.getvalue()


class TestCliHappyPath(unittest.TestCase):
    def test_text_output_on_normal_sample(self):
        code, out, err = run_cli(["--file", NORMAL_LOG, "--no-color"])
        self.assertEqual(code, 0)
        self.assertIn("Summary", out)
        self.assertIn("SshLoginSuccess", out)
        self.assertIn("Lines read:", out)

    def test_json_output_is_valid(self):
        code, out, err = run_cli(["--file", NORMAL_LOG, "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(out)  # raises if the JSON is invalid
        self.assertIn("events", data)
        self.assertIn("summary", data)
        self.assertTrue(len(data["events"]) > 0)
        # Every event carries the full normalized schema.
        for key in ("TimestampUtc", "Host", "Program", "EventType", "RawLine"):
            self.assertIn(key, data["events"][0])

    def test_type_filter_limits_events(self):
        code, out, err = run_cli(
            ["--file", NORMAL_LOG, "--format", "json", "--type", "SudoCommand"]
        )
        data = json.loads(out)
        self.assertTrue(len(data["events"]) >= 1)
        for event in data["events"]:
            self.assertEqual(event["EventType"], "SudoCommand")

    def test_brute_force_sorted_by_utc(self):
        # The Accepted line is written first in the file but, in UTC, happens
        # near the end. Output must be in UTC order, not file order.
        code, out, err = run_cli(["--file", BRUTE_LOG, "--format", "json"])
        data = json.loads(out)
        times = [e["TimestampUtc"] for e in data["events"]]
        self.assertEqual(times, sorted(times))
        # The successful login should not be the first event in the timeline.
        self.assertNotEqual(data["events"][0]["EventType"], "SshLoginSuccess")

    def test_since_until_filter(self):
        code, out, err = run_cli([
            "--file", BRUTE_LOG, "--format", "json",
            "--since", "2026-10-08T10:00:03Z", "--until", "2026-10-08T10:00:05Z",
        ])
        data = json.loads(out)
        self.assertTrue(len(data["events"]) >= 1)
        for event in data["events"]:
            self.assertGreaterEqual(event["TimestampUtc"], "2026-10-08T10:00:03")


class TestCliHostileInput(unittest.TestCase):
    def test_control_characters_are_escaped_in_text_output(self):
        # The hostile sample contains a raw ESC and a raw BEL. They must not
        # appear verbatim in the output; they must be shown as \x1b / \x07.
        code, out, err = run_cli(["--file", HOSTILE_LOG, "--no-color"])
        self.assertEqual(code, 0)
        self.assertNotIn("\x1b", out)   # no raw ESC survived
        self.assertNotIn("\x07", out)   # no raw BEL survived
        self.assertIn("\\x1b", out)     # ESC shown as visible text
        self.assertIn("josé", out)      # a legitimate Unicode name is kept


class TestCliVersion(unittest.TestCase):
    def test_version_flag(self):
        code, out, err = run_cli(["--version"])
        self.assertEqual(code, 0)
        self.assertIn("0.1.0", out)


class TestCliErrors(unittest.TestCase):
    def test_missing_file(self):
        code, out, err = run_cli(["--file", "does_not_exist_12345.log"])
        self.assertEqual(code, 1)
        self.assertIn("Could not find", err)
        self.assertIn("journal-only", err)  # mentions Debian/Arch note

    def test_empty_file(self):
        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False
        )
        handle.close()
        try:
            code, out, err = run_cli(["--file", handle.name])
            self.assertEqual(code, 1)
            self.assertIn("empty", err)
        finally:
            os.remove(handle.name)

    def test_permission_denied_message(self):
        # Simulate open() raising PermissionError, independent of real perms.
        with mock.patch("LogTimeline.open", side_effect=PermissionError()):
            code, out, err = run_cli(["--file", "/var/log/auth.log"])
        self.assertEqual(code, 1)
        self.assertIn("Permission denied", err)
        self.assertIn("adm", err)

    def test_bad_date_filter(self):
        code, out, err = run_cli(["--file", NORMAL_LOG, "--since", "nonsense"])
        self.assertEqual(code, 1)
        self.assertIn("date filter", err)

    def test_usage_error_exit_code_two(self):
        # An invalid --type choice is a usage error: argparse exits with 2.
        code, out, err = run_cli(["--file", NORMAL_LOG, "--type", "NotAType"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
