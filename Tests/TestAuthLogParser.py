"""Tests for Parsers.AuthLogParser: every event type, skipping, counting."""

import unittest

from Parsers.AuthLogParser import AuthLogParser
from Core.EventModel import EventType


class TestAuthLogParser(unittest.TestCase):
    def setUp(self):
        self.parser = AuthLogParser()

    def parse_one(self, line):
        """Helper: parse one line and return the Event (or None)."""
        return self.parser.parse_line(line)

    # --- SSH events ----------------------------------------------------------

    def test_ssh_login_success_password(self):
        line = ("2026-10-08T07:40:00-04:00 kali sshd[1200]: "
                "Accepted password for kali from 192.0.2.10 port 51514 ssh2")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshLoginSuccess)
        self.assertEqual(event.User, "kali")
        self.assertEqual(event.SourceIp, "192.0.2.10")
        self.assertEqual(event.Port, 51514)
        self.assertEqual(event.Program, "sshd")

    def test_ssh_login_success_publickey(self):
        line = ("2026-10-08T07:40:00-04:00 kali sshd[1200]: "
                "Accepted publickey for kali from 192.0.2.10 port 51514 ssh2")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshLoginSuccess)

    def test_ssh_login_failure(self):
        line = ("2026-10-08T07:41:00-04:00 kali sshd[1201]: "
                "Failed password for kali from 198.51.100.7 port 40222 ssh2")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshLoginFailure)
        self.assertEqual(event.User, "kali")
        self.assertEqual(event.SourceIp, "198.51.100.7")
        self.assertEqual(event.Port, 40222)

    def test_ssh_login_failure_invalid_user(self):
        line = ("2026-10-08T07:41:30-04:00 kali sshd[1202]: Failed password "
                "for invalid user admin from 203.0.113.5 port 52814 ssh2")
        event = self.parse_one(line)
        # An "invalid user" failed password is still a login FAILURE; the
        # attempted name is captured as the user.
        self.assertEqual(event.EventType, EventType.SshLoginFailure)
        self.assertEqual(event.User, "admin")

    def test_ssh_invalid_user_with_port(self):
        line = ("2026-10-08T07:41:30-04:00 kali sshd[1202]: "
                "Invalid user admin from 203.0.113.5 port 52814")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshInvalidUser)
        self.assertEqual(event.User, "admin")
        self.assertEqual(event.SourceIp, "203.0.113.5")
        self.assertEqual(event.Port, 52814)

    def test_ssh_invalid_user_without_port(self):
        line = ("2026-10-08T07:41:30-04:00 kali sshd[1202]: "
                "Invalid user admin from 203.0.113.5")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshInvalidUser)
        self.assertIsNone(event.Port)

    def test_sshd_session_program_name_accepted(self):
        # Newer OpenSSH uses "sshd-session" instead of "sshd".
        line = ("2026-10-08T07:42:00-04:00 kali sshd-session[1300]: "
                "Accepted password for kali from 192.0.2.10 port 51600 ssh2")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SshLoginSuccess)
        self.assertEqual(event.Program, "sshd-session")

    # --- sudo events ---------------------------------------------------------

    def test_sudo_command(self):
        line = ("2026-10-08T07:43:00-04:00 kali sudo: kali : TTY=pts/0 ; "
                "PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SudoCommand)
        self.assertEqual(event.User, "kali")
        self.assertEqual(event.Command, "/usr/bin/apt update")

    def test_sudo_auth_failure_pam(self):
        line = ("2026-10-08T07:44:00-04:00 kali sudo: "
                "pam_unix(sudo:auth): authentication failure; "
                "logname=kali uid=1000 euid=0 tty=/dev/pts/0 ruser= "
                "rhost=  user=kali")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SudoAuthFailure)
        self.assertEqual(event.User, "kali")

    def test_sudo_auth_failure_incorrect_attempts(self):
        line = ("2026-10-08T07:44:30-04:00 kali sudo: kali : 3 incorrect "
                "password attempts ; TTY=pts/0 ; PWD=/home/kali ; "
                "USER=root ; COMMAND=/usr/bin/less /var/log/auth.log")
        event = self.parse_one(line)
        # Classified as an auth failure, not a command, even though the line
        # also carries a COMMAND= field.
        self.assertEqual(event.EventType, EventType.SudoAuthFailure)
        self.assertEqual(event.User, "kali")

    # --- session events ------------------------------------------------------

    def test_session_opened(self):
        line = ("2026-10-08T07:45:00-04:00 kali sudo: "
                "pam_unix(sudo:session): session opened for user "
                "root(uid=0) by kali(uid=1000)")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SessionOpened)
        self.assertEqual(event.User, "root")

    def test_session_closed_owner_exact_line(self):
        # This is the exact line format verified on the owner's machine.
        line = ("2026-10-08T07:39:51.894612-04:00 kali sudo: "
                "pam_unix(sudo:session): session closed for user root")
        event = self.parse_one(line)
        self.assertEqual(event.EventType, EventType.SessionClosed)
        self.assertEqual(event.User, "root")
        self.assertEqual(event.Host, "kali")
        self.assertEqual(event.Program, "sudo")

    # --- skipping / counting / timezone --------------------------------------

    def test_unrecognized_line_is_skipped_and_counted(self):
        line = ("2026-10-08T07:46:00-04:00 kali systemd-logind[400]: "
                "New session 3 of user kali.")
        event = self.parse_one(line)
        self.assertIsNone(event)
        self.assertEqual(self.parser.lines_read, 1)
        self.assertEqual(self.parser.lines_skipped, 1)

    def test_blank_line_not_counted(self):
        self.assertIsNone(self.parse_one("   \n"))
        self.assertEqual(self.parser.lines_read, 0)
        self.assertEqual(self.parser.lines_skipped, 0)

    def test_classic_syslog_line_flagged(self):
        line = "Oct  8 07:39:51 kali sudo: session closed for user root"
        event = self.parse_one(line)
        self.assertIsNone(event)
        self.assertEqual(self.parser.classic_format_lines, 1)
        self.assertEqual(self.parser.lines_skipped, 1)

    def test_timestamp_converted_to_utc(self):
        line = ("2026-10-08T07:39:51-04:00 kali sudo: "
                "pam_unix(sudo:session): session closed for user root")
        event = self.parse_one(line)
        # -04:00 07:39 becomes 11:39 UTC.
        self.assertEqual(event.TimestampUtc.hour, 11)
        self.assertEqual(str(event.TimestampUtc.tzinfo), "UTC")

    def test_parse_file_counts_and_yields(self):
        lines = [
            "2026-10-08T07:40:00-04:00 kali sshd[1200]: Accepted password "
            "for kali from 192.0.2.10 port 51514 ssh2\n",
            "garbage line that will not match\n",
            "\n",  # blank: ignored, not counted
        ]
        events = list(self.parser.parse_file(lines))
        self.assertEqual(len(events), 1)
        self.assertEqual(self.parser.lines_read, 2)
        self.assertEqual(self.parser.lines_skipped, 1)


if __name__ == "__main__":
    unittest.main()
