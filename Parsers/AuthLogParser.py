"""Parser for Linux ``auth.log`` lines in ISO 8601 format.

This is the single place that knows what a log line looks like and which
events v0.1 recognizes. To add a new event type you add a recognizer here and
a constant in ``Core/EventModel.py`` - nothing else needs to change.

Design notes:
  * The parser is deliberately forgiving. Any line it does not understand is
    skipped and counted, never fatal - real logs contain many message types
    we do not model.
  * Log content is attacker-controlled (an attacker chooses the username they
    try to log in with). We only ever *match* text with narrow regular
    expressions and copy fields into an Event. We never execute, evaluate or
    trust anything we read. Making the text safe to print is a separate job,
    handled by ``Core/Sanitizer.py`` at output time.
"""

import re
from datetime import datetime
from typing import Iterable, Iterator, Optional

from Core.EventModel import Event, EventType
from Core.TimeUtils import (
    parse_iso_timestamp,
    to_utc,
    looks_like_classic_syslog,
    UnsupportedTimestampError,
)


# Overall shape of one syslog line in the supported format:
#   2026-10-08T07:39:51.894612-04:00 kali sudo: <message>
#   2026-10-08T07:39:51.894612-04:00 kali sshd[1234]: <message>
# Groups: timestamp (no spaces), host, program (maybe "[pid]"), message.
#   - timestamp is \S+  : a single run of non-space characters.
#   - program is [^\s:]+ : non-space, non-colon, so it stops at the colon that
#     separates the program from the message.
_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^\s:]+):\s*"
    r"(?P<message>.*)$"
)

# Strip a trailing "[1234]" process id from a program token like "sshd[1234]".
_PID_SUFFIX = re.compile(r"\[\d+\]$")

# --- Message patterns, one per recognized event ------------------------------
# Each pattern is anchored and uses named groups so it never over-matches.
# They are based on real OpenSSH / sudo / PAM messages. Any variant NOT covered
# by a test is treated as unsupported: the line is simply skipped and counted.

# "Accepted password for kali from 192.0.2.10 port 51514 ssh2"
# "Accepted publickey for kali from 192.0.2.10 port 51514 ssh2"
_SSH_ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# "Failed password for kali from 198.51.100.7 port 40222 ssh2"
# "Failed password for invalid user admin from 203.0.113.5 port 52814 ssh2"
_SSH_FAILED = re.compile(
    r"^Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

# "Invalid user admin from 203.0.113.5 port 52814"  (port is optional)
_SSH_INVALID_USER = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+)(?: port (?P<port>\d+))?"
)

# "kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/apt update"
_SUDO_COMMAND = re.compile(
    r"^(?P<user>\S+) : .*?COMMAND=(?P<command>.*)$"
)

# "kali : 3 incorrect password attempts ; TTY=pts/0 ; ..."
_SUDO_INCORRECT = re.compile(
    r"^(?P<user>\S+) : .*incorrect password attempt"
)

# Pull a username out of a PAM auth-failure line. We use a word boundary so
# "user=kali" matches but the "user=" inside "ruser=" does not.
_PAM_USER = re.compile(r"\b(?:logname|user)=(?P<user>\S+)")

# PAM session lines, e.g.
#   "pam_unix(sudo:session): session opened for user root(uid=0) by kali(...)"
#   "pam_unix(sudo:session): session closed for user root"
# The user group stops before "(" so "root(uid=0)" yields just "root".
_SESSION_OPENED = re.compile(r"session opened for user (?P<user>[^\s(]+)")
_SESSION_CLOSED = re.compile(r"session closed for user (?P<user>[^\s(]+)")


class AuthLogParser:
    """Turns auth.log lines into normalized ``Event`` objects.

    Create one parser, then call :meth:`parse_file` (streaming over a file) or
    :meth:`parse_line` (a single line). The parser keeps simple counters so the
    summary can report how many lines were read and skipped.
    """

    def __init__(self) -> None:
        self.lines_read = 0             # every non-blank line we looked at
        self.lines_skipped = 0          # lines we could not turn into events
        self.classic_format_lines = 0   # lines that look like classic syslog

    def parse_file(self, line_source: Iterable[str]) -> Iterator[Event]:
        """Yield one ``Event`` per recognized line in ``line_source``.

        ``line_source`` is any iterable of strings - typically an open file
        object, which Python reads one line at a time, so even a very large
        log is never loaded fully into memory.
        """
        for line in line_source:
            event = self.parse_line(line)
            if event is not None:
                yield event

    def parse_line(self, line: str) -> Optional[Event]:
        """Parse a single raw line into an ``Event``, or return ``None``.

        Returns ``None`` (and updates the skip counters) when the line is
        blank, in an unsupported format, or an event type we do not handle.
        """
        raw = line.rstrip("\n")
        stripped = raw.strip()
        if not stripped:
            # Blank lines are ignored entirely and not counted as "read".
            return None

        self.lines_read += 1

        # Detect classic syslog ("Oct  8 ...") up front so that, if nothing in
        # the file parses, the CLI can print a precise "format not supported"
        # message instead of a vague "no events found".
        first_token = stripped.split(" ", 1)[0]
        if looks_like_classic_syslog(first_token):
            self.classic_format_lines += 1
            self.lines_skipped += 1
            return None

        match = _LINE_PATTERN.match(raw)
        if match is None:
            self.lines_skipped += 1
            return None

        # Convert the timestamp to UTC here, at the edge of the system, so that
        # every Event downstream already carries a comparable UTC time. If the
        # timestamp is not ISO 8601 we skip the line rather than crash.
        try:
            moment = to_utc(parse_iso_timestamp(match.group("timestamp")))
        except UnsupportedTimestampError:
            self.lines_skipped += 1
            return None

        host = match.group("host")
        program = _PID_SUFFIX.sub("", match.group("program"))
        message = match.group("message")

        event = self._recognize(moment, host, program, message, raw)
        if event is None:
            self.lines_skipped += 1
        return event

    # -- recognition ----------------------------------------------------------

    def _recognize(
        self,
        moment: datetime,
        host: str,
        program: str,
        message: str,
        raw: str,
    ) -> Optional[Event]:
        """Match ``message`` against the known patterns and build an Event.

        Returns ``None`` if nothing matches. We check the program name first so
        a stray "Accepted ..." from an unrelated service is not mislabeled as
        an SSH login. PAM session messages are checked last because they can
        appear under several programs (sudo, sshd, cron, ...).
        """
        if program in ("sshd", "sshd-session"):
            ssh_event = self._recognize_ssh(moment, host, program, message, raw)
            if ssh_event is not None:
                return ssh_event

        if program == "sudo":
            sudo_event = self._recognize_sudo(moment, host, program, message, raw)
            if sudo_event is not None:
                return sudo_event

        return self._recognize_session(moment, host, program, message, raw)

    def _recognize_ssh(self, moment, host, program, message, raw):
        """Recognize the three SSH event types from an sshd message."""
        accepted = _SSH_ACCEPTED.match(message)
        if accepted:
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SshLoginSuccess, RawLine=raw,
                User=accepted.group("user"),
                SourceIp=accepted.group("ip"),
                Port=int(accepted.group("port")),
            )

        failed = _SSH_FAILED.match(message)
        if failed:
            # Note: "Failed password for invalid user admin ..." is reported as
            # a login FAILURE (the user string is the attempted name). A bare
            # "Invalid user ..." line is reported separately below.
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SshLoginFailure, RawLine=raw,
                User=failed.group("user"),
                SourceIp=failed.group("ip"),
                Port=int(failed.group("port")),
            )

        invalid = _SSH_INVALID_USER.match(message)
        if invalid:
            port = invalid.group("port")
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SshInvalidUser, RawLine=raw,
                User=invalid.group("user"),
                SourceIp=invalid.group("ip"),
                Port=int(port) if port else None,
            )
        return None

    def _recognize_sudo(self, moment, host, program, message, raw):
        """Recognize sudo auth-failure and sudo-command events."""
        # A sudo auth failure shows up two ways: the PAM "authentication
        # failure" line, or a summary like "... 3 incorrect password attempts".
        # Both are checked before the normal command pattern because the
        # "incorrect attempts" line also contains a COMMAND= field.
        if "authentication failure" in message:
            found = _PAM_USER.search(message)
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SudoAuthFailure, RawLine=raw,
                User=found.group("user") if found else None,
            )

        incorrect = _SUDO_INCORRECT.match(message)
        if incorrect:
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SudoAuthFailure, RawLine=raw,
                User=incorrect.group("user"),
            )

        command = _SUDO_COMMAND.match(message)
        if command:
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SudoCommand, RawLine=raw,
                User=command.group("user"),
                Command=command.group("command"),
            )
        return None

    def _recognize_session(self, moment, host, program, message, raw):
        """Recognize PAM session open/close events (any program)."""
        opened = _SESSION_OPENED.search(message)
        if opened:
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SessionOpened, RawLine=raw,
                User=opened.group("user"),
            )

        closed = _SESSION_CLOSED.search(message)
        if closed:
            return Event(
                TimestampUtc=moment, Host=host, Program=program,
                EventType=EventType.SessionClosed, RawLine=raw,
                User=closed.group("user"),
            )
        return None
