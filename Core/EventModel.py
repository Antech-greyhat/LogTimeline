"""Data model for LogTimeline.

This module defines the two building blocks the rest of the program shares:

* ``EventType`` - the fixed set of security events v0.1 understands.
* ``Event``     - one normalized record, the same shape no matter which
                  log line produced it.

Keeping the data model in one small module means every other file agrees on
exactly what an "event" looks like.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


class EventType:
    """The event types LogTimeline v0.1 can recognize.

    These are plain string constants (not an ``Enum``) to keep things simple
    for readers new to Python, and so the values drop straight into JSON
    output without any conversion.

    To add a new event type later you change exactly two places:
      1. add a constant here, and
      2. teach ``Parsers/AuthLogParser.py`` how to recognize it.
    Nothing else in the program needs to change.
    """

    SshLoginSuccess = "SshLoginSuccess"
    SshLoginFailure = "SshLoginFailure"
    SshInvalidUser = "SshInvalidUser"
    SudoCommand = "SudoCommand"
    SudoAuthFailure = "SudoAuthFailure"
    SessionOpened = "SessionOpened"
    SessionClosed = "SessionClosed"


# A tuple of every known type. Used to validate the --type flag and to build
# the per-type counts in the summary. Defined once here so there is a single
# source of truth; the CLI and the summary both read from it.
ALL_EVENT_TYPES = (
    EventType.SshLoginSuccess,
    EventType.SshLoginFailure,
    EventType.SshInvalidUser,
    EventType.SudoCommand,
    EventType.SudoAuthFailure,
    EventType.SessionOpened,
    EventType.SessionClosed,
)


@dataclass
class Event:
    """One security-relevant event, normalized into a common shape.

    Every recognized log line becomes exactly one ``Event``. Fields that do
    not apply to a given event stay ``None`` (for example a session-close
    line has no source IP or port).

    Note on the field names: they are PascalCase to match the documented
    output schema (and the project's PascalCase convention), so the JSON keys
    users see line up with the attribute names in the code. Python normally
    uses snake_case for attributes, so this is a deliberate, consistent
    exception rather than an accident.
    """

    # --- Required fields (no default): every event has these. -----------
    TimestampUtc: datetime   # timezone-aware, always converted to UTC
    Host: str                # hostname from the log line, e.g. "kali"
    Program: str             # program name without [pid], e.g. "sshd"
    EventType: str           # one of the EventType constants above
    RawLine: str             # the original line, kept for reference/audit

    # --- Optional fields (default None): present only when relevant. ----
    User: Optional[str] = None       # account named in the line, if any
    SourceIp: Optional[str] = None   # remote IP, for SSH events
    Port: Optional[int] = None       # remote port, for SSH events
    Command: Optional[str] = None    # command run, for sudo command events
