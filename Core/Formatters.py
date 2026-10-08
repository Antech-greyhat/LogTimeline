"""Turn a list of events and a summary into text or JSON output.

Two output formats are supported in v0.1:

* ``text`` - a human-readable timeline, one event per line, with optional ANSI
  color and a summary footer. Every log-derived field is passed through the
  sanitizer first, so hostile log content cannot attack the terminal.
* ``json`` - machine-readable output built with the standard ``json`` module
  (never assembled by hand), which safely escapes any control characters.

Timestamps are shown in UTC by default. ``--local`` switches the *text* display
to the machine's local timezone; JSON always uses UTC, because the field is
named ``TimestampUtc`` and tools consuming the JSON expect a stable value.
"""

import json
from datetime import datetime
from typing import List

from Core.EventModel import Event
from Core.Sanitizer import sanitize
from Core.TimelineBuilder import Summary


# ANSI color codes, used only when color is enabled. Kept in one place so the
# palette is easy to find and change.
_COLORS = {
    "reset": "\x1b[0m",
    "red": "\x1b[31m",
    "green": "\x1b[32m",
    "yellow": "\x1b[33m",
    "blue": "\x1b[34m",
    "cyan": "\x1b[36m",
    "grey": "\x1b[90m",
}

# Which color each event type uses in the text timeline. Failures are red so
# they stand out when scanning; a successful login is green; sudo is cyan.
_EVENT_COLORS = {
    "SshLoginSuccess": "green",
    "SshLoginFailure": "red",
    "SshInvalidUser": "yellow",
    "SudoCommand": "cyan",
    "SudoAuthFailure": "red",
    "SessionOpened": "blue",
    "SessionClosed": "grey",
}

# Width of the event-type column so rows line up. The longest type name is 15
# characters (e.g. "SshLoginSuccess"), so 16 leaves a single space of padding.
_TYPE_WIDTH = 16


def _format_time(moment: datetime, use_local: bool) -> str:
    """Format a UTC datetime for display.

    In UTC mode we append a plain ``Z``. In local mode we convert to the
    machine's timezone and show the offset (e.g. ``+0300``) so the reader can
    see which timezone the time is in.
    """
    if use_local:
        local = moment.astimezone()  # no argument -> system local timezone
        return local.strftime("%Y-%m-%d %H:%M:%S %z")
    return moment.strftime("%Y-%m-%d %H:%M:%S") + "Z"


def _event_details(event: Event) -> str:
    """Build the ``key=value`` detail text for one event (text format).

    Only fields that are present are shown. Every value that came from the log
    is sanitized, because usernames, IPs and commands are attacker-influenced.
    The port is an integer we parsed ourselves, so it is safe as-is.
    """
    parts: List[str] = []
    if event.User is not None:
        parts.append("user=" + sanitize(event.User))
    if event.SourceIp is not None:
        parts.append("ip=" + sanitize(event.SourceIp))
    if event.Port is not None:
        parts.append("port=" + str(event.Port))
    if event.Command is not None:
        parts.append("cmd=" + sanitize(event.Command))
    return " ".join(parts)


def _format_event_line(event: Event, use_local: bool, use_color: bool) -> str:
    """Format one event as a single timeline line."""
    time_text = _format_time(event.TimestampUtc, use_local)

    # Pad the type to a fixed width BEFORE adding color codes, so the
    # (invisible) codes do not throw the column alignment off.
    type_column = "{0:<{1}}".format(event.EventType, _TYPE_WIDTH)
    if use_color:
        color_name = _EVENT_COLORS.get(event.EventType)
        if color_name:
            type_column = _COLORS[color_name] + type_column + _COLORS["reset"]

    details = _event_details(event)
    return "{0}  {1}  {2}".format(time_text, type_column, details).rstrip()


def _format_summary(summary: Summary, use_local: bool) -> List[str]:
    """Build the summary footer lines (text format)."""
    lines = ["", "Summary", "-------"]
    lines.append("Lines read:        {0}".format(summary.lines_read))
    lines.append("Events recognized: {0}".format(summary.events_recognized))
    # Only mention "shown" when filtering actually reduced the set, to avoid
    # cluttering the common no-filter case.
    if summary.events_shown != summary.events_recognized:
        lines.append(
            "Events shown:      {0}  (after filters)".format(summary.events_shown)
        )
    lines.append("Lines skipped:     {0}".format(summary.lines_skipped))

    if summary.earliest is not None and summary.latest is not None:
        start = _format_time(summary.earliest, use_local)
        end = _format_time(summary.latest, use_local)
        lines.append("Time range:        {0}  ->  {1}".format(start, end))
    else:
        lines.append("Time range:        (no events to show)")

    lines.append("By event type:")
    any_shown = False
    for name, count in summary.counts_by_type.items():
        if count:
            any_shown = True
            lines.append("  {0:<{1}} {2}".format(name, _TYPE_WIDTH, count))
    if not any_shown:
        lines.append("  (none)")
    return lines


def format_text(
    events: List[Event],
    summary: Summary,
    use_local: bool = False,
    use_color: bool = False,
) -> str:
    """Render the full text timeline: one line per event, then the footer."""
    lines = [_format_event_line(e, use_local, use_color) for e in events]
    lines.extend(_format_summary(summary, use_local))
    return "\n".join(lines)


def _event_to_dict(event: Event) -> dict:
    """Convert one Event to a plain dict with stable, ordered keys."""
    return {
        "TimestampUtc": event.TimestampUtc.isoformat(),
        "Host": event.Host,
        "Program": event.Program,
        "EventType": event.EventType,
        "User": event.User,
        "SourceIp": event.SourceIp,
        "Port": event.Port,
        "Command": event.Command,
        "RawLine": event.RawLine,
    }


def _summary_to_dict(summary: Summary) -> dict:
    """Convert the Summary to a plain dict for JSON output."""
    return {
        "LinesRead": summary.lines_read,
        "EventsRecognized": summary.events_recognized,
        "EventsShown": summary.events_shown,
        "LinesSkipped": summary.lines_skipped,
        "Earliest": summary.earliest.isoformat() if summary.earliest else None,
        "Latest": summary.latest.isoformat() if summary.latest else None,
        # Only include types that actually occurred, to keep the output tidy.
        "CountsByType": {k: v for k, v in summary.counts_by_type.items() if v},
    }


def format_json(
    events: List[Event],
    summary: Summary,
    use_local: bool = False,  # accepted for a uniform interface; see note below
) -> str:
    """Render the timeline as JSON.

    ``use_local`` is accepted so this function has the same shape as
    ``format_text``, but it is intentionally ignored: JSON always reports UTC,
    because the field is literally named ``TimestampUtc`` and machines reading
    it expect one stable timezone. The ``json`` module escapes any control
    characters, so no manual sanitizing is needed here.
    """
    payload = {
        "events": [_event_to_dict(event) for event in events],
        "summary": _summary_to_dict(summary),
    }
    return json.dumps(payload, indent=2)
