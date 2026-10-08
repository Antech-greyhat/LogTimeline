"""Timestamp parsing and timezone handling.

LogTimeline sorts events chronologically, which only works if every timestamp
is directly comparable. Log lines can carry different UTC offsets - the
owner's machine writes ``-04:00`` even though the owner sits in UTC+3 - so
this module does two jobs:

1. Turn the ISO 8601 timestamp text into a timezone-aware ``datetime``.
2. Convert that datetime to UTC, giving one common reference for sorting.

Only ISO 8601 timestamps are supported in v0.1. The classic syslog format
(``Oct  8 07:39:51``) has no year and no timezone, so it cannot be sorted
reliably across machines or across a year boundary; we detect it and report
it as unsupported rather than guessing.
"""

from datetime import datetime, timezone
from typing import FrozenSet


class UnsupportedTimestampError(ValueError):
    """Raised when a timestamp is not an ISO 8601 value we can use.

    Subclasses ``ValueError`` so existing ``except ValueError`` handlers keep
    working, while still letting callers catch this specific case.
    """


# The three-letter month names that begin a classic syslog timestamp. We use
# these only to *recognize* that format so we can print a helpful message -
# we never try to parse it in v0.1.
_CLASSIC_SYSLOG_MONTHS: FrozenSet[str] = frozenset(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)


def looks_like_classic_syslog(token: str) -> bool:
    """Return True if ``token`` is the leading month of a classic syslog line.

    Classic syslog lines look like ``Oct  8 07:39:51 host prog: msg``, so the
    very first token is a month abbreviation such as ``Oct``. ISO lines start
    with a year like ``2026-...`` instead. Checking the first token against
    the known month names is a simple, reliable signal.
    """
    return token in _CLASSIC_SYSLOG_MONTHS


def parse_iso_timestamp(token: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a timezone-aware datetime.

    Handles:
      * offsets such as ``+03:00`` and ``-04:00``
      * a trailing ``Z`` meaning UTC (``datetime.fromisoformat`` only learned
        to accept ``Z`` in Python 3.11, so we translate it ourselves to stay
        compatible with 3.9 and 3.10)
      * fractional seconds (microseconds)

    Raises ``UnsupportedTimestampError`` if the text is not ISO 8601, or if it
    has no timezone offset (an offset-less timestamp is ambiguous and every
    real line in the supported format carries one).
    """
    # Python 3.9/3.10 cannot parse a trailing "Z", so swap it for the
    # equivalent "+00:00" before handing the text to fromisoformat.
    if token.endswith("Z"):
        token = token[:-1] + "+00:00"

    try:
        parsed = datetime.fromisoformat(token)
    except ValueError:
        # Not ISO 8601. Raise a specific error so the caller can explain the
        # situation instead of letting a raw traceback reach the user.
        raise UnsupportedTimestampError(
            f"Timestamp is not ISO 8601: {token!r}"
        )

    # A timestamp with no offset is ambiguous (which timezone?). We refuse to
    # guess rather than silently sort events into the wrong order.
    if parsed.tzinfo is None:
        raise UnsupportedTimestampError(
            f"Timestamp has no timezone offset: {token!r}"
        )

    return parsed


def to_utc(moment: datetime) -> datetime:
    """Convert a timezone-aware datetime to UTC.

    Sorting events only makes sense once they share one timezone. We pick UTC
    because it has no daylight-saving jumps and is the natural common
    denominator for logs that may be gathered from several machines.
    """
    return moment.astimezone(timezone.utc)


def parse_user_datetime(text: str) -> datetime:
    """Parse a ``--since`` / ``--until`` value supplied on the command line.

    Accepts either a date (``2026-10-08``) or a full ISO datetime
    (``2026-10-08T07:00:00`` or ``2026-10-08T07:00:00+03:00``). A value with
    no timezone is assumed to be **UTC**, matching the tool's default UTC
    display, so filtering stays predictable. Always returns a UTC datetime.

    Raises ``UnsupportedTimestampError`` on anything it cannot read.
    """
    cleaned = text.strip()

    # Date only, e.g. "2026-10-08": treat it as midnight UTC on that day.
    if len(cleaned) == 10:
        try:
            naive = datetime.strptime(cleaned, "%Y-%m-%d")
        except ValueError:
            raise UnsupportedTimestampError(
                f"Could not read date {text!r}; expected YYYY-MM-DD."
            )
        return naive.replace(tzinfo=timezone.utc)

    # Otherwise expect a full ISO datetime (offset optional).
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        raise UnsupportedTimestampError(
            f"Could not read date/time {text!r}; use ISO 8601 like "
            f"2026-10-08 or 2026-10-08T07:00:00."
        )

    # No offset given -> assume UTC so the comparison is well defined.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return to_utc(parsed)
