"""Sort, filter and summarize events into a timeline.

The parser produces events in the order they appear in the file. This module
turns that stream into an analyst-friendly timeline:

* filter by time window (``--since`` / ``--until``) and by event type
  (``--type``),
* sort chronologically using the UTC timestamps, and
* count totals for the summary footer.

Sorting is done on ``TimestampUtc``, which the parser already converted to UTC,
so events coming from log lines with different offsets interleave correctly.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Sequence

from Core.EventModel import Event, ALL_EVENT_TYPES


@dataclass
class Summary:
    """The numbers shown in the text footer and the JSON ``summary`` block.

    ``events_recognized`` counts every event parsed from the file;
    ``events_shown`` counts those left after filtering. When no filters are
    used the two are equal. The time range and per-type counts always describe
    the events actually shown, so the footer matches the output above it.
    """

    lines_read: int
    events_recognized: int
    events_shown: int
    lines_skipped: int
    earliest: Optional[datetime]        # UTC time of the first shown event
    latest: Optional[datetime]          # UTC time of the last shown event
    counts_by_type: Dict[str, int]      # how many of each type were shown


def filter_events(
    events: Sequence[Event],
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    types: Optional[Sequence[str]] = None,
) -> List[Event]:
    """Return only the events that pass every active filter.

    ``since`` / ``until`` are inclusive UTC bounds (``None`` means no bound).
    ``types`` is a list of event-type names to keep; if given, anything whose
    type is not in the list is dropped. All comparisons use the UTC timestamp.
    """
    selected: List[Event] = []
    for event in events:
        if since is not None and event.TimestampUtc < since:
            continue
        if until is not None and event.TimestampUtc > until:
            continue
        if types and event.EventType not in types:
            continue
        selected.append(event)
    return selected


def sort_events(events: Sequence[Event]) -> List[Event]:
    """Return the events sorted oldest-first by their UTC timestamp."""
    return sorted(events, key=lambda event: event.TimestampUtc)


def build_summary(
    shown_events: Sequence[Event],
    lines_read: int,
    lines_skipped: int,
) -> Summary:
    """Build the summary from the events that will be displayed.

    ``shown_events`` should already be filtered and sorted, so ``earliest`` /
    ``latest`` can be read from the ends of the list. ``events_recognized`` is
    derived as ``lines_read - lines_skipped`` because every line that was read
    and not skipped became exactly one event.
    """
    counts = {name: 0 for name in ALL_EVENT_TYPES}
    for event in shown_events:
        # Defensive: only count known types. An unknown type should never
        # appear, but counting into a missing key would raise KeyError.
        if event.EventType in counts:
            counts[event.EventType] += 1

    earliest = shown_events[0].TimestampUtc if shown_events else None
    latest = shown_events[-1].TimestampUtc if shown_events else None

    return Summary(
        lines_read=lines_read,
        events_recognized=lines_read - lines_skipped,
        events_shown=len(shown_events),
        lines_skipped=lines_skipped,
        earliest=earliest,
        latest=latest,
        counts_by_type=counts,
    )
