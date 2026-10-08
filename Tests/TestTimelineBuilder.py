"""Tests for Core.TimelineBuilder: sorting, filtering and summary counts."""

import unittest
from datetime import datetime, timezone

from Core.EventModel import Event, EventType
from Core.TimelineBuilder import filter_events, sort_events, build_summary


def make_event(hour, event_type=EventType.SshLoginFailure, user="kali"):
    """Create a simple UTC event at a given hour, for testing."""
    return Event(
        TimestampUtc=datetime(2026, 10, 8, hour, 0, 0, tzinfo=timezone.utc),
        Host="kali", Program="sshd", EventType=event_type,
        RawLine="raw", User=user,
    )


class TestSorting(unittest.TestCase):
    def test_sort_orders_by_utc_time(self):
        events = [make_event(12), make_event(9), make_event(10)]
        ordered = sort_events(events)
        self.assertEqual([e.TimestampUtc.hour for e in ordered], [9, 10, 12])


class TestFiltering(unittest.TestCase):
    def test_filter_since_is_inclusive(self):
        events = [make_event(9), make_event(10), make_event(11)]
        since = datetime(2026, 10, 8, 10, tzinfo=timezone.utc)
        kept = filter_events(events, since=since)
        self.assertEqual([e.TimestampUtc.hour for e in kept], [10, 11])

    def test_filter_until_is_inclusive(self):
        events = [make_event(9), make_event(10), make_event(11)]
        until = datetime(2026, 10, 8, 10, tzinfo=timezone.utc)
        kept = filter_events(events, until=until)
        self.assertEqual([e.TimestampUtc.hour for e in kept], [9, 10])

    def test_filter_by_type(self):
        events = [
            make_event(9, EventType.SshLoginFailure),
            make_event(10, EventType.SudoCommand),
        ]
        kept = filter_events(events, types=[EventType.SudoCommand])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].EventType, EventType.SudoCommand)

    def test_no_filters_keeps_everything(self):
        events = [make_event(9), make_event(10)]
        self.assertEqual(len(filter_events(events)), 2)


class TestSummary(unittest.TestCase):
    def test_counts_and_range(self):
        events = sort_events([
            make_event(9, EventType.SshLoginFailure),
            make_event(10, EventType.SshLoginFailure),
            make_event(11, EventType.SudoCommand),
        ])
        summary = build_summary(events, lines_read=10, lines_skipped=3)
        self.assertEqual(summary.lines_read, 10)
        self.assertEqual(summary.lines_skipped, 3)
        self.assertEqual(summary.events_recognized, 7)   # 10 - 3
        self.assertEqual(summary.events_shown, 3)
        self.assertEqual(summary.counts_by_type[EventType.SshLoginFailure], 2)
        self.assertEqual(summary.counts_by_type[EventType.SudoCommand], 1)
        self.assertEqual(summary.earliest.hour, 9)
        self.assertEqual(summary.latest.hour, 11)

    def test_empty_summary(self):
        summary = build_summary([], lines_read=0, lines_skipped=0)
        self.assertIsNone(summary.earliest)
        self.assertIsNone(summary.latest)
        self.assertEqual(summary.events_shown, 0)
        self.assertEqual(summary.events_recognized, 0)


if __name__ == "__main__":
    unittest.main()
