"""Tests for Core.TimeUtils: ISO parsing, UTC conversion, and user dates."""

import unittest
from datetime import datetime, timezone, timedelta

from Core.TimeUtils import (
    parse_iso_timestamp,
    to_utc,
    parse_user_datetime,
    looks_like_classic_syslog,
    UnsupportedTimestampError,
)


class TestParseIsoTimestamp(unittest.TestCase):
    def test_negative_offset_with_microseconds(self):
        # The owner's real machine writes -04:00 with microseconds.
        moment = parse_iso_timestamp("2026-10-08T07:39:51.894612-04:00")
        self.assertEqual(moment.utcoffset(), timedelta(hours=-4))
        self.assertEqual(moment.microsecond, 894612)

    def test_positive_offset(self):
        moment = parse_iso_timestamp("2026-10-08T07:39:51+03:00")
        self.assertEqual(moment.utcoffset(), timedelta(hours=3))

    def test_zulu_suffix_is_utc(self):
        # "Z" must be accepted even on Python 3.9 / 3.10.
        moment = parse_iso_timestamp("2026-10-08T07:39:51Z")
        self.assertEqual(moment.utcoffset(), timedelta(0))

    def test_missing_offset_is_rejected(self):
        with self.assertRaises(UnsupportedTimestampError):
            parse_iso_timestamp("2026-10-08T07:39:51")

    def test_non_iso_token_is_rejected(self):
        with self.assertRaises(UnsupportedTimestampError):
            parse_iso_timestamp("Oct")


class TestToUtc(unittest.TestCase):
    def test_converts_to_utc(self):
        moment = parse_iso_timestamp("2026-10-08T07:39:51-04:00")
        as_utc = to_utc(moment)
        self.assertEqual(as_utc.tzinfo, timezone.utc)
        # 07:39 at -04:00 is 11:39 UTC.
        self.assertEqual(as_utc.hour, 11)
        self.assertEqual(as_utc.minute, 39)

    def test_mixed_offsets_sort_correctly(self):
        # One event at 07:00-04:00 (= 11:00 UTC) and one at 10:00+03:00
        # (= 07:00 UTC). In UTC the +03:00 one is EARLIER, even though its
        # wall-clock time looks later. This is exactly why we sort on UTC.
        a = to_utc(parse_iso_timestamp("2026-10-08T07:00:00-04:00"))  # 11:00Z
        b = to_utc(parse_iso_timestamp("2026-10-08T10:00:00+03:00"))  # 07:00Z
        self.assertLess(b, a)


class TestParseUserDatetime(unittest.TestCase):
    def test_date_only_is_utc_midnight(self):
        moment = parse_user_datetime("2026-10-08")
        self.assertEqual(moment, datetime(2026, 10, 8, tzinfo=timezone.utc))

    def test_datetime_without_offset_is_utc(self):
        moment = parse_user_datetime("2026-10-08T07:00:00")
        self.assertEqual(moment, datetime(2026, 10, 8, 7, tzinfo=timezone.utc))

    def test_datetime_with_offset_converts_to_utc(self):
        moment = parse_user_datetime("2026-10-08T10:00:00+03:00")
        self.assertEqual(moment, datetime(2026, 10, 8, 7, tzinfo=timezone.utc))

    def test_bad_value_raises(self):
        with self.assertRaises(UnsupportedTimestampError):
            parse_user_datetime("nonsense")


class TestClassicDetection(unittest.TestCase):
    def test_month_names_detected(self):
        self.assertTrue(looks_like_classic_syslog("Oct"))
        self.assertTrue(looks_like_classic_syslog("Jan"))

    def test_iso_year_not_detected(self):
        self.assertFalse(looks_like_classic_syslog("2026-10-08T07:39:51Z"))


if __name__ == "__main__":
    unittest.main()
