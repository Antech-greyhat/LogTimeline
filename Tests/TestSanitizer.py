r"""Tests for Core.Sanitizer: control characters escaped, real text kept."""

import unittest
from Core.Sanitizer import sanitize


class TestSanitizer(unittest.TestCase):
    def test_normal_text_unchanged(self):
        self.assertEqual(sanitize("kali"), "kali")
        self.assertEqual(sanitize("/usr/bin/apt update"), "/usr/bin/apt update")

    def test_unicode_letters_preserved(self):
        # A legitimate non-English username should still display intact.
        self.assertEqual(sanitize("josé"), "josé")

    def test_escape_sequence_neutralized(self):
        # A fake "clear screen" ANSI sequence must be made visible, not run.
        cleaned = sanitize("admin\x1b[2J")
        self.assertNotIn("\x1b", cleaned)          # the ESC byte is gone
        self.assertIn("\\x1b", cleaned)            # shown as literal text
        self.assertTrue(cleaned.startswith("admin"))

    def test_control_characters_escaped(self):
        self.assertEqual(sanitize("a\x07b"), "a\\x07b")   # bell
        self.assertEqual(sanitize("a\nb"), "a\\x0ab")     # newline
        self.assertEqual(sanitize("a\x7fb"), "a\\x7fb")   # DEL

    def test_c1_range_escaped(self):
        self.assertEqual(sanitize("\x9b"), "\\x9b")       # C1 control


if __name__ == "__main__":
    unittest.main()
