import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from check_patch_order import _enforce_reorder_only


class EnforceReorderOnlyTests(unittest.TestCase):
    def test_filters_added_lines(self) -> None:
        original = "a\nb\nc"
        candidate = "b\nx\nc\na\ny"
        self.assertEqual(_enforce_reorder_only(original, candidate), "b\nc\na")

    def test_falls_back_if_missing_line(self) -> None:
        original = "a\nb\nc"
        candidate = "b\nc"
        self.assertEqual(_enforce_reorder_only(original, candidate), original)

    def test_preserves_duplicates(self) -> None:
        original = "a\na\nb"
        candidate = "a\nb\na"
        self.assertEqual(_enforce_reorder_only(original, candidate), candidate)


if __name__ == "__main__":
    unittest.main()
