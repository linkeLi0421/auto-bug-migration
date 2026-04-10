import unittest
from unittest import mock

from script.codex_usage import CodexUsageTracker


class CodexUsageTrackerTest(unittest.TestCase):
    def test_parse_tui_output_parses_cached_input_summary(self) -> None:
        tracker = CodexUsageTracker()

        output = "Tokens: 12,345 input, 6,789 cached input, 4,567 output\nCost: $0.1234\n"

        usage = tracker.parse_tui_output(output, model="gpt-5.4-medium")

        self.assertEqual(
            usage,
            {
                "input_tokens": 12345,
                "cached_input_tokens": 6789,
                "output_tokens": 4567,
                "cost": 0.1234,
            },
        )

    def test_parse_tui_output_does_not_crash_on_cached_input_label(self) -> None:
        tracker = CodexUsageTracker()

        output = "cached input, 4,567 output\n"

        usage = tracker.parse_tui_output(output, model="gpt-5.4-medium")

        self.assertEqual(
            usage,
            {
                "input_tokens": 0,
                "cached_input_tokens": 0,
                "output_tokens": 0,
                "cost": 0.0,
            },
        )

    def test_log_usage_swallows_parser_failures(self) -> None:
        tracker = CodexUsageTracker()

        with mock.patch.object(
            tracker,
            "parse_tui_output",
            side_effect=RuntimeError("boom"),
        ):
            tracker.log_usage("transplant", "not jsonl")

        self.assertEqual(tracker.input_tokens, 0)
        self.assertEqual(tracker.cached_input_tokens, 0)
        self.assertEqual(tracker.output_tokens, 0)
        self.assertEqual(tracker.cost, 0.0)


if __name__ == "__main__":
    unittest.main()
