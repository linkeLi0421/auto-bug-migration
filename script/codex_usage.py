"""Token and cost tracking for codex CLI.

Supports two output formats:
- JSONL from ``codex exec --json`` (structured, precise)
- Raw TUI output captured via ``tmux pipe-pane`` (best-effort regex parsing)

Usage:

    from codex_usage import CodexUsageTracker

    tracker = CodexUsageTracker()
    tracker.log_usage("step label", codex_jsonl_output, model="gpt-5.4-medium")
    # ... at the end ...
    tracker.log_session_total()
"""
from __future__ import annotations

import json
import logging
import re

logger = logging.getLogger(__name__)

# Strip ANSI escape sequences (CSI, OSC, etc.)
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[()][AB012]|\x1b\[[\d;]*m")

# Pricing per 1M tokens (update as needed)
CODEX_PRICING = {
    "gpt-5.4-medium": {"input": 2.50, "cached_input": 0.625, "output": 10.00},
}
CODEX_PRICING_DEFAULT = {"input": 2.50, "cached_input": 0.625, "output": 10.00}


class CodexUsageTracker:
    """Accumulates token usage and cost across multiple codex invocations."""

    def __init__(self) -> None:
        self.input_tokens = 0
        self.cached_input_tokens = 0
        self.output_tokens = 0
        self.cost = 0.0

    def parse(self, output: str, model: str | None = None) -> dict:
        """Parse JSONL output from ``codex exec --json`` and return usage dict."""
        total_in = 0
        total_cached = 0
        total_out = 0
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            usage = ev.get("usage")
            if usage:
                total_in += usage.get("input_tokens", 0)
                total_cached += usage.get("cached_input_tokens", 0)
                total_out += usage.get("output_tokens", 0)

        pricing = CODEX_PRICING.get(model or "", CODEX_PRICING_DEFAULT)
        uncached_in = total_in - total_cached
        cost = (
            uncached_in * pricing["input"] / 1_000_000
            + total_cached * pricing["cached_input"] / 1_000_000
            + total_out * pricing["output"] / 1_000_000
        )

        self.input_tokens += total_in
        self.cached_input_tokens += total_cached
        self.output_tokens += total_out
        self.cost += cost

        return {
            "input_tokens": total_in,
            "cached_input_tokens": total_cached,
            "output_tokens": total_out,
            "cost": cost,
        }

    def parse_tui_output(self, output: str, model: str | None = None) -> dict:
        """Best-effort extraction of token/cost info from raw TUI output.

        The Codex TUI renders a summary that typically looks like::

            Tokens: 12 345 input, 4 567 output
            Cost:   $0.1234

        Numbers may contain spaces or commas as thousands separators.
        Returns the same dict shape as :meth:`parse`.
        """
        clean = _ANSI_RE.sub("", output)
        number = r"\d[\d\s,]*"

        def _parse_num(s: str) -> int:
            """Strip thousands separators and convert to int."""
            normalized = re.sub(r"[\s,]", "", s)
            if not normalized:
                return 0
            return int(normalized)

        total_in = 0
        total_cached = 0
        total_out = 0
        cost = 0.0

        # Look for token counts line by line. Requiring a leading digit avoids
        # false positives such as matching the whitespace in "cached input".
        token_patterns = [
            re.compile(
                rf"Tokens:\s*(?P<input>{number})\s*input\b"
                rf"(?:.*?(?P<cached>{number})\s*cached input\b)?"
                rf".*?(?P<output>{number})\s*output\b",
                re.IGNORECASE,
            ),
            re.compile(
                rf"\binput:\s*(?P<input>{number})\b.*?"
                rf"\boutput:\s*(?P<output>{number})\b",
                re.IGNORECASE,
            ),
            re.compile(
                rf"(?P<input>{number})\s*input\b.*?"
                rf"(?P<output>{number})\s*output\b",
                re.IGNORECASE,
            ),
        ]
        for line in clean.splitlines():
            for pattern in token_patterns:
                m = pattern.search(line)
                if not m:
                    continue
                total_in = _parse_num(m.group("input"))
                total_out = _parse_num(m.group("output"))
                cached_group = m.groupdict().get("cached")
                if cached_group:
                    total_cached = _parse_num(cached_group)
                break
            if total_in or total_out or total_cached:
                break

        # Look for cost: "$0.1234" or "cost: $1.23"
        m = re.search(r"\$\s*([\d.]+)", clean)
        if m:
            cost = float(m.group(1))

        # If we found tokens but no explicit cost, compute it
        if total_in + total_out > 0 and cost == 0.0:
            pricing = CODEX_PRICING.get(model or "", CODEX_PRICING_DEFAULT)
            uncached_in = max(total_in - total_cached, 0)
            cost = (
                uncached_in * pricing["input"] / 1_000_000
                + total_cached * pricing["cached_input"] / 1_000_000
                + total_out * pricing["output"] / 1_000_000
            )

        self.input_tokens += total_in
        self.cached_input_tokens += total_cached
        self.output_tokens += total_out
        self.cost += cost

        return {
            "input_tokens": total_in,
            "cached_input_tokens": total_cached,
            "output_tokens": total_out,
            "cost": cost,
        }

    def log_usage(self, label: str, output: str, model: str | None = None) -> None:
        """Parse codex output and log token usage + cost.

        Tries JSONL parsing first; falls back to TUI regex extraction.
        """
        try:
            u = self.parse(output, model)
            if u["input_tokens"] == 0 and u["output_tokens"] == 0:
                # JSONL parsing found nothing — try TUI output fallback
                u = self.parse_tui_output(output, model)
            if u["input_tokens"] == 0 and u["output_tokens"] == 0:
                return
            logger.info(
                "[%s] Tokens: %d in (%d cached) + %d out = %d total  |  "
                "Cost: $%.4f  |  Session total: $%.4f",
                label,
                u["input_tokens"], u["cached_input_tokens"], u["output_tokens"],
                u["input_tokens"] + u["output_tokens"],
                u["cost"], self.cost,
            )
        except Exception:
            logger.warning("Failed to parse Codex usage for %s", label, exc_info=True)

    def log_session_total(self) -> None:
        """Log accumulated session totals if any cost was tracked."""
        if self.cost > 0:
            logger.info(
                "=== Session token usage: %d in (%d cached) + %d out  |  "
                "Total cost: $%.4f ===",
                self.input_tokens, self.cached_input_tokens,
                self.output_tokens, self.cost,
            )
