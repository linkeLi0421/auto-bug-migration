"""Token and cost tracking for codex CLI (--json mode).

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

logger = logging.getLogger(__name__)

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

    def log_usage(self, label: str, output: str, model: str | None = None) -> None:
        """Parse codex JSONL output and log token usage + cost."""
        u = self.parse(output, model)
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

    def log_session_total(self) -> None:
        """Log accumulated session totals if any cost was tracked."""
        if self.cost > 0:
            logger.info(
                "=== Session token usage: %d in (%d cached) + %d out  |  "
                "Total cost: $%.4f ===",
                self.input_tokens, self.cached_input_tokens,
                self.output_tokens, self.cost,
            )
