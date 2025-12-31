#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agent_tools import AgentTools, KbIndex, SourceManager  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Tiny CLI wrapper for react_agent tooling."
    )
    parser.add_argument("symbol", help="Symbol name or USR to inspect")
    parser.add_argument(
        "--v1-json-dir",
        required=True,
        help="Root directory containing V1 *_analysis.json files",
    )
    parser.add_argument(
        "--v2-json-dir",
        required=True,
        help="Root directory containing V2 *_analysis.json files",
    )
    parser.add_argument(
        "--v1-src",
        default=".",
        help="Local filesystem root for V1 source code",
    )
    parser.add_argument(
        "--v2-src",
        default=".",
        help="Local filesystem root for V2 source code",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List matching AST nodes (file:line:col kind) instead of showing code",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max rows to print with --list",
    )
    return parser


def main(argv: list[str]) -> int:
    args = build_parser().parse_args(argv)
    kb = KbIndex(args.v1_json_dir, args.v2_json_dir)
    sm = SourceManager(args.v1_src, args.v2_src)
    tools = AgentTools(kb, sm)

    if args.list:
        nodes = kb.query_all(args.symbol)
        for ver in ("v1", "v2"):
            print(f"=== {ver} nodes ===")
            rows = []
            for n in nodes.get(ver, []):
                if not isinstance(n, dict):
                    continue
                loc = n.get("location", {}) or {}
                rows.append(
                    (
                        str(loc.get("file", "")),
                        int(loc.get("line", 0) or 0),
                        int(loc.get("column", 0) or 0),
                        str(n.get("kind", "")),
                    )
                )
            rows.sort()
            for file_path, line, col, kind in rows[: max(args.limit, 0)]:
                print(f"{file_path}:{line}:{col} {kind}")
            print()
        return 0

    print(tools.inspect_symbol(args.symbol))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
