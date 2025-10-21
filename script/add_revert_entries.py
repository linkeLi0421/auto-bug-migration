#!/usr/bin/env python3
"""
add_revert_entries.py

Usage:
    python add_revert_entries.py allowlist.txt            # writes allowlist.revert.txt
    python add_revert_entries.py allowlist.txt -o out.txt  # writes to out.txt
    python add_revert_entries.py allowlist.txt -i          # edit file in place

Behavior:
- For each line matching:  fun:<identifier>
  the script will ensure there is a line immediately after it: fun:__revert_<identifier>
- If the revert line already exists anywhere in the file, it will not be duplicated.
- Other lines (src:, comments, blank) are preserved in order.
"""

import argparse
import re
from pathlib import Path

FUN_RE = re.compile(r'^\s*fun\s*:\s*([A-Za-z_]\w*)\s*$')

def process_lines(lines, commit):
    """
    Returns a list of output lines with __revert_ entries inserted.
    """
    # Collect existing revert names to avoid duplicates
    existing_reverts = set()
    for ln in lines:
        m = re.match(r'^\s*fun\s*:\s*__revert_([A-Za-z_]\w*)\s*$', ln)
        if m:
            existing_reverts.add(m.group(1))

    out_lines = []
    for i, ln in enumerate(lines):
        out_lines.append(ln.rstrip('\n'))
        m = FUN_RE.match(ln)
        if m:
            name = m.group(1)
            if name in existing_reverts:
                # revert already exists somewhere; skip insertion to avoid duplicates
                continue
            revert_line = f"fun:__revert_{commit}_{name}"
            # If next non-empty line is already the revert we want, skip insertion.
            next_index = i + 1
            # Look ahead a small window to avoid false positives with comments/blank lines:
            lookahead_max = min(len(lines), i + 4)
            already_next = False
            while next_index < lookahead_max:
                nxt = lines[next_index].strip()
                if nxt == "":
                    next_index += 1
                    continue
                if nxt == revert_line:
                    already_next = True
                break
            if not already_next:
                out_lines.append(revert_line)

    # Add trailing newline to each line for writing
    return [l + "\n" for l in out_lines]

def main():
    p = argparse.ArgumentParser(description="Add fun:__revert_<commit hash>_<name> lines after each fun:<name> in an allowlist file.")
    p.add_argument("--commit", type=str, help="Commit hash")
    p.add_argument("infile", type=Path, help="Input allowlist file")
    p.add_argument("-o", "--out", type=Path, help="Output file (default: infile.revert.txt)")
    p.add_argument("-i", "--inplace", action="store_true", help="Edit input file in place (overwrites file)")
    args = p.parse_args()

    if not args.infile.exists():
        print(f"Error: {args.infile} not found.")
        raise SystemExit(2)

    out_path = args.out or (args.infile.with_name(args.infile.name + ".revert.txt"))
    if args.inplace:
        out_path = args.infile

    text = args.infile.read_text(encoding="utf-8")
    lines = text.splitlines(True)  # keep endings

    commit = args.commit
    new_lines = process_lines(lines, commit)
    out_path.write_text("".join(new_lines), encoding="utf-8")
    print(f"Wrote {len(new_lines)} lines to {out_path}")

if __name__ == "__main__":
    main()
