#!/usr/bin/env python3
"""Aggregate per-project duplication reports into one cross-project summary."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def parse_report(path: Path) -> dict | None:
    """Parse the Level-1 and Crashes tables from a per-project report."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None

    # Level 1 single-row table: "| raw | ff | ffl |"
    m = re.search(
        r"## Level 1.*?\| raw OSV ids \|.*?\n\| ---: \|.*?\n"
        r"\| (\d+) \| (\d+) \| (\d+) \|",
        text, re.S,
    )
    if not m:
        return None
    raw_bugs, bug_ff, bug_ffl = int(m.group(1)), int(m.group(2)), int(m.group(3))

    # Crashes single-row table: "| raw | ff | ffl | matched |"
    m2 = re.search(
        r"## Crashes.*?unique FuzzBench `crash_key`s.*?\n\| ---: \|.*?\n"
        r"\| (\d+) \| (\d+) \| (\d+) \| (\d+) \|",
        text, re.S,
    )
    if m2:
        raw_crashes = int(m2.group(1))
        crash_ff = int(m2.group(2))
        crash_ffl = int(m2.group(3))
        matched = int(m2.group(4))
    else:
        raw_crashes = crash_ff = crash_ffl = matched = None

    # Total crash occurrences (context number below the crashes table)
    m3 = re.search(r"represent \*\*([\d,]+) total crash occurrences\*\*", text)
    total_occ = int(m3.group(1).replace(",", "")) if m3 else None

    # Biggest duplicate group for the narrative column.
    biggest = re.search(
        r"Bugs that share a top-3 `\(function, file\)` fingerprint\n"
        r"\n"
        r"\| top-3.*?\n\| --- \|.*?\n"
        r"\| `([^`]+)` \| ([^|]+?) \| (\d+) \|",
        text, re.S,
    )
    l1_example = None
    if biggest:
        l1_example = {
            "chain": biggest.group(1).strip(),
            "ids": biggest.group(2).strip(),
            "count": int(biggest.group(3)),
        }

    return {
        "bugs_raw": raw_bugs,
        "bugs_ff": bug_ff,
        "bugs_ffl": bug_ffl,
        "crashes_raw": raw_crashes,
        "crashes_ff": crash_ff,
        "crashes_ffl": crash_ffl,
        "crashes_matching_transplant": matched,
        "crash_occurrences_total": total_occ,
        "l1_example": l1_example,
    }


def _render_motivation_with_examples() -> list[str]:
    """Short preamble that introduces the three levels with one example each."""
    lines = [
        "## The three levels of duplication",
        "",
        "1. **Level 1 — inside the transplanted bug set.**  Different OSV ids "
        "can describe the same code defect reported from different PoC inputs. "
        "The transplant workflow treats each OSV id as a separate target; the "
        "evaluation double-counts them.",
        "2. **Level 2 — fuzz crashes that *are* transplanted bugs.**  The "
        "side-effect analyzer flags a fuzz crash as *unmatched* when its "
        "stacktrace does not line up with any bug's `(crash_file, crash_line)` "
        "from `bug_metadata.json`.  Many unmatched crashes nevertheless share "
        "the top frames with a transplanted bug's reference crash — they are "
        "the same bug reported at a different (inlined / macro-expanded) "
        "line.",
        "3. **Level 3 — inside the unmatched fuzz crash set.**  Hundreds of "
        "distinct FuzzBench `crash_key`s collapse onto a much smaller number "
        "of underlying bugs once top-3 stack frames are used as the "
        "fingerprint.",
        "",
    ]
    return lines


def _render_stack_examples() -> list[str]:
    """Concrete stack-trace examples for each of the three levels."""
    lines: list[str] = []
    lines.append("## Concrete stack-trace examples")
    lines.append("")
    lines.append(
        "The tables above summarize *counts*; this section shows raw "
        "stacktraces for one canonical case at each level so the reader can "
        "judge what 'similar' means."
    )
    lines.append("")

    # Level 1 — ghostscript OSV-2022-121 vs OSV-2022-54: same stack, different trigger scope
    lines.append("### Level 1 example — same function chain, disjoint trigger windows")
    lines.append("")
    lines.append(
        "Two ghostscript OSV ids whose crash stacks are "
        "function-chain-identical but whose *commit ranges do not overlap* "
        "— OSV-2022-121 triggers on rows 35–44 and OSV-2022-54 picks up "
        "exactly where the first stops, at rows 45–50.  Sequential "
        "regressions on the same line, not one bug reported twice."
    )
    lines.append("")
    lines.append(
        "Source crash reports: "
        "`data/crash/target_crash-a16d4303-testcase-OSV-2022-121.txt` and "
        "`data/crash/target_crash-f4f1797a-testcase-OSV-2022-54.txt` — the "
        "captured reference crashes used during transplant verification. "
        "The two crashes share the same **function call chain** end to end, "
        "but many line numbers differ because each was captured at a "
        "different commit (`a16d4303` vs `f4f1797a`) and unrelated code "
        "churn between those commits shifted line positions throughout "
        "`pdf_fontps.c`, `pdf_font.c`, `pdf_int.c`, `pdf_page.c`, "
        "`zpdfops.c`, `imainarg.c`, etc."
    )
    lines.append("")
    lines.append(
        "Frames 0–4 (`s_hex_process`, `s_exD_process`, `sreadbuf`, "
        "`s_process_read_buf`, `spgetcc`) match exactly.  Most frames 5–24 "
        "agree on function and file but not on line (e.g. "
        "`ps_font_eexec_func` 988↔984, `pdfi_read_ps_font` 1253↔1249, "
        "`pdfi_load_font` 738↔733, `pdfi_Tf` 1324↔1316, "
        "`pdfi_interpret_content_stream` 2076↔2057, `zPDFdrawpage` "
        "930↔919).  Side-by-side:"
    )
    lines.append("")
    lines.append("**OSV-2022-121** captured at commit `a16d4303`")
    lines.append("```")
    lines.append("==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7eecef254830")
    lines.append("READ of size 1 at 0x7eecef254830 thread T0")
    lines.append("    #0 s_hex_process                       base/sstring.c:416")
    lines.append("    #1 s_exD_process                       base/seexec.c:168")
    lines.append("    #2 sreadbuf                            base/stream.c:842")
    lines.append("    #3 s_process_read_buf                  base/stream.c:768")
    lines.append("    #4 spgetcc                             base/stream.c:481")
    lines.append("    #5 ps_font_eexec_func                  pdf/pdf_fontps.c:988")
    lines.append("    #6 pdfi_pscript_interpret              pdf/pdf_fontps.c:362")
    lines.append("    #7 pdfi_read_ps_font                   pdf/pdf_fontps.c:1253")
    lines.append("    #8 pdfi_read_type1_font                pdf/pdf_font1.c:529")
    lines.append("    #9 pdfi_load_font                      pdf/pdf_font.c:738")
    lines.append("   #10 pdfi_load_dict_font                 pdf/pdf_font.c:840")
    lines.append("   #11 pdfi_load_resource_font             pdf/pdf_font.c:878")
    lines.append("   #12 pdfi_Tf                             pdf/pdf_font.c:1324")
    lines.append("   #13 pdfi_interpret_stream_operator      pdf/pdf_int.c:1654")
    lines.append("   #14 pdfi_interpret_content_stream       pdf/pdf_int.c:2076")
    lines.append("   #15 pdfi_process_page_contents          pdf/pdf_page.c:127")
    lines.append("   #16 pdfi_process_one_page               pdf/pdf_page.c:152")
    lines.append("   #17 pdfi_page_render                    pdf/pdf_page.c:834")
    lines.append("   #18 zPDFdrawpage                        psi/zpdfops.c:930")
    lines.append("   #19 interp                              psi/interp.c:1725")
    lines.append("   ... (gs_call_interp, gs_interpret, ... shared)")
    lines.append("   #24 run_string                          psi/imainarg.c:1169")
    lines.append("```")
    lines.append("")
    lines.append("**OSV-2022-54** captured at commit `f4f1797a`")
    lines.append("```")
    lines.append("==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7e18b02a4830")
    lines.append("READ of size 1 at 0x7e18b02a4830 thread T0")
    lines.append("    #0 s_hex_process                       base/sstring.c:416   # same")
    lines.append("    #1 s_exD_process                       base/seexec.c:168    # same")
    lines.append("    #2 sreadbuf                            base/stream.c:842    # same")
    lines.append("    #3 s_process_read_buf                  base/stream.c:768    # same")
    lines.append("    #4 spgetcc                             base/stream.c:481    # same")
    lines.append("    #5 ps_font_eexec_func                  pdf/pdf_fontps.c:984    # −4")
    lines.append("    #6 pdfi_pscript_interpret              pdf/pdf_fontps.c:362    # same")
    lines.append("    #7 pdfi_read_ps_font                   pdf/pdf_fontps.c:1249   # −4")
    lines.append("    #8 pdfi_read_type1_font                pdf/pdf_font1.c:529     # same")
    lines.append("    #9 pdfi_load_font                      pdf/pdf_font.c:733      # −5")
    lines.append("   #10 pdfi_load_dict_font                 pdf/pdf_font.c:830      # −10")
    lines.append("   #11 pdfi_load_resource_font             pdf/pdf_font.c:870      # −8")
    lines.append("   #12 pdfi_Tf                             pdf/pdf_font.c:1316     # −8")
    lines.append("   #13 pdfi_interpret_stream_operator      pdf/pdf_int.c:1652      # −2")
    lines.append("   #14 pdfi_interpret_content_stream       pdf/pdf_int.c:2057      # −19")
    lines.append("   #15 pdfi_process_page_contents          pdf/pdf_page.c:126      # −1")
    lines.append("   #16 pdfi_process_one_page               pdf/pdf_page.c:151      # −1")
    lines.append("   #17 pdfi_page_render                    pdf/pdf_page.c:833      # −1")
    lines.append("   #18 zPDFdrawpage                        psi/zpdfops.c:919       # −11")
    lines.append("   #19 interp                              psi/interp.c:1725       # same")
    lines.append("   ... (gs_call_interp, gs_interpret, ... shared)")
    lines.append("   #24 run_string                          psi/imainarg.c:1166     # −3")
    lines.append("```")
    lines.append("")
    lines.append(
        "So the resemblance between the two crashes is specifically at the "
        "*(function, file)* level, not the *(function, file, line)* level.  "
        "Strict `(file, line, function)` dedup (the L1.a key used throughout "
        "this report) would **not** collapse these two — they land in "
        "separate groups because most lines don't match.  Only a looser "
        "top-N *function-chain* fingerprint catches them."
    )
    lines.append("")
    lines.append(
        "#### Trigger scope — from `gstoraster_fuzzer.csv`"
    )
    lines.append("")
    lines.append(
        "Each row of `gstoraster_fuzzer.csv` is one ghostscript commit "
        "(sampled monotonically along the project's git history).  Each "
        "cell is `fraction|count`, where `count` is the number of PoCs that "
        "reproduced the bug at that commit.  Cells `0|0` and `time out` are "
        "non-triggers; `0.5|0` is a flaky / inconclusive signal (partial "
        "match without a confirmed crash) and is excluded from the strict "
        "counts below.  A *strict trigger* means `count > 0` — at least "
        "one PoC confirmed the bug at that commit."
    )
    lines.append("")
    lines.append(
        "| bug | strict triggers | first file line | last file line | commit range |"
    )
    lines.append("| --- | ---: | ---: | ---: | --- |")
    lines.append(
        "| OSV-2022-121 | 10 / 255 | 35 | 44 | `a16d4303…` → `47b3cf18…` |"
    )
    lines.append(
        "| OSV-2022-54  | 6 / 255  | 45 | 50 | `f4f1797a…` → `0d5d7852…` |"
    )
    lines.append("")
    lines.append(
        "**The two windows are adjacent and non-overlapping.**  OSV-2022-121 "
        "triggers on a contiguous run from row 35 through row 44; "
        "OSV-2022-54 picks up at row 45 and runs through row 50.  There is "
        "**no commit that triggers both bugs** (strictly) — row 44 was the "
        "last build where OSV-2022-121 fired, and OSV-2022-54 does not "
        "appear until the very next sampled commit."
    )
    lines.append("")
    lines.append(
        "This pattern strongly suggests the two OSV entries describe "
        "**successive regressions of the same code path**, not a single "
        "defect reported twice.  A plausible reading of the data: the fix "
        "between rows 44 and 45 closed the original bug (OSV-2022-121), but "
        "the replacement code on the same path had its own overflow "
        "(OSV-2022-54), which was then fixed at row 51 before a follow-up "
        "commit re-broke the area (the `0.5|0` flaky region starting around "
        "row 242 may be that).  Same stack, same function chain — *different "
        "defects on the same line*."
    )
    lines.append("")
    lines.append(
        "The reference crashes were captured at exactly the commit where "
        "each bug first triggered (`a16d4303` for OSV-2022-121, `f4f1797a` "
        "for OSV-2022-54) — which is why the PoC filename encodes that "
        "commit hash."
    )
    lines.append("")
    lines.append(
        "**Implication for dedup.**  Three different dedup keys give three "
        "different answers on this pair:"
    )
    lines.append("")
    lines.append(
        "1. **`(file, line, function)` (L1.a):** NOT collapsed — most "
        "lines differ, so strict key-matching keeps them apart.  The `% "
        "duplication` column in the Level 1 table above uses this key and "
        "does not double-count these two.\n"
        "2. **Top-N function-chain fingerprint (L1.b, looser):** would "
        "collapse them — every stack frame agrees on `(function, file)`.\n"
        "3. **Trigger-commit range (orthogonal signal from "
        "`gstoraster_fuzzer.csv`):** **disjoint** windows (rows 35–44 vs "
        "45–50).  No commit strictly triggers both, and they fire on "
        "adjacent contiguous runs.  This is the clearest possible signal "
        "that they are separate defects despite identical function chains: "
        "the commit that closed OSV-2022-121 is the same commit that "
        "exposed OSV-2022-54 on the same path."
    )
    lines.append("")
    lines.append(
        "These pairs exist because OSV often files two entries against the "
        "same code path (same harness, same crashing function) when a fix "
        "introduces a subtly different overflow on the same line.  The "
        "stacks are indistinguishable; only the commit-range reveals they "
        "are sequential regressions.  A sound evaluation reports both a "
        "raw OSV count and a function-chain-collapsed count, and marks "
        "same-function-chain pairs whose trigger windows are disjoint (or "
        "nearly so) as **separate regressions** rather than collapsing "
        "them into one bug."
    )
    lines.append("")

    # Level 2 — c-blosc2 OSV-2021-221 reference vs top unmatched
    lines.append("### Level 2 example — c-blosc2 `blosc_d` crash")
    lines.append("")
    lines.append(
        "`benchmarks/c-blosc2_transplant_decompress_frame_fuzzer/crashes/"
        "OSV-2021-221.txt` is the reference crash recorded when the "
        "transplanted bug OSV-2021-221 was verified.  The c-blosc2 24h "
        "FuzzBench run produced **~7,100 occurrences** of crashes with the "
        "exact same top-8 frame chain — but those occurrences were labeled "
        "*unmatched* because ASAN reported the top frame at "
        "`blosc/blosc-private.h:90` (macro expansion site) while "
        "`bug_metadata.json` has `crash_line: 1484` (the call site).  "
        "Same bug, different reported line."
    )
    lines.append("")
    lines.append("**OSV-2021-221 reference crash (from benchmarks/crashes/)**")
    lines.append("```")
    lines.append("==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7c75b3fe03d4")
    lines.append("READ of size 4 at 0x7c75b3fe03d4 thread T0")
    lines.append("    #0 blosc_d                           blosc/blosc2.c:1484")
    lines.append("    #1 _blosc_getitem                    blosc/blosc2.c:2763")
    lines.append("    #2 blosc2_getitem_ctx                blosc/blosc2.c:2833")
    lines.append("    #3 blosc2_getitem                    blosc/blosc2.c:2792")
    lines.append("    #4 get_coffset                       blosc/frame.c")
    lines.append("    #5 frame_get_lazychunk               blosc/frame.c:1972")
    lines.append("    #6 frame_decompress_chunk            blosc/frame.c:2821")
    lines.append("    #7 blosc2_schunk_decompress_chunk    blosc/schunk.c:804")
    lines.append("    #8 LLVMFuzzerTestOneInput            tests/fuzz/fuzz_decompress_frame.c:45")
    lines.append("```")
    lines.append("")
    lines.append("**Top unmatched FuzzBench crash (libafl, trial 51, t=0s)**")
    lines.append("```")
    lines.append("==ERROR: AddressSanitizer: SEGV on unknown address 0x60f0202022b9")
    lines.append("The signal is caused by a READ memory access.")
    lines.append("    #0 blosc_d                           blosc/blosc-private.h:90   # ← macro expansion")
    lines.append("    #1 _blosc_getitem                    blosc/blosc2.c:2763")
    lines.append("    #2 blosc2_getitem_ctx                blosc/blosc2.c:2833")
    lines.append("    #3 blosc_getitem                     blosc/blosc2.c:2792")
    lines.append("    #4 get_coffset                       blosc/frame.c:1770")
    lines.append("    #5 frame_get_lazychunk               blosc/frame.c:1972")
    lines.append("    #6 frame_decompress_chunk            blosc/frame.c:2821")
    lines.append("    #7 blosc2_schunk_decompress_chunk    blosc/schunk.c:804")
    lines.append("    #8 LLVMFuzzerTestOneInput            tests/fuzz/fuzz_decompress_frame.c:47")
    lines.append("```")
    lines.append("")
    lines.append(
        "The frame function chain (`blosc_d → _blosc_getitem → "
        "blosc2_getitem_ctx → ...`) is identical; the crash type also "
        "matches (both are out-of-bounds READs inside block decompression).  "
        "The top-3-frame fingerprint groups them.  This is a single c-blosc2 "
        "cluster — one of the 27 L2 matches the summary table above reports "
        "for c-blosc2 — worth **~1,400 of the 4,237 re-classified crashes**."
    )
    lines.append("")

    # Level 3 — c-blosc2 top unmatched cluster
    lines.append("### Level 3 example — 12 `crash_key`s, one underlying bug")
    lines.append("")
    lines.append(
        "`c-blosc2/.../sideeffect/unmatched_crashes_by_key.csv` contains "
        "**12 distinct FuzzBench `crash_key`s** whose top-3 frames are "
        "`blosc_d → _blosc_getitem → blosc2_getitem_ctx`, totaling **4,316 "
        "crash occurrences** across all 6 fuzzers.  FuzzBench produced "
        "different keys for each because the sanitizer varied the reported "
        "crash_type and address:"
    )
    lines.append("")
    lines.append(
        "| crash_type variant | approximate occurrences | why it's 'different' to FuzzBench |"
    )
    lines.append("| --- | ---: | --- |")
    lines.append("| `UNKNOWN READ` (SEGV) | ~3,800 | page fault on unmapped memory |")
    lines.append("| `Heap-buffer-overflow READ` | ~400 | page fault on mapped-but-poisoned memory |")
    lines.append("| `Null-dereference READ` | ~50 | specific address happened to be 0x0 |")
    lines.append("| `Integer-overflow` | ~70 | UBSAN caught the arithmetic first |")
    lines.append("")
    lines.append(
        "All four variants are the same out-of-bounds read in `blosc_d` — "
        "only the sanitizer *symptom* differs depending on how the fuzz input "
        "misaligned the block header.  `duplication_report.py` collapses "
        "them into a single fingerprint cluster."
    )
    lines.append("")
    return lines


def render(summaries: dict[str, dict], include_examples: bool = False) -> str:
    lines: list[str] = []
    lines.append("# Cross-project bug-and-crash duplication summary")
    lines.append("")
    lines.append(
        "Aggregates the per-project reports produced by "
        "`script/sideeffect/duplication_report.py`. Each project's report "
        "lives at `<project>/.../duplication_analysis.md` — this file "
        "distills the headline numbers and compares them."
    )
    lines.append("")
    if include_examples:
        lines.extend(_render_motivation_with_examples())

    # ---- Level 1 ---------------------------------------------------------
    lines.append("## Level 1 — duplication inside each transplanted bug set")
    lines.append("")
    lines.append(
        "| benchmark | raw OSV ids | top-3 `(func, file)` | top-3 `(func, file, line)` | biggest same-chain group |"
    )
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for name, s in summaries.items():
        if s is None:
            lines.append(f"| {name} | — | — | — | *(no report)* |")
            continue
        ex = s.get("l1_example")
        if ex and ex["count"] > 1:
            ex_str = f"`{ex['chain']}` — {ex['count']} OSV ids"
        else:
            ex_str = "*(no same-chain group)*"
        lines.append(
            f"| {name} | {s['bugs_raw']} | {s['bugs_ff']} | "
            f"{s['bugs_ffl']} | {ex_str} |"
        )
    lines.append("")
    lines.append(
        "Columns progress from the least deduplicated (raw OSV count) to the "
        "strictest key (top-3 `(function, file, line)`).  The loose key "
        "`(function, file)` collapses bugs that share a call chain even if "
        "line numbers have drifted from inlining or macro expansion."
    )
    lines.append("")

    # ---- Crashes (merged L2 + L3) ---------------------------------------
    lines.append("## Crashes — unmatched crashes per benchmark")
    lines.append("")
    lines.append(
        "| benchmark | unique FuzzBench `crash_key`s | top-3 `(func, file)` | top-3 `(func, file, line)` | fingerprint-matches a transplanted bug |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for name, s in summaries.items():
        if s is None:
            continue
        if s.get("crashes_raw") is None:
            lines.append(f"| {name} | — | — | — | — |")
            continue
        lines.append(
            f"| {name} | {s['crashes_raw']} | {s['crashes_ff']} | "
            f"{s['crashes_ffl']} | {s['crashes_matching_transplant']} |"
        )
    lines.append("")
    lines.append(
        "Raw count uses FuzzBench's native `crash_key` (type + top-3 "
        "function names) as the identifier.  Same progression as Level 1: "
        "the two dedup columns apply the same top-3 keys used for bugs; "
        "the last column is the subset of `(func, file)` clusters whose "
        "fingerprint equals a transplanted bug's reference crash — i.e. "
        "unmatched signatures that *should* have matched."
    )
    lines.append("")

    # ---- Takeaways ------------------------------------------------------
    lines.append("## Takeaways across projects")
    lines.append("")
    bench_with_l1 = [s for s in summaries.values() if s]
    total_raw = sum(s["bugs_raw"] for s in bench_with_l1)
    total_ff = sum(s["bugs_ff"] for s in bench_with_l1)
    total_ffl = sum(s["bugs_ffl"] for s in bench_with_l1)
    lines.append(
        f"* Across {len(bench_with_l1)} benchmarks, the nominal transplanted-"
        f"bug count is **{total_raw}** (raw OSV) → **{total_ffl}** under the "
        f"strict `(func, file, line)` key → **{total_ff}** under the loose "
        f"`(func, file)` key.  Roughly "
        f"{(total_raw - total_ff) / total_raw:.0%} of raw OSV ids are "
        f"duplicates at the loose-key level."
    )
    with_fuzz = [s for s in summaries.values() if s and s.get("crashes_raw") is not None]
    if with_fuzz:
        total_c_raw = sum(s["crashes_raw"] for s in with_fuzz)
        total_c_ff = sum(s["crashes_ff"] for s in with_fuzz)
        total_c_ffl = sum(s["crashes_ffl"] for s in with_fuzz)
        total_matched = sum(s["crashes_matching_transplant"] for s in with_fuzz)
        total_occ = sum(s["crash_occurrences_total"] or 0 for s in with_fuzz)
        lines.append(
            f"* Across {len(with_fuzz)} benchmarks with fuzz experiments, "
            f"**{total_c_raw}** unique FuzzBench `crash_key`s (≈ "
            f"{total_occ:,} crash occurrences) collapse to "
            f"**{total_c_ff}** loose clusters / **{total_c_ffl}** strict "
            f"clusters.  **{total_matched}** of the `(func, file)` clusters "
            f"match a transplanted bug's reference fingerprint — those are "
            f"the 'unmatched' crashes that were really transplant hits "
            f"misclassified by strict `(crash_file, crash_line)` matching."
        )
    lines.append("")
    lines.append(
        "**Reporting guidance:** publish all three numbers side-by-side.  "
        "Magma-style canary instrumentation is the only way to avoid the "
        "choice entirely (see `magma.md`); absent that, the three keys "
        "describe the uncertainty range honestly — a strict key is "
        "conservative (may under-collapse real duplicates), a loose key is "
        "aggressive (may merge distinct regressions on the same path, as in "
        "the ghostscript OSV-2022-121 / OSV-2022-54 example)."
    )
    lines.append("")

    if include_examples:
        lines.extend(_render_stack_examples())

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", required=True,
                        help="name=<path_to_report>.md, may repeat")
    parser.add_argument("--with-examples", action="store_true",
                        help="Include a 'Concrete stack-trace examples' "
                             "section that shows one canonical case for each "
                             "of the three duplication levels.")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    summaries: dict[str, dict] = {}
    for entry in args.report:
        if "=" not in entry:
            raise SystemExit(f"--report expects name=<path>, got {entry}")
        name, path = entry.split("=", 1)
        summaries[name] = parse_report(Path(path))

    args.output.write_text(render(summaries, include_examples=args.with_examples))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
