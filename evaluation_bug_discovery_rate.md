# Evaluation Plan: Bug Discovery Rate

## Modeled after Magma (Hazimeh et al., SIGMETRICS 2021)

This plan adapts Magma's ground-truth fuzzing benchmark evaluation methodology to our bug transplant system. Like Magma, we have ground-truth knowledge of every planted bug. Unlike Magma (which manually forward-ports bugs and inserts canary oracles), our bugs are automatically transplanted and gated via the dispatch mechanism. We use FuzzBench's built-in coverage measurement to determine when bug-relevant code is reached, and crash-input dispatch bytes to determine when bugs are triggered.

---

## 1. What We Measure: Two-Level Bug-Centric Metrics

Following Magma, we distinguish levels of bug discovery. This is more informative than raw crash counts (which suffer from deduplication problems) or coverage (which correlates weakly with bug-finding).

### 1.1 Bug Reached

A bug is **reached** when the fuzzer generates an input that causes execution to cover the bug's crash line — the specific file:line where the sanitizer would fire.

**How we measure:** During benchmark generation, we extract the crash line (file:line) from each bug's ASAN/UBSAN crash output (the `SUMMARY:` line). At triage time, we parse FuzzBench's LLVM coverage snapshots (`coverage-archive-NNNN.json.gz`) and check if the bug's crash line was covered. The earliest coverage snapshot containing the line gives the "time first reached."

This approach works uniformly for both transplanted bugs (with dispatch gating) and local bugs (that exist on the target commit without any patch). No source-level instrumentation is required — we rely entirely on FuzzBench's existing coverage infrastructure.

### 1.2 Bug Triggered

A bug is **triggered** when the fuzzer produces an input that causes an actual crash, and that crash input's dispatch bytes match the bug's assigned bit.

**How we measure:** FuzzBench saves crashing inputs in each trial's crash directory. At triage time, we read the dispatch bytes from each crash input and map them to bug IDs via the dispatch_value in `bug_metadata.json`. Local bugs (dispatch_value=0) are considered triggered by any crash whose dispatch bytes are all zero.

### 1.3 Why Not Canary Instrumentation?

We initially considered Magma-style canary instrumentation (`bug_canary.c/h` with mmap'd shared memory) but found it impractical for our use case:

- **Transplanted bugs:** The canary can only be placed at the dispatch-gated block entry, which tells us "the dispatch bit was active" — equivalent to just reading the dispatch byte from the input, which we already do.
- **Local bugs:** We don't know the exact code path, so we can't place canaries at all.
- **Trigger detection:** The actual fault condition is detected by the sanitizer (ASAN/UBSAN), not by a manually-written predicate. Duplicating the sanitizer's logic in a canary would be error-prone and unnecessary.

The coverage-based "reached" + crash-based "triggered" approach is simpler, requires no source-level instrumentation, and works uniformly for all bug types.

---

## 2. Crash Line Collection

### 2.1 Crash Line Collection

After merging all patches (`combined.diff` + `harness.diff`), line numbers shift compared to per-bug patches. Therefore, crash lines must be collected by running each bug's PoC against the **final merged binary**, not from per-bug `transplant_crash.txt` files (which reflect pre-merge line numbers).

The `fuzzbench_generate.py` script collects crash lines by:
1. Building the merged binary inside the benchmark Docker image (with `combined.diff` + `harness.diff` applied)
2. Running each bug's PoC (with dispatch bytes prepended) against the merged binary
3. Parsing the ASAN/UBSAN `SUMMARY` line from the crash output to extract `file:line:column in function`

Example crash output:
```
SUMMARY: AddressSanitizer: SEGV /src/c-blosc2/blosc/frame.c:1306:7 in get_vlmeta_from_trailer
```

This gives `crash_file=/src/c-blosc2/blosc/frame.c`, `crash_line=1306`, `crash_function=get_vlmeta_from_trailer`.

This works uniformly for both transplanted bugs (with dispatch gating) and local bugs (that exist on the target commit without any patch). Every bug that was verified during the merge phase has a PoC that crashes the merged binary.

### 2.3 Coverage Matching

At triage time, for each coverage snapshot, we parse the LLVM coverage JSON and check if the crash line has a non-zero execution count. The LLVM coverage format uses segments:

```json
{"filename": "/src/c-blosc2/blosc/frame.c", "segments": [[1306, 7, 42, true, true, false], ...]}
```

A segment `[line, col, count, hasCount, ...]` with `count > 0` means that line was executed. We match by file path suffix and line number.

---

## 3. No PoC Seeds

Bug PoCs are **not** included as fuzzer seeds. If included, fuzzers would trigger all bugs within seconds, making the evaluation meaningless. Instead:

- Fuzzers start with the project's **original seed corpus** from OSS-Fuzz (with dispatch zero bytes prepended so the harness accepts them).
- The fuzzer must independently discover inputs that both (a) set the right dispatch bits and (b) satisfy the data-flow constraints to trigger each bug.
- The dispatch byte is the first byte of the input — the fuzzer can mutate it freely like any other byte.

---

## 4. Experimental Setup

### 4.1 Target Selection

Select OSS-Fuzz C/C++ projects with sufficient transplantable bugs (target: 10+ bugs per project).

| Project | Domain | Expected bugs | Input type |
|---------|--------|---------------|------------|
| c-blosc2 | Compression | 28 | Binary blobs |
| (additional projects TBD) | | | |

### 4.2 Fuzzers Under Evaluation

| Fuzzer | Strategy | Why include |
|--------|----------|-------------|
| **libFuzzer** | Coverage-guided, in-process | Baseline; used by OSS-Fuzz natively |
| **AFL++** | Coverage-guided, fork-server | State-of-the-art greybox fuzzer |
| **honggfuzz** | Coverage + comparison instrumentation | Strong on magic-value bugs |
| **AFL** | Classic coverage-guided | Baseline comparison |

### 4.3 Campaign Parameters

Following Magma's methodology and Klees et al.'s best practices:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Trial duration** | 24 hours | Standard; matches Magma's primary campaigns |
| **Repeated trials** | 10 per (fuzzer, target) pair | Statistical soundness; matches Magma |
| **Seed corpus** | OSS-Fuzz project seeds only (no PoCs) | Fairness; fuzzers must discover bugs independently |
| **Sanitizer** | AddressSanitizer (ASAN) | Primary; matches OSS-Fuzz default |
| **Dispatch byte** | First N bytes of input, consumed by harness | Transparent to fuzzer; fuzzer can mutate it freely |
| **Coverage snapshots** | Every 15 minutes (FuzzBench default) | For tracking when crash lines are reached |

### 4.4 Infrastructure

FuzzBench handles trial isolation, corpus archiving, coverage measurement, and report generation. Each trial runs in a fresh Docker container.

---

## 5. Triage Pipeline

### 5.1 Inputs

- `bug_metadata.json` — per-bug dispatch_value, crash_file, crash_line, crash_function
- FuzzBench experiment directory — containing per-fuzzer/trial crash dirs and coverage snapshots

### 5.2 Processing

```bash
python3 script/fuzzbench_triage.py \
  --experiment-dir /tmp/fuzzbench-data/<experiment> \
  --bug-metadata <benchmark>/bug_metadata.json \
  --output <output>/triage.csv
```

The triage script:
1. **Scans crash directories** — reads dispatch bytes from each crash input, maps to bug IDs
2. **Scans coverage snapshots** — parses LLVM coverage JSON, checks if each bug's crash line was covered
3. **Merges results** — for each (fuzzer, trial, bug) triple, records time_first_reached and time_first_triggered

### 5.3 Outputs

| File | Content |
|------|---------|
| `triage.csv` | Per-fuzzer/trial/bug timeline: fuzzer, trial, bug_id, time_first_reached, time_first_triggered |
| `triage_bug_report.json` | Detailed per-bug JSON with crash locations and which fuzzers reached/triggered |
| `triage_bug_report.txt` | Human-readable table: bug ID, crash location, reached (yes/no), triggered (yes/no) |

---

## 6. Analysis Methodology

### 6.1 Time-to-Bug via Survival Analysis

Following Magma, we use the **Kaplan-Meier estimator** to model each bug's survival function — the probability that a bug remains undiscovered as a function of time.

**Why survival analysis (not just means):**
- Some bugs are never found within the time limit -> **censored data**. Simply averaging over found-only trials inflates performance. Kaplan-Meier handles censored observations correctly.
- Fuzzing is highly stochastic — the same fuzzer can find a bug in 30 minutes or not at all across 10 trials.

**For each bug b, for each fuzzer F:**
1. Collect time-to-trigger values from all trials (some may be censored).
2. Fit a Kaplan-Meier survival curve.
3. Plot: x-axis = time (hours), y-axis = P(bug survives) = P(not yet triggered).

**Produce survival plots for:**
- Individual interesting bugs (like Magma's Figure 5)
- Aggregated across all bugs per fuzzer (overall performance)

### 6.2 Bug Count Comparison

**Mean bugs per fuzzer** (with standard deviation across trials), presented as a bar chart. Break down into:
- Bugs reached (crash line covered in coverage)
- Bugs triggered (crash with matching dispatch bytes)

This two-level breakdown reveals *where* each fuzzer falls short: path exploration vs. constraint satisfaction.

### 6.3 Statistical Significance

Use the **Mann-Whitney U-test** (non-parametric) to compare every pair of fuzzers on each target.

Report a matrix of p-values for every (fuzzer_A, fuzzer_B, target) triple. Use p < 0.05 as the significance threshold. Present as a heatmap.

### 6.4 Bug Difficulty Classification

Rank bugs by mean trigger time (across all fuzzers):

| Difficulty | Mean trigger time | Description |
|------------|------------------|-------------|
| Easy | < 1 hour | Regression baseline |
| Medium | 1-12 hours | Core evaluation |
| Hard | 12-24 hours | Deep bugs |
| Very hard | Only in extended campaigns | Edge cases |
| Unfound | Never triggered | Report count |

### 6.5 Dispatch Space Exploration

Unique to our benchmark: the dispatch byte is an additional exploration axis. Measure:
- **Time to first non-zero dispatch value:** How quickly does each fuzzer discover that byte 0 controls code-path selection?
- **Dispatch coverage:** What fraction of assigned dispatch bits does each fuzzer activate within 24h?

---

## 7. Threats to Validity and Controls

### 7.1 Dispatch Overhead

The dispatch mechanism adds N bytes of input + one branch per gated code location. Measure:
- **Execution throughput:** Compare executions/second on the transplanted binary vs. the unmodified target.
- **Code size:** Compare binary size before and after transplant.

Expected: negligible (<5% throughput impact).

### 7.2 Transplant Validity

For a random sample of bugs, manually verify that the transplanted crash has the same root cause as the original (same sanitizer class, same code area, overlapping call chain).

### 7.3 Coverage as Reached Proxy

Using crash line coverage as "reached" is a proxy — the line may be covered by normal execution without the bug-triggering data flow. This means "reached" is an over-approximation (some "reached" bugs may not actually be on the path to triggering). However:
- This is consistent across all fuzzers (fair comparison)
- The "triggered" metric (actual crash) is precise
- Over-counting "reached" is better than missing it entirely (as we would without any instrumentation)

### 7.4 Seed Bias

Seeds have dispatch bytes set to `0x00` (default path). Fuzzers must mutate byte 0 to reach transplanted bugs. Verify that all fuzzers mutate byte 0 within the first few minutes by checking dispatch byte distribution in corpus snapshots.

---

## 8. Presentation of Results

### 8.1 Required Tables

| Table | Content |
|-------|---------|
| T1 | Target summary: project, domain, # bugs, # dispatch bits |
| T2 | Bug list: bug ID, crash location, dispatch bit, reached/triggered per fuzzer |
| T3 | Mean bugs reached/triggered per fuzzer per target (24h) |
| T4 | Mann-Whitney U-test p-value matrix per target |

### 8.2 Required Figures

| Figure | Content |
|--------|---------|
| F1 | Bar chart: mean bugs reached + triggered per fuzzer (stacked, with stddev) |
| F2 | Heatmap: p-value matrix for all fuzzer pairs |
| F3 | Survival curves for selected bugs (easy, hard, dispatch-dependent) |
| F4 | Aggregate survival curve: P(any untriggered bug survives) vs. time |
| F5 | Dispatch space exploration over time per fuzzer |
| F6 | FuzzBench coverage growth (from built-in reports) |

### 8.3 Key Narratives

1. **Does our benchmark discriminate between fuzzers?** Are there statistically significant differences in bug discovery rates?
2. **Do fuzzers handle the dispatch space well?** Does the single-byte dispatch mechanism create a meaningful exploration challenge?
3. **How does our benchmark compare to Magma?** Comparable bug density and statistical rigor, but automatically transplanted (lower human cost, more scalable).
4. **What is the hardest class of bugs?** Are format-dependent bugs (that required testcase patching during transplant) harder for fuzzers to rediscover?
