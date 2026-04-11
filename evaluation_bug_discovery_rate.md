# Evaluation Plan: Bug Discovery Rate

## Modeled after Magma (Hazimeh et al., SIGMETRICS 2021)

This plan adapts Magma's ground-truth fuzzing benchmark evaluation methodology to our bug transplant system. Like Magma, we have ground-truth knowledge of every planted bug. Unlike Magma (which manually forward-ports bugs and inserts canary oracles), our bugs are automatically transplanted and gated via the dispatch mechanism. We use FuzzBench's built-in coverage measurement to determine when bug-relevant code is reached, and FuzzBench crash stack traces to determine when bugs are triggered.

---

## 1. What We Measure: Two-Level Bug-Centric Metrics

Following Magma, we distinguish levels of bug discovery. This is more informative than raw crash counts (which suffer from deduplication problems) or coverage (which correlates weakly with bug-finding).

### 1.1 Bug Reached

A bug is **reached** when the fuzzer generates an input that causes execution to cover the bug's crash line - the specific file:line where the sanitizer would fire.

**How we measure:** During benchmark generation, we extract the crash line (file:line) from each bug's ASAN/UBSAN crash output (the `SUMMARY:` line). At triage time, we parse FuzzBench's LLVM coverage snapshots (`coverage-archive-NNNN.json.gz`) and check if the bug's crash line was covered. The earliest coverage snapshot containing the line gives the "time first reached."

This approach works uniformly for both transplanted bugs (with dispatch gating) and local bugs (that exist on the target commit without any patch). No source-level instrumentation is required; we rely entirely on FuzzBench's existing coverage infrastructure.

### 1.2 Bug Triggered

A bug is **triggered** when the fuzzer produces an input that causes an actual sanitizer crash whose stack trace matches the target bug's known crash signature.

**Current implementation:** trigger attribution is based on FuzzBench's `local.db` crash table and the benchmark-local reference crash logs in `fuzzbench/benchmarks/<benchmark>/crashes/*.txt`. We no longer use `dispatch_value` alone to decide which bug was triggered. This is necessary for OpenSC because many bugs have `dispatch_value=0` and are always active; those bugs can still fire even when the input's first byte is non-zero. Therefore, dispatch bytes are useful for gating transplanted patches, but they are not sufficient for crash attribution.

For duplicated crash lines, triage uses deeper stack frames. Example: `OSV-2020-209` and `OSV-2020-885` both crash in `coolkey_apdu_io` at `card-coolkey.c:930`, but one stack contains `sc_decipher` and the other contains `sc_compute_signature`, so they are separated by stack context rather than by dispatch byte.

### 1.3 Why Not Canary Instrumentation?

We initially considered Magma-style canary instrumentation (`bug_canary.c/h` with mmap'd shared memory) but found it impractical for our use case:

- **Transplanted bugs:** The canary can only be placed at the dispatch-gated block entry, which tells us "the dispatch bit was active" - equivalent to just reading the dispatch byte from the input, which we already do.
- **Local bugs:** We don't know the exact code path, so we can't place canaries at all.
- **Trigger detection:** The actual fault condition is detected by the sanitizer (ASAN/UBSAN), not by a manually-written predicate. Duplicating the sanitizer's logic in a canary would be error-prone and unnecessary.

The coverage-based "reached" + stacktrace-based "triggered" approach is simpler, requires no source-level instrumentation, and works uniformly for all bug types.

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

## 3. Seed Corpus Policy

### 3.1 Initial Policy: No PoC Seeds

The initial policy was to exclude all bug PoCs from the fuzzer seed corpus. The rationale was that exact crashing PoCs would let fuzzers trigger all bugs immediately, making the evaluation meaningless. Under this policy, OpenSC fuzzers started from the project's original OSS-Fuzz seed corpus, with dispatch-byte variants prepended so the harness accepted the inputs.

Empirically, this was too weak for `opensc_transplant_fuzz_pkcs15_reader`. The original OpenSC seed corpus had only seven PKCS#15 reader seeds. Even after expanding each original seed with dispatch bytes `00 01 02 04 08 10 20 40`, the 24-hour campaign mostly found the same CoolKey crash family and did not adequately exercise the card/parser paths needed for the other transplanted bugs.

### 3.2 Current Policy: Non-Crashing PoC-Derived Structural Seeds

The current OpenSC benchmark uses **PoC-derived structural seed material**, but it still excludes exact crashing PoCs from the final seed corpus.

The benchmark build now:

1. Copies benchmark-local seed candidates from `fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/seeds/`.
2. Uses the 23 `testcase-*-patched` files from `data/merge_offline_opensc_6903aebf/testcases/` as source material.
3. Generates non-crashing variants from each candidate:
   - `dispatch_zero`: zero byte 0 to deactivate dispatch-gated patches while preserving the APDU/card routing structure.
   - `head_1`, `head_2`, `head_8`, `head_16`, `head_64`, `head_256`, `head_1024`: truncated structural prefixes.
   - `trim_1`: full input minus the last byte.
   - `zero_last`, `ff_last`, `zero_mid`, `ff_mid`: simple single-byte mutations.
   - `exact`: generated as a candidate only, then filtered by replay.
4. Replays every candidate once against the built target and adds only candidates that exit cleanly.

Validation for the rebuilt libFuzzer runner:

| Item | Count |
|------|-------|
| Original OSS-Fuzz seed dispatch variants | 56 |
| PoC-derived non-crashing variants | 174 |
| Total final seeds | 230 |
| Bugs represented by PoC-derived variants | 23/23 |
| Exact crashing PoCs included | 0 |
| One-shot replay failures across final seed corpus | 0/230 |

Variant breakdown in the rebuilt corpus:

| Variant | Count |
|---------|-------|
| `head_1` | 23 |
| `head_2` | 23 |
| `head_8` | 23 |
| `head_16` | 23 |
| `head_64` | 23 |
| `head_256` | 19 |
| `head_1024` | 12 |
| `trim_1` | 11 |
| `dispatch_zero` | 7 |
| `ff_mid` | 7 |
| `zero_mid` | 3 |

This changes the benchmark philosophy slightly: fuzzers no longer start from only the project's original corpus, but they still must mutate non-crashing structural inputs into crashing inputs. This is a pragmatic adjustment for OpenSC because the original seed corpus did not cover enough smart-card/parser structure to make the 23-bug benchmark useful.

---

## 4. Experimental Setup

### 4.1 Target Selection

Select OSS-Fuzz C/C++ projects with sufficient transplantable bugs (target: 10+ bugs per project).

| Project | Domain | Expected bugs | Input type |
|---------|--------|---------------|------------|
| opensc | Smart-card / PKCS#15 parsing | 23 | APDU-like binary conversations for `fuzz_pkcs15_reader` |
| c-blosc2 | Compression | 28 | Binary blobs |
| (additional projects TBD) | | | |

Current OpenSC benchmark:

- Benchmark name: `opensc_transplant_fuzz_pkcs15_reader`
- Target commit: `6903aebfddc466d966c7b865fae34572bf3ed23e`
- Target: `fuzz_pkcs15_reader`
- Bug metadata: `fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/bug_metadata.json`
- Total bugs: 23
- Dispatch bytes: 1
- Dispatch-gated bugs: 7 (`dispatch_value` = `1`, `2`, `4`, `8`, `16`, `32`, `64`)
- Always-active/default bugs: 16 (`dispatch_value` = `0`)

The large number of always-active OpenSC bugs is important: a crash can be caused by a `dispatch_value=0` bug even when byte 0 selects a non-zero dispatch-gated path. This is why trigger attribution now uses crash stack traces instead of dispatch bytes alone.

### 4.2 Fuzzers Under Evaluation

| Fuzzer | Strategy | Why include |
|--------|----------|-------------|
| **libFuzzer** | Coverage-guided, in-process | Baseline; used by OSS-Fuzz natively |
| **AFL++** | Coverage-guided, fork-server | State-of-the-art greybox fuzzer |
| **honggfuzz** | Coverage + comparison instrumentation | Strong on magic-value bugs |
| **AFL** | Classic coverage-guided | Baseline comparison |
| **Eclipser** | Greybox + concolic-style input solving | Tests whether branch-solving helps dispatch/format constraints |
| **FairFuzz** | Rare-branch focused AFL variant | Tests whether rare-branch prioritization improves bug-path exploration |

### 4.3 Campaign Parameters

Following Magma's methodology and Klees et al.'s best practices:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Trial duration** | 24 hours | Standard; matches Magma's primary campaigns |
| **Repeated trials** | 10 per (fuzzer, target) pair | Statistical soundness; matches Magma |
| **Seed corpus** | OpenSC now uses original seeds plus filtered non-crashing PoC-derived variants | Original seeds alone were too weak for OpenSC; exact crashing PoCs remain excluded |
| **Sanitizer** | AddressSanitizer (ASAN) | Primary; matches OSS-Fuzz default |
| **Dispatch byte** | First N bytes of input, consumed by harness | Transparent to fuzzer; fuzzer can mutate it freely |
| **Coverage snapshots** | Every 15 minutes (FuzzBench default) | For tracking when crash lines are reached |

### 4.4 Infrastructure

FuzzBench handles trial isolation, corpus archiving, coverage measurement, and report generation. Each trial runs in a fresh Docker container.

---

## 5. Triage Pipeline

### 5.1 Inputs

- `bug_metadata.json` - per-bug dispatch_value, crash_file, crash_line, crash_function
- FuzzBench experiment directory - containing per-fuzzer/trial crash dirs and coverage snapshots

### 5.2 Processing

```bash
python3 script/fuzzbench_triage.py \
  --experiment-dir /tmp/fuzzbench-data/<experiment> \
  --bug-metadata <benchmark>/bug_metadata.json \
  --output <output>/triage.csv
```

The triage script:
1. **Scans crash records first** - reads FuzzBench's `local.db` crash table and maps crash stack traces to bug IDs using the benchmark reference crash logs.
2. **Disambiguates duplicated crash locations** - uses deeper stack frames when several bugs share the same top frame or crash line.
3. **Scans coverage snapshots** - parses LLVM coverage JSON, checks only the bug/file/line tuples present in `bug_metadata.json`, and records the earliest snapshot where each crash line was covered.
4. **Skips unnecessary reachability work** - once a bug is already triggered in a `(fuzzer, trial)`, the coverage pass does not need to prove that same bug was reached for that same fuzzer/trial.
5. **Merges results** - for each (fuzzer, trial, bug) triple, records `time_first_reached` and `time_first_triggered`.

Important semantics:

- Reach time is snapshot-granular. For the current setup, snapshots are every 900 seconds; `0.00h` means the crash line was already covered in `coverage-archive-0000`, not that the triage failed.
- Trigger time comes from actual FuzzBench crash rows, not from coverage.
- Trigger identity is stacktrace-based, not dispatch-byte-based.

### 5.3 Outputs

| File | Content |
|------|---------|
| `triage.csv` | Per-fuzzer/trial/bug timeline: fuzzer, trial, bug_id, time_first_reached, time_first_triggered |
| `triage_bug_report.json` | Detailed per-bug JSON with crash locations and which fuzzers reached/triggered |
| `triage_bug_report.txt` | Human-readable table: bug ID, crash location, reached (yes/no), triggered (yes/no) |

Additional helper scripts currently used during OpenSC evaluation:

| Script | Purpose |
|--------|---------|
| `script/fuzzbench_triage_report.py` | Converts triage CSV/JSON output into human-readable Markdown and CSV summaries under `fuzzbench-output/human-readable/<experiment>/` |
| `script/watch_fuzzbench_crashes.py` | Polls a running FuzzBench experiment and reports trial progress, DB crash rows, top crash states, raw crash archive counts, and sample raw crash members |

---

## 6. Analysis Methodology

### 6.1 Time-to-Bug via Survival Analysis

Following Magma, we use the **Kaplan-Meier estimator** to model each bug's survival function - the probability that a bug remains undiscovered as a function of time.

**Why survival analysis (not just means):**
- Some bugs are never found within the time limit -> **censored data**. Simply averaging over found-only trials inflates performance. Kaplan-Meier handles censored observations correctly.
- Fuzzing is highly stochastic - the same fuzzer can find a bug in 30 minutes or not at all across 10 trials.

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
- Bugs triggered (sanitizer crash whose stack trace matches a benchmark reference crash log)

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

Using crash line coverage as "reached" is a proxy - the line may be covered by normal execution without the bug-triggering data flow. This means "reached" is an over-approximation (some "reached" bugs may not actually be on the path to triggering). However:
- This is consistent across all fuzzers (fair comparison)
- The "triggered" metric (actual crash) is precise
- Over-counting "reached" is better than missing it entirely (as we would without any instrumentation)

### 7.4 Seed Bias

The original seed-only plan had dispatch bytes set to `0x00` (default path), so fuzzers had to mutate byte 0 to reach dispatch-gated transplanted bugs. The current OpenSC corpus includes both original-seed dispatch variants and filtered PoC-derived structural variants. This reduces the risk that the benchmark measures only "can the fuzzer reconstruct a valid smart-card conversation from seven weak seeds?", but it introduces a different bias: fuzzers now receive structural hints derived from known PoCs.

Control:

- Exact crashing PoCs are filtered out by replay before the seed corpus is packaged.
- The final rebuilt libFuzzer corpus was replayed once end-to-end: 230 seeds, 0 immediate crashes.
- Report seed policy explicitly with every OpenSC result table, because it differs from the initial "original seeds only" plan.
- Keep old and new experiments separate by experiment name so we can compare the seed-policy effect.

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

---

## 9. OpenSC Progress Log

### 9.1 Original OpenSC 24h Campaign

Experiment:

```bash
sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
  --fuzzer aflplusplus afl honggfuzz libfuzzer eclipser fairfuzz \
  --experiment-name transplant-opensc-24h \
  --run-time 86400 \
  --output-dir ./fuzzbench-output/fuzzbench-data \
  --trials 10 \
  &> ./fuzzing_opensc.log
```

Result location:

```text
/mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h
```

What we learned:

- The experiment completed with 60 trials total: 6 fuzzers x 10 trials.
- With the original seed policy, the benchmark produced very narrow crash diversity.
- Most real crashes mapped to the CoolKey family, especially `OSV-2020-209` and `OSV-2020-885`.
- Several fuzzers appeared to "trigger everything" under the first triage logic, but that was a triage artifact caused by dispatch-byte attribution. The fixed triage showed that trigger identity must depend on crash logs and stack traces, not on `dispatch_value` alone.
- Reachability did work, but it is snapshot-granular. Many "best reach time = 0.00h" entries meant the line was already covered in `coverage-archive-0000`, not that the reach pass failed.

Main diagnosis:

- The original OpenSC seed corpus had only seven useful PKCS#15 reader seeds.
- Expanding those seven seeds with dispatch bytes produced only 56 seeds.
- This was not enough structural diversity for all smart-card/parser paths in the 23-bug benchmark.
- OpenSC also has 16 always-active/default bugs (`dispatch_value=0`), so a default-path bug can shadow a dispatch-gated bug even when byte 0 is non-zero.

### 9.2 Triage Fixes Completed

Files changed:

| File | Change |
|------|--------|
| `script/fuzzbench_triage.py` | Trigger attribution changed from dispatch-byte matching to FuzzBench `local.db` crash-stack matching. |
| `script/fuzzbench_triage.py` | Added deeper-frame disambiguation for duplicated crash lines such as `OSV-2020-209` vs `OSV-2020-885`. |
| `script/fuzzbench_triage.py` | Coverage timing now uses snapshot times from `local.db` instead of assuming file order alone. |
| `script/fuzzbench_triage.py` | Coverage scan checks only bug/file/line tuples from `bug_metadata.json` and skips bugs already triggered in the same `(fuzzer, trial)`. |
| `script/fuzzbench_triage_report.py` | Added human-readable Markdown/CSV summaries per fuzzer and per bug-fuzzer. |
| `script/watch_fuzzbench_crashes.py` | Added live experiment watcher for DB crash counts, top crash states, raw crash archive counts, and sample crash inputs. |

Validation already done:

- `python3 -m py_compile script/fuzzbench_triage.py`
- `python3 -m py_compile script/fuzzbench_triage_report.py`
- `python3 -m py_compile script/watch_fuzzbench_crashes.py`

### 9.3 Seed-Corpus Fix Completed

Files changed:

| File | Change |
|------|--------|
| `fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/Dockerfile` | Copies `seeds/` into `/src/benchmark_seeds/`. |
| `fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/build.sh` | Generates original dispatch variants and filtered non-crashing PoC-derived variants. |
| `fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/seeds/` | Contains 23 `testcase-*-patched` seed candidates copied from the merge output. |
| `script/fuzzbench_generate.py` | Future generated benchmarks now copy seed candidates and emit the same replay-filtering seed logic. |

Seed validation:

- Benchmark-local seed candidates: 23 files.
- Rebuilt `gcr.io/fuzzbench/runners/libfuzzer/opensc_transplant_fuzz_pkcs15_reader:latest`.
- Final seed zip in the rebuilt runner: `/out/fuzz_pkcs15_reader_seed_corpus.zip`.
- Final seed count: 230.
- Original dispatch variants: 56.
- PoC-derived non-crashing variants: 174.
- Bugs represented by PoC-derived variants: 23/23.
- Exact full PoCs included: 0.
- One-shot replay failures: 0/230.

Variant breakdown:

| Variant | Count |
|---------|-------|
| `head_1` | 23 |
| `head_2` | 23 |
| `head_8` | 23 |
| `head_16` | 23 |
| `head_64` | 23 |
| `head_256` | 19 |
| `head_1024` | 12 |
| `trim_1` | 11 |
| `dispatch_zero` | 7 |
| `ff_mid` | 7 |
| `zero_mid` | 3 |

### 9.4 Current Rerun: `transplant-opensc-24h-1`

Experiment command:

```bash
sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
  --fuzzer aflplusplus afl honggfuzz libfuzzer eclipser fairfuzz \
  --experiment-name transplant-opensc-24h-1 \
  --run-time 86400 \
  --output-dir ./fuzzbench-output/fuzzbench-data \
  --trials 10 \
  &> ./fuzzing_opensc.log
```

Result location:

```text
/mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1
```

Nested FuzzBench experiment directory:

```text
/mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/transplant-opensc-24h-1
```

Local DB:

```text
/mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/local.db
```

Current status as of the watcher check at 2026-04-11 05:24:47 UTC while the run is still active:

| Metric | Value |
|--------|-------|
| Experiment created | 2026-04-11 03:02:06 UTC |
| Fuzzers | `afl`, `aflplusplus`, `eclipser`, `fairfuzz`, `honggfuzz`, `libfuzzer` |
| Trials | 60 total, 10 per fuzzer |
| Runner containers | 60 up |
| Trials started | 60/60 |
| Trials ended | 0/60 |
| Latest measured snapshot | 4500 seconds |
| Snapshot rows | 360 |
| Distinct snapshot times | 6 |
| Crash DB rows | 275 |
| Raw crash archives | 254 |
| Nonempty raw crash members | 511 |
| Raw crash member prefix entries | `crash`: 681 |

Crash rows by fuzzer at the same checkpoint:

| Fuzzer | Crash rows |
|--------|------------|
| `afl` | 50 |
| `aflplusplus` | 29 |
| `eclipser` | 55 |
| `fairfuzz` | 18 |
| `honggfuzz` | 108 |
| `libfuzzer` | 15 |

Raw crash archives by fuzzer at the same checkpoint:

| Fuzzer | Raw crash archives |
|--------|--------------------|
| `afl` | 43 |
| `aflplusplus` | 38 |
| `eclipser` | 46 |
| `fairfuzz` | 22 |
| `honggfuzz` | 60 |
| `libfuzzer` | 45 |

Top raw crash states at the same checkpoint:

| Count | Sanitizer class | Crash state |
|-------|-----------------|-------------|
| 53 | `Index-out-of-bounds` | `insert_key -> detect_netkey -> sc_pkcs15emu_tcos_init_ex` |
| 51 | `Stack-buffer-overflow READ` | `sc_pkcs15emu_object_add -> sc_pkcs15emu_coolkey_init -> sc_pkcs15emu_coolkey_init_ex` |
| 49 | `Heap-buffer-overflow READ` | `parse_sec_attr_44 -> setcos_select_file -> sc_select_file` |
| 38 | `Index-out-of-bounds` | `pgp_parse_algo_attr_blob -> pgp_get_card_features -> pgp_init` |
| 18 | `Stack-buffer-overflow WRITE` | `piv_compute_signature -> sc_compute_signature -> use_key` |
| 12 | `Index-out-of-bounds` | `insert_pin -> detect_netkey -> sc_pkcs15emu_tcos_init_ex` |
| 9 | `Stack-buffer-overflow WRITE` | `fuzz_reader_transmit -> sc_single_transmit -> sc_transmit` |
| 9 | `Heap-buffer-overflow READ` | `hextoint -> get_name_from_EF_DatiPersonali -> itacns_add_data_files` |
| 8 | `Stack-buffer-overflow WRITE` | `tcos_decipher -> sc_decipher -> use_key` |
| 7 | `Heap-buffer-overflow READ` | `sc_oberthur_parse_containers -> sc_pkcs15emu_oberthur_init -> sc_pkcs15emu_oberthur_init_ex` |
| 6 | `Stack-buffer-overflow READ` | `sc_asn1_read_tag -> sc_asn1_find_tag -> piv_compute_signature` |
| 6 | `Heap-buffer-overflow READ` | `sc_oberthur_parse_privateinfo -> sc_pkcs15emu_oberthur_init -> sc_pkcs15emu_oberthur_init_ex` |
| 4 | `Stack-buffer-overflow WRITE` | `sc_get_response -> sc_transmit -> sc_transmit_apdu` |
| 3 | `Heap-double-free` | `sc_pkcs15_free_tokeninfo -> sc_pkcs15_card_free -> fuzz_pkcs15_reader.c` |
| 2 | `Heap-buffer-overflow READ` | `sc_pkcs15emu_oberthur_add_pubkey -> sc_oberthur_parse_publicinfo -> sc_pkcs15emu_oberthur_init` |

Interpretation:

- The new seed policy is already producing much broader crash diversity than the original seed-only experiment.
- Crashes now cover TCOS/NetKey, SetCOS, CoolKey, OpenPGP, PIV, Oberthur, Itacns, APDU response handling, and PKCS#15 cleanup paths.
- The current DB counts are raw crash rows, not final unique bug counts. Several states may map to multiple OSV IDs or may need stack-based disambiguation during triage.
- Early log messages such as `Corpus not found for cycle: 0` occurred during startup and measurement scheduling. The run is now producing snapshots and crash archives, so this is not currently blocking the experiment.

### 9.5 Next Steps

When the 24-hour run finishes, run triage on the nested experiment directory:

```bash
sudo -E python3 script/fuzzbench_triage.py \
  --experiment-dir fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/transplant-opensc-24h-1/ \
  --bug-metadata fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/bug_metadata.json \
  --benchmark opensc_transplant_fuzz_pkcs15_reader \
  --output /mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/triage_results.csv
```

Then generate the human-readable report:

```bash
python3 script/fuzzbench_triage_report.py \
  --input /mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/triage_results.csv \
  --bug-metadata fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/bug_metadata.json \
  --db /mydata/auto-bug-migration/fuzzbench-output/fuzzbench-data/transplant-opensc-24h-1/local.db \
  --output-dir /mydata/auto-bug-migration/fuzzbench-output/human-readable/transplant-opensc-24h-1
```

Compare these outputs against the original `transplant-opensc-24h` campaign to quantify the effect of the new seed policy:

- Unique bugs triggered.
- Unique bugs reached.
- Per-fuzzer bug counts.
- Time-to-first-trigger per bug.
- Whether the two CoolKey bugs still dominate after 24 hours.
- Which bugs remain unfound despite the structural seed variants.
