# sideeffect/ — Empirical side-effect analysis for bug-transplant benchmarks

Quantifies how much the dispatch mechanism perturbs the fuzzing task itself,
beyond the intended bug injection. Operates directly on a FuzzBench experiment
directory (its `local.db` + coverage/crash archives) plus the
`bug_metadata.json` emitted by `fuzzbench_generate.py`. Per-(fuzzer, trial,
bug) survival data is derived inline by importing `scan_crash_dirs` and
`scan_coverage_for_bugs` from `fuzzbench_triage` — no pre-built triage CSV is
consumed.

## Motivation

The bug-transplant pipeline prepends N dispatch bytes to every fuzz input. This
is an entirely new input dimension the original program did not have. If that
dimension changes difficulty beyond the intended bug injection, the benchmark
is measuring "fuzzer X against an artificially perturbed Y" rather than
"fuzzer X against Y".

Paper §3.1 identifies three concrete side-effect questions:

1. Do crashing inputs concentrate on sparse dispatch-bit patterns, or spread
   across the space the dispatch byte creates?
2. Is there an asymmetry in time-to-trigger between dispatch-gated bugs
   (`dispatch_value > 0`) and always-active bugs (`dispatch_value == 0`)?
3. Does the pessimistic model (setting other gated bits perturbs an
   always-active bug's crash path) hold empirically?

Question (1) needs raw crashing-input bytes. FuzzBench prunes crash archives at
experiment close, so on already-run experiments the bytes may be gone. When
available, `analyze.py` pulls them from `experiment-folders`. When not, we fall
back to **bit inference from crash stacktraces**: a crash that hit a gated
bug's code implies that bug's bit was set, so the set of matched gated bugs
gives a lower bound on the bits active at crash time.

Questions (2) and (3) are answered from the per-(fuzzer, trial, bug) reach and
trigger timings we compute inline via `fuzzbench_triage.scan_crash_dirs` and
`fuzzbench_triage.scan_coverage_for_bugs`.

## Data this folder consumes

- `--experiment-dir` — FuzzBench experiment dir containing `local.db` and
  `experiment-folders/`. The authoritative source for trials, crashes,
  snapshots, and coverage JSONs.
- `--bug-metadata` — `bug_metadata.json` produced by
  `script/fuzzbench_generate.py`. Provides `dispatch_value` per bug (0 ⇒
  always-active, ≠0 ⇒ gated) and crash locations. Source of truth for stratum
  membership.
- `--benchmark` *(optional)* — benchmark filter in `local.db`; auto-detected
  when a single benchmark is present.

If `experiment-folders/*/trial-*/coverage/*.json.gz` archives are missing or
empty, reach columns are left unobserved and the report flags the missing
paths. No fallback inputs are consumed.

## Outputs

Written under `--output-dir`.

- `stratum_summary.csv` — one row per (fuzzer, stratum). Fraction of
  trial×bug pairs triggered / reached by 24h, reach-only share, KM median
  trigger/reach time. Top-level §3.1 answer.
- `per_bug_stratum.csv` — one row per bug: stratum, triggered-trial count
  across all 60 trials, reach-only share, KM median trigger time.
- `reached_vs_triggered.csv` — per (fuzzer, stratum, bug) reach/trigger counts.
- `bit_inference.csv` — per crash: bits implied by matched bugs, timestamp,
  fuzzer, trial.
- `bit_frequency_by_fuzzer.csv` — per fuzzer × dispatch bit: crash count, total
  gated crashes, lower-bound bit-set frequency.
- `crash_bytes.csv` *(if archives non-empty)* — per crash: first N dispatch
  bytes as hex, matched bug, gated flag.
- `side_effect_summary.md` — human-readable rollup.

## Re-run

```
python3 script/sideeffect/analyze.py \
  --experiment-dir <fuzzbench-data>/<experiment-name>/ \
  --bug-metadata <benchmark-dir>/bug_metadata.json \
  --output-dir <output-dir>
```

The experiment dir must contain `local.db` and `experiment-folders/`. Raw
crash dispatch-byte extraction runs automatically when
`experiment-folders/*/trial-*/crashes/*.tar.gz` archives are intact.

## Relationship to existing scripts

- `fuzzbench_triage.py` produces the per-trial bug discovery timeline and the
  stacktrace-matching logic we rely on. We import
  `_match_bug_ids_in_stacktrace`, `_bug_targets_from_metadata`, and
  `load_bug_metadata` rather than reimplementing them.
- `fuzzbench_triage_report.py` emits `triage_results_survival_long.csv`. This
  folder is strictly downstream — it never re-derives survival events.

## What this folder does NOT do

- Does not measure coverage beyond the triage's existing crash-line reach flag.
- Does not quantify per-bit interaction effects — the pessimistic model claims
  each bit perturbs every other bug, and isolating that needs a counterfactual
  (same fuzzer, same seed, different dispatch byte forced). Out of scope here.
- Does not claim the gated-vs-always-active gap is purely from dispatch
  overhead — code-path complexity is a confound. The report flags bugs with
  similar reach times but different trigger times as the cleanest signal.
