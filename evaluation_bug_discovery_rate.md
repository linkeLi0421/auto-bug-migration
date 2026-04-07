# Evaluation Plan: Bug Discovery Rate

## Modeled after Magma (Hazimeh et al., SIGMETRICS 2021)

This plan adapts Magma's ground-truth fuzzing benchmark evaluation methodology to our bug transplant system. Like Magma, we have ground-truth knowledge of every planted bug — but unlike Magma (which manually forward-ports bugs and inserts canary oracles), our bugs are automatically transplanted and gated via the dispatch mechanism. This gives us a natural ground-truth signal: each bug has a known dispatch bit, a known testcase, and a known expected crash signature.

---

## 1. What We Measure: Three-Level Bug-Centric Metrics

Following Magma, we distinguish three levels of bug discovery. This is more informative than raw crash counts (which suffer from deduplication problems) or coverage (which correlates weakly with bug-finding).

### 1.1 Bug Reached

A bug is **reached** when the fuzzer generates an input whose dispatch byte activates the bug's bit AND execution enters the function(s) on the bug's crash path.

**How to measure:** Instrument each bug's entry-point function(s) with a lightweight canary (a global flag write, identical to Magma's `magma_log` pattern). The canary fires when the function is called with the correct dispatch bit active. This is a pure path-exploration metric — the fuzzer found the right dispatch value and navigated to the right code region, but may not have satisfied the data-flow constraints to actually trigger the fault.

### 1.2 Bug Triggered

A bug is **triggered** when the fuzzer generates an input that causes the actual fault condition — e.g., the heap-buffer-overflow, use-after-free, or divide-by-zero occurs. The trigger condition is the boolean predicate that the original vulnerability requires.

**How to measure:** Insert a trigger canary at the exact fault site (before the sanitizer would fire). The trigger condition is derived from the original bug's root cause. For example, for a heap-buffer-overflow, the canary checks whether the access index exceeds the buffer size. This is logged to shared memory (via Magma's mmap-based reporting) so it doesn't interfere with the fuzzer's feedback loop.

---

## 2. Instrumentation Design

### 2.1 Canary Implementation

We adopt Magma's always-evaluate canary pattern to avoid leaking branch information to coverage-guided fuzzers:

```c
// In shared memory (mmap'd, polled by monitor)
struct bug_canary {
    uint64_t reached;    // incremented when function entered with correct dispatch
    uint64_t triggered;  // incremented when fault condition satisfied
    uint64_t timestamp_first_reached;
    uint64_t timestamp_first_triggered;
};

void bug_canary_log(int bug_id, bool trigger_condition) {
    extern struct bug_canary *canaries;  // = mmap(...)
    extern bool faulty;                  // = false initially (weird-state guard)
    
    canaries[bug_id].reached   += 1 & (faulty ^ 1);
    canaries[bug_id].triggered += trigger_condition & (faulty ^ 1);
    faulty = faulty | trigger_condition;
    
    // Record first-reach/trigger timestamps
    if (canaries[bug_id].timestamp_first_reached == 0)
        canaries[bug_id].timestamp_first_reached = time_monotonic_ms();
    if (trigger_condition && canaries[bug_id].timestamp_first_triggered == 0)
        canaries[bug_id].timestamp_first_triggered = time_monotonic_ms();
}
```

Key properties (from Magma):
- **No implicit branches** — uses bitwise ops, not `if` statements, so coverage-guided fuzzers cannot detect the canary.
- **Weird-state guard** — after the first triggered bug, subsequent canaries are suppressed (program is in undefined state).
- **Always-evaluate** — both `reached` and `triggered` are written on every call, preventing the compiler from optimizing away the instrumentation.

### 2.2 Canary Placement

For each transplanted bug, we insert the canary at two locations:

1. **Reached canary:** At the entry of the function where the bug manifests (identified from the original crash stack trace). Called with `trigger_condition = false`.
2. **Trigger canary:** Immediately before the faulty line of code. Called with the bug's specific trigger condition (derived from the original vulnerability).

Since our bugs are dispatch-gated, the canary is placed inside the `if (__bug_dispatch[B] & (1 << N))` block so it only fires when the bug's code path is active.

### 2.3 Runtime Monitor

A separate monitor process (following Magma's design) polls the shared-memory canary region every 5 seconds and logs timestamped snapshots to a CSV file:

```
timestamp_ms, bug_id, reached_count, triggered_count
```

This provides continuous time-series data without interfering with the fuzzer.

---

## 3. Experimental Setup

### 3.1 Target Selection

Select 5–8 OSS-Fuzz C/C++ projects from different domains that have a sufficient number of transplantable bugs (target: 10+ bugs per project). Example selection criteria:

| Project | Domain | Expected bugs | Input type |
|---------|--------|---------------|------------|
| c-blosc2 | Compression | 15–20 | Binary blobs |
| libpng | Image parsing | 10–15 | PNG files |
| libtiff | Image parsing | 10–15 | TIFF files |
| libxml2 | Document parsing | 15–20 | XML |
| zstd | Compression | 8–12 | Binary blobs |
| openssl | Crypto/network | 15–20 | Binary blobs |
| sqlite3 | Database | 10–15 | SQL queries |
| php | Language runtime | 10–15 | Various |

Total target: 80–130 planted bugs across all projects (comparable to Magma's 118 bugs across 7 targets).

### 3.2 Fuzzers Under Evaluation

Select 4–6 fuzzers representing different strategies (following Magma's choice of diverse mutation-based fuzzers):

| Fuzzer | Strategy | Why include |
|--------|----------|-------------|
| **libFuzzer** | Coverage-guided, in-process | Baseline; used by OSS-Fuzz natively |
| **AFL++** | Coverage-guided, fork-server | State-of-the-art greybox fuzzer |
| **honggfuzz** | Coverage + comparison instrumentation | Strong on magic-value bugs (Magma showed this) |
| **AFL++ + CmpLog** | AFL++ with comparison logging | Tests value-aware mutation |
| **AFL++ + MOPT** | AFL++ with optimized mutation scheduling | Tests schedule optimization |
| (Optional) **SymCC-AFL** | Hybrid concolic + greybox | Tests constraint-solving for deep bugs |

### 3.3 Campaign Parameters

Following Magma's methodology and Klees et al.'s best practices:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| **Trial duration** | 24 hours | Standard; matches Magma's primary campaigns |
| **Repeated trials** | 10 per (fuzzer, target) pair | Statistical soundness; matches Magma |
| **Extended campaigns** | 7 days, 5 trials | For hard-to-find bugs (Magma showed 11 additional bugs found after 24h) |
| **Seed corpus** | OSS-Fuzz project seeds (identical across fuzzers) | Fairness; no fuzzer gets a head start |
| **Sanitizer** | AddressSanitizer (ASAN) | Primary; matches OSS-Fuzz default |
| **Memory limit** | 2048 MB | Standard OSS-Fuzz setting |
| **Timeout per exec** | 25 seconds | Standard OSS-Fuzz setting |
| **Dispatch byte** | First byte of input, consumed by harness | Transparent to fuzzer; fuzzer can mutate it freely |

**Seed corpus note:** Every seed must have a dispatch byte prepended (value `0x00`). The fuzzer starts by exercising the default (unpatched) code path and must discover non-zero dispatch values through mutation to reach transplanted bugs. This tests the fuzzer's ability to explore the dispatch space.

### 3.4 Infrastructure

- **Machines:** Identical hardware (document CPU model, RAM, kernel version)
- **Isolation:** One fuzzer instance per CPU core; no sharing; `taskset` for pinning
- **Docker:** Each trial runs in a fresh container from the same image
- **Reproducibility:** Random seeds logged; all configurations version-controlled

### 3.5 Total Compute Budget

Rough estimate:
- 24h campaigns: 6 fuzzers × {unkonw} projects × 3 trials × 24h = 4320 CPU-hours

---

## 4. Analysis Methodology

### 4.1 Time-to-Bug via Survival Analysis

Following Magma, we use the **Kaplan-Meier estimator** to model each bug's survival function — the probability that a bug remains undiscovered as a function of time.

**Why survival analysis (not just means):**
- Some bugs are never found within the time limit → **censored data**. Simply averaging over found-only trials inflates performance. Kaplan-Meier handles censored observations correctly.
- Fuzzing is highly stochastic — the same fuzzer can find a bug in 30 minutes or not at all across 10 trials.

**For each bug b, for each fuzzer F:**
1. Collect 10 time-to-trigger values from the 10 trials (some may be censored if the bug was never triggered).
2. Fit a Kaplan-Meier survival curve.
3. Plot: x-axis = time (hours), y-axis = P(bug survives) = P(not yet triggered).
4. A fuzzer that drives the survival probability to 0 faster is better at finding that bug.

**Produce survival plots for:**
- Individual interesting bugs (like Magma's Figure 5)
- Aggregated across all bugs per fuzzer (overall performance)

### 4.2 Bug Count Comparison

**Mean bugs triggered per fuzzer** (with standard deviation across 10 trials), presented as a bar chart (like Magma's Figure 3). Break down into:
- Bugs reached (path exploration)
- Bugs triggered (fault activation)
- Bugs detected (crash saved by fuzzer)

This three-level breakdown reveals *where* each fuzzer falls short.

### 4.3 Statistical Significance

Use the **Mann-Whitney U-test** (non-parametric, no distribution assumptions) to compare every pair of fuzzers on each target, following Magma exactly.

**Report:** A matrix of p-values for every (fuzzer_A, fuzzer_B, target) triple. Use p < 0.05 as the significance threshold. Present as a heatmap (like Magma's Figure 4) where red cells indicate non-significant differences and darker cells indicate higher significance.

This prevents over-interpreting small differences in mean bug counts that may be due to randomness.

### 4.4 Bug Difficulty Classification

Rank bugs by mean trigger time (across all fuzzers) to approximate "difficulty":

| Difficulty | Mean trigger time | Expected count |
|------------|------------------|----------------|
| Easy | < 1 hour | ~20–30% of bugs |
| Medium | 1–12 hours | ~30–40% |
| Hard | 12–24 hours | ~15–20% |
| Very hard | Only found in 7-day campaigns | ~5–10% |
| Unfound | Never triggered | Report count |

"Easy" bugs serve as a **regression baseline**: if a new fuzzer fails to find these, its exploration strategy has a fundamental problem.

### 4.5 Dispatch Space Exploration

**Unique to our benchmark (not in Magma):** The dispatch byte is an additional axis of exploration. Measure:

- **Time to first non-zero dispatch value:** How quickly does each fuzzer discover that byte 0 controls code-path selection?
- **Dispatch coverage:** What fraction of the assigned dispatch bits does each fuzzer activate within 24h?
- **Dispatch mutation patterns:** Does the fuzzer treat byte 0 as random data, or does it learn its structure? (Analyze the distribution of dispatch byte values in the fuzzer's queue over time.)

This analysis reveals whether coverage-guided fuzzers naturally explore the dispatch space or whether the single-byte dispatch mechanism is a bottleneck.

---

## 5. Threats to Validity and Controls

### 5.1 Dispatch Overhead

The dispatch mechanism adds one byte of input + one branch per gated code location. Measure:
- **Execution throughput:** Compare executions/second on the transplanted binary vs. the unmodified target. Report overhead percentage.
- **Code size:** Compare binary size (text section) before and after transplant.

Expected: negligible (<5% throughput impact, <10% size increase).

### 5.2 Transplant Validity

Not all transplanted bugs may be semantically equivalent to the originals. For a random sample of 30 bugs:
- Manually verify that the transplanted crash is the same root cause as the original.
- Compare crash stacks (same sanitizer class, same code area, overlapping call chain — using your existing match criteria).

### 5.3 Canary Overhead and Leakage

- **Overhead:** Measure throughput with and without canary instrumentation. Magma reports <5% overhead; we should target the same.
- **Leakage:** Run each fuzzer with and without canaries on 3 targets. Use Mann-Whitney U-test to check if bug discovery rates differ significantly. If no significant difference → canaries do not leak information.

### 5.4 Seed Bias

The dispatch byte in seeds is `0x00` (default path). This means fuzzers start with zero transplanted bugs reachable. If a fuzzer never mutates byte 0, it will find zero bugs. To control for this:
- **Baseline check:** Verify that all fuzzers mutate byte 0 within the first few minutes (log dispatch values from the fuzzer's queue).
- **Alternative:** As a sensitivity analysis, also run campaigns with seeded dispatch values (one seed per bug with the correct dispatch byte). Report both configurations.

---

## 6. Presentation of Results

### 6.1 Required Tables

| Table | Content | Magma equivalent |
|-------|---------|-----------------|
| T1 | Target summary: project, domain, # bugs, # dispatch bits, LOC | Table 2 |
| T2 | Bug list: bug ID, CWE class, sanitizer, dispatch bit, mean trigger time, which fuzzers found it | Table A2 |
| T3 | Mean bugs reached/triggered/detected per fuzzer per target (24h) | Figure 3 |
| T4 | Mean bugs reached/triggered/detected per fuzzer per target (7d) | Table A3 |
| T5 | Mann-Whitney U-test p-value matrix per target | Figure 4 |

### 6.2 Required Figures

| Figure | Content | Magma equivalent |
|--------|---------|-----------------|
| F1 | Bar chart: mean bugs triggered per fuzzer (with stddev error bars) | Figure 3 |
| F2 | Heatmap: p-value matrix for all fuzzer pairs per target | Figure 4 |
| F3 | Survival curves for 4–6 selected bugs (interesting cases: easy, hard, dispatch-dependent) | Figure 5 |
| F4 | Aggregate survival curve: P(any untriggered bug survives) vs. time, per fuzzer | Novel |
| F5 | Dispatch space exploration: fraction of dispatch bits discovered over time, per fuzzer | Novel |
| F6 | Throughput comparison: execs/sec across fuzzers on transplanted vs. unmodified binary | Novel |

### 6.3 Key Narratives to Build

1. **Does our transplant benchmark discriminate between fuzzers?** (Are there statistically significant differences in bug discovery rates?) If all fuzzers find the same bugs → benchmark is too easy or bugs are too shallow.

2. **Do fuzzers handle the dispatch space well?** If fuzzers struggle to explore byte 0 → the dispatch mechanism itself is a meaningful exploration challenge. If they explore it easily → the benchmark isolates bug-finding ability from dispatch overhead.

3. **How does our benchmark compare to Magma?** Report: comparable bug density, same statistical rigor, but our bugs are automatically transplanted (lower human cost, more scalable) while Magma's are manually forward-ported (higher quality canaries, more precise trigger conditions).

4. **What is the hardest class of bugs?** Are format-dependent bugs (that required testcase patching during transplant) harder for fuzzers to rediscover? Are bugs gated behind multi-byte magic values harder?
