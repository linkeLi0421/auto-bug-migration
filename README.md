# OSS-Fuzz for Select

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/linkeLi0421/auto-bug-migration)

This repository contains scripts and examples used to explore automated fuzzing workflows.  It is focused on building and testing fuzzing harnesses for specific open-source projects.

## Repository structure
- `Function_instrument/` – simple instrumentation example with a `Makefile` and `trace.c`.
- `script/` – assorted Python utilities for building targets, running fuzzers and analysing bug data.
- `cfg-clang/` and `oss-fuzz/` – configuration and data directories used by the scripts.

## Requirements
- Python 3.8+
- Clang/LLVM toolchain
- git

## Usage
Most functionality lives in the `script` directory.

### buildAndtest.py
Build and test fuzzing targets across commit ranges:
```bash
python script/buildAndtest.py --help
```

### fuzz_helper.py get_dict
Retrieve the fuzzer dictionary for a project. This must be run before `get_poc_for_new_version`.

```bash
sudo python3 script/fuzz_helper.py get_dict <project> \
  --commit <base_commit> \
  --build_csv <builds_csv>
```

**Example:**
```bash
sudo python3 script/fuzz_helper.py get_dict wasm3 \
  --commit bc32ee \
  --build_csv ~/log/wasm3_builds.csv
```

### fuzz_helper.py get_poc_for_new_version
Generate a PoC for a new version given an old version PoC. Builds the target at `--target_commit` with the revert `--patch` applied, collects execution traces and an allowlist from the buggy commit, then fuzzes with coverage guidance to find a crash matching the original bug signature.

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `project` | Yes | Project name |
| `fuzzer_name` | Yes | Name of the fuzzer |
| `--buggy_commit` | Yes | Commit hash where the bug originally exists |
| `--target_commit` | Yes | Commit hash to generate the PoC for |
| `--testcases` | Yes | Path to directory containing seed testcases |
| `--test_input` | Yes | Testcase filename (e.g., `testcase-OSV-2021-660`) |
| `--build_csv` | Yes | CSV mapping project commits to OSS-Fuzz commit IDs |
| `--patch` | No | Revert patch to apply at target commit |
| `--signature_changes` | Yes (for transplant bugs) | Filename of the JSON signature mapping in `data/signature_change_list/` (e.g., `OSV-2021-1787_e14064.json`). Required when the bug is transplanted to a different commit, so that renamed functions in the crash stack can be matched. |
| `--sanitizer` | No | Sanitizer to use (default: `address`) |

**Example:**
```bash
# 1. Generate the dictionary first
sudo python3 script/fuzz_helper.py get_dict wasm3 \
  --commit bc32ee \
  --build_csv ~/log/wasm3_builds.csv

# 2. Run PoC generation with fuzzing
sudo python3 script/fuzz_helper.py get_poc_for_new_version \
  --buggy_commit 715a8d \
  --target_commit bc32ee \
  --testcases ~/oss-fuzz-for-select/pocs/tmp \
  --test_input testcase-OSV-2021-660 \
  --build_csv ~/log/wasm3_builds.csv \
  --patch patch/OSV-2021-660_bc32ee_patches.diff \
  --signature_changes OSV-2021-660_bc32ee.json \
  --sanitizer address \
  -e ASAN_OPTIONS=detect_leaks=0 \
  wasm3 fuzzer

# Example for stb project
sudo python3 script/fuzz_helper.py get_poc_for_new_version \
  --buggy_commit b1826c \
  --target_commit e14064 \
  --testcases ~/oss-fuzz-for-select/pocs/tmp \
  --test_input testcase-OSV-2021-1787 \
  --build_csv ~/log/stb_builds.csv \
  --patch patch/OSV-2021-1787_e14064_patches.diff \
  --signature_changes OSV-2021-1787_e14064.json \
  --sanitizer address \
  -e ASAN_OPTIONS=detect_leaks=0 \
  stb stbi_read_fuzzer
```

**What it does:**
1. Collects the crash log at the buggy commit using the seed testcase
2. Collects an execution trace at the buggy commit and generates a coverage allowlist
3. Collects a trace at the target commit with the revert patch applied
4. Fuzzes at the target commit with the allowlist-filtered coverage to find a matching crash

### revert_patch_test.py
End-to-end pipeline for selective code migration. Given a target project and a set of bug-introducing commits, it generates revert patches, fixes build errors using the LLM-based multi-agent (`multi_agent.py`), and verifies that the patched code still triggers the original bug.

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `target_test_result` | Yes (positional) | CSV file containing PoC test results across all commits of the target project |
| `--bug_info` | Yes | JSON file with full bug details (project, fuzz_target, sanitizer, etc.) |
| `--build_csv` | Yes | CSV file mapping project commits to OSS-Fuzz build commit IDs |
| `--target` | Yes | Target project name (e.g., `opensc`, `libxml2`) |
| `--bug_id` | No | Process only this specific bug ID (e.g., `OSV-2020-525`) |
| `--buggy_commit` | No | Override the buggy commit to process |
| `--target-commit` | No | Override the target commit to migrate bugs to (default: latest commit in CSV) |
| `--crash-stack-only` | No | Only revert functions that appear in the crash stack (instead of the full execution trace) |
| `--debug-artifact-dir` | No | Skip patch generation and reuse pre-generated patches from this artifact directory |
| `--auto-select-images` | No | Automatically select Docker images based on commit timestamp |
| `--fixed-image YEAR` | No | Pin Docker images to latest versions before the given year (e.g., `2022`) |

**Environment variables:**
| Variable | Required | Description |
|---|---|---|
| `REPO_PATH` | Yes | Path to the directory containing the target project git repo |
| `V1_REPO_PATH` | Yes | Path for old version (V1) source checkout used by the react agent |
| `V2_REPO_PATH` | Yes | Path for new version (V2) source checkout used by the react agent |
| `TESTCASES` | Yes | Path to the directory containing testcase files |
| `OPENAI_API_KEY` | Yes | API key for the LLM used by the react agent |
| `REACT_AGENT_JOBS` | No | Number of parallel agent jobs (default: `4`) |

**Example:**
```bash
source script/setenv.sh

# Process all bugs for the opensc project
sudo -E python3 script/revert_patch_test.py ~/log/opensc.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/opensc_builds.csv \
  --target opensc \
  --auto-select-images

# Process a single bug
sudo -E python3 script/revert_patch_test.py ~/log/opensc.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/opensc_builds.csv \
  --target opensc \
  --auto-select-images \
  --bug_id OSV-2020-525

# Migrate bugs to a specific commit, using only crash-stack functions
sudo -E python3 script/revert_patch_test.py ~/log/opensc.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/opensc_builds.csv \
  --target opensc \
  --auto-select-images \
  --target-commit 2192a2 \
  --crash-stack-only

# Reuse patches from a previous multi-agent run (skip patch generation)
sudo -E python3 script/revert_patch_test.py ~/log/opensc.csv \
  --bug_info osv_testcases_summary.json \
  --build_csv ~/log/opensc_builds.csv \
  --target opensc \
  --debug-artifact-dir data/react_agent_artifacts/multi_20260206_181042_305401_f923ac9f
```

**What it does:**
1. Parses the CSV to identify bug-introducing commits that need transplant
2. For each bug, diffs the buggy commit against the target commit and extracts revert patches
3. Builds the project with the revert patches applied and collects build errors
4. Calls the react multi-agent (`multi_agent.py`) in iterative rounds to fix build errors using LLM-generated override diffs
5. Merges all override diffs into a final patch bundle and runs a final OSS-Fuzz build
6. Verifies the patched build still triggers the original bug (crash reproduction)
7. Caches results incrementally to `data/patches/<target>_patches.pkl.gz` for resumability

### patch_merge.py
Merge compatible patches from multiple bugs into a single unified patch. Loads patch sets produced by `revert_patch_test`, builds a compatibility graph, detects fully compatible groups (cliques), and optionally refreshes stale patches and verifies the merged result.

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `cache_file` | Yes (positional) | Pickled patch dictionary (`*.pkl.gz`) from `revert_patch_test` |
| `--bug_distribution_csv` | Yes | CSV describing bug trigger status per commit (same format as `revert_patch_test`) |
| `--graphviz_output` | No | DOT file path for visualizing the compatibility graph |
| `--fuzz_target` | No | Fuzzer target name for post-merge build and verification |
| `--target_commit` | No | Commit hash used as the base when restoring context to merged patches |
| `--revert_bug_info` | No | JSON file with bug details (forwarded to `revert_patch_test` for patch refresh) |
| `--revert_build_csv` | No | Build CSV (forwarded to `revert_patch_test`) |
| `--revert_target` | No | Target project name (forwarded to `revert_patch_test`) |
| `--revert_output_dir` | No | Directory to capture `revert_patch_test` stdout/stderr logs |

**Environment variables:** Same as `revert_patch_test.py` (`REPO_PATH`, `TESTCASES`, etc.) when using automatic patch refresh.

**Example:**
```bash
source script/setenv.sh

# Basic compatibility analysis with graph output
sudo -E python3 script/patch_merge.py \
  --bug_distribution_csv ~/log/opensc.csv \
  data/patches/opensc_patches.pkl.gz \
  --graphviz_output ~/log/patch_compatibility.dot

# Full merge with automatic patch refresh and fuzzer verification
sudo -E python3 script/patch_merge.py \
  --bug_distribution_csv ~/log/opensc.csv \
  data/patches/opensc_patches.pkl.gz \
  --graphviz_output ~/log/patch_compatibility.dot \
  --revert_bug_info osv_testcases_summary.json \
  --revert_build_csv ~/log/opensc_builds.csv \
  --revert_target opensc \
  --revert_output_dir ~/log/revert_patch/ \
  --target_commit 2192a2 \
  --fuzz_target fuzz_pkcs15init
```

**What it does:**
1. Loads patch sets from the pickle cache and the bug distribution CSV
2. Builds a compatibility graph: patches touching disjoint functions are automatically compatible; overlapping patches are compatible only if both bugs are triggered at a shared commit
3. When overlapping patches exist at different commits, records them as needing refresh
4. If `--revert_*` flags are provided, triggers `revert_patch_test` to regenerate stale patches and re-analyzes until stable
5. Detects fully compatible groups (maximal cliques) using Bron-Kerbosch
6. For the largest group, restores context lines at `--target_commit` and writes a merged diff to `patch/group_<commit>_final.diff`
7. If `--fuzz_target` is provided, builds the fuzzer with the merged patch and runs stack verification against each bug

**Compatibility logic:**
- Patches touching **different functions** are always compatible
- Patches touching **the same functions** require a shared commit where both bugs are triggered. If the patch commits differ from the shared commit, a refresh is needed
- Local bugs (from `data/local_compatibility/<target>.json`) are attached as synthetic nodes in the graph (shown as red in Graphviz output)

**Output files:**
- `patch/group_<commit>_final.diff` — merged unified diff for the largest compatible group
- `data/signature_change_list/merged_<commit>.json` — combined signature mappings for stack verification
- Graphviz DOT file (if `--graphviz_output` specified) — visual compatibility graph

## Contributing
Pull requests and bug reports are welcome.  Please ensure that all scripts pass basic syntax checks before submitting changes.

