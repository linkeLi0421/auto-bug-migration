# OSS-Fuzz for Select

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
| `--signature_changes` | No | JSON file mapping old function names to new ones |
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
  --sanitizer address \
  -e ASAN_OPTIONS=detect_leaks=0 \
  wasm3 fuzzer
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

## Contributing
Pull requests and bug reports are welcome.  Please ensure that all scripts pass basic syntax checks before submitting changes.

