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

### run_fuzz_test.py
Run fuzzing tests with trace collection for a set of bugs. It reads bug configurations from JSON files, builds the target project at the specified commits, retrieves fuzzer dictionaries, and runs `fuzz_helper.py fuzz_one` for each bug entry.

**Arguments:**
| Argument | Required | Description |
|---|---|---|
| `--target_bugs` | Yes | JSON config file mapping test IDs to commit and bug info (keys: `id`, `base`, `buggy` or `buggy1`/`buggy2`) |
| `--bug_info` | Yes | JSON file with full bug details including `reproduce.project`, `reproduce.fuzz_target`, and `reproduce.sanitizer` |
| `--build_csv` | Yes | CSV file mapping project commits to OSS-Fuzz build commit IDs |

**Environment variables:**
| Variable | Description |
|---|---|
| `TESTCASES` | **(Required)** Path to the directory containing testcase files (named `testcase-<bug_id>`) |
| `PYTHON_PATH` | Python interpreter path (default: `python3`). Set via `script/setenv.sh` |

**Example:**
```bash
source script/setenv.sh

python3 script/run_fuzz_test.py \
  --target_bugs config/my_bugs.json \
  --bug_info osv_testcases_summary.json \
  --build_csv log/opensc_builds.csv
```

**target_bugs JSON format:**
```json
{
  "test_1": {
    "id": "OSV-2020-525",
    "base": "a3ee8c",
    "buggy": "8963c3"
  },
  "test_2": {
    "id": "OSV-2021-100",
    "base": "abc123",
    "buggy1": "def456",
    "buggy2": "ghi789"
  }
}
```
Each entry can use single-bug mode (`buggy`) or two-bug mode (`buggy1`/`buggy2`).

**What it does:**
1. Checks out the latest OSS-Fuzz commit and patches Dockerfiles (removes `--depth 1` for full git history)
2. Retrieves the fuzzer dictionary via `fuzz_helper.py get_dict`
3. Runs `fuzz_helper.py fuzz_one` with the appropriate sanitizer, commits, and testcase

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

