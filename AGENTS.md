# Repository Guidelines

## Project Structure & Module Organization
Top-level orchestration lives in `script/`. The main entrypoints are `script/bug_transplant.py`, `script/bug_transplant_batch.py`, `script/bug_transplant_merge_offline.py`, `script/fuzzbench_generate.py`, and `script/fuzzbench_triage.py`. Prompt templates are in `script/prompts/`. Generated artifacts, intermediate patches, and run outputs are stored under `data/`. Native helpers live in `cfg-clang/` (LLVM/Clang CFG tool) and `Function_instrument/` (trace library). `oss-fuzz/` is a vendored checkout used for project images and infra tests; `fuzzbench/` is used for experiment runs and generated benchmarks.

## Build, Test, and Development Commands
Create a Python environment and install dependencies with `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`. Load repo-specific paths with `source script/setenv.sh` based on `script/setenv_example.sh`. Common workflows:

- `python3 script/bug_transplant_batch.py ... --dry-run` previews a transplant batch.
- `python3 script/bug_transplant_batch.py ... --resume` continues an interrupted run.
- `python3 script/bug_transplant_merge_offline.py ...` merges per-bug outputs.
- `python3 script/fuzzbench_generate.py ...` builds a FuzzBench benchmark bundle.
- `cd cfg-clang && mkdir -p build && cd build && cmake -DCMAKE_PREFIX_PATH=/llvm/build .. && make` builds the CFG tool.
- `make -C Function_instrument` builds `libtrace.so` and `libtrace.a`.

## Coding Style & Naming Conventions
Python code uses 4-space indentation, type hints where practical, `pathlib.Path`, and module-level logging (`logger = logging.getLogger(__name__)`). Keep functions focused and favor explicit CLI flags over hidden defaults. Use `snake_case` for Python identifiers and filenames; preserve existing names such as `buildAndtest.py` when modifying established modules. Shell snippets should be POSIX-friendly Bash.

## Testing Guidelines
There is no single root test runner. For Python infra under `oss-fuzz/infra`, run `pytest oss-fuzz/infra` or targeted files such as `pytest oss-fuzz/infra/utils_test.py`; test files follow the `*_test.py` pattern. For native helpers, use `bash cfg-clang/test_enhanced_cfg.sh` and rebuild `Function_instrument` with `make clean all` after changes. Validate pipeline changes with a small `--dry-run` or a single-bug run before scaling up.

## Commit & Pull Request Guidelines
Recent history uses concise, imperative subjects like `Add FuzzBench evaluation pipeline` and `Replace canary instrumentation with coverage-based crash line tracking`. Keep commit titles short, present tense, and scoped to one logical change. PRs should include the affected workflow, exact commands used for validation, linked issues or bug IDs, and screenshots only when UI files such as `index.html` change. Avoid bundling unrelated updates to `oss-fuzz/`, generated outputs, or local experiment data.
