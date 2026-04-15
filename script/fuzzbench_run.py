#!/usr/bin/env python3
"""Run a FuzzBench experiment for a transplant benchmark.

Generates an experiment config and invokes FuzzBench's run_experiment.py,
which handles building, fuzzing, coverage measurement, and crash collection.

Usage:
    # Build + run 24h experiment with aflplusplus
    sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
        --fuzzer aflplusplus --run-time 86400 --experiment-name transplant-opensc

    # Multiple fuzzers, 5 trials
    sudo -E python3 script/fuzzbench_run.py opensc_transplant_fuzz_pkcs15_reader \
        --fuzzer aflplusplus libfuzzer --run-time 86400 --trials 5 \
        --experiment-name transplant-opensc-5t

    # After experiment, triage:
    python3 script/fuzzbench_triage.py \
        --experiment-dir <experiment_filestore>/<experiment-name> \
        --bug-metadata fuzzbench/benchmarks/opensc_transplant_fuzz_pkcs15_reader/bug_metadata.json \
        --benchmark opensc_transplant_fuzz_pkcs15_reader \
        --output results.csv
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent


def resolve_fuzzbench_dir(explicit_path: str | None) -> Path:
    """Find the FuzzBench root directory."""
    if explicit_path:
        p = Path(explicit_path)
        if (p / "Makefile").exists():
            return p
        logger.error("Not a valid FuzzBench directory: %s", p)
        sys.exit(1)

    candidate = PROJECT_ROOT / "fuzzbench"
    if (candidate / "Makefile").exists():
        return candidate

    logger.error("Cannot find FuzzBench directory. Use --fuzzbench-dir.")
    sys.exit(1)


def generate_experiment_config(output_path: Path, experiment_filestore: Path,
                               report_filestore: Path, trials: int,
                               run_time: int) -> None:
    """Write a local experiment config YAML."""
    # snapshot_period must be shorter than max_total_time, otherwise the
    # runner sleeps past the deadline and the dispatcher sees 0 snapshots.
    snapshot_period = min(900, max(10, run_time // 10))
    content = f"""local_experiment: true
trials: {trials}
max_total_time: {run_time}
snapshot_period: {snapshot_period}
experiment_filestore: {experiment_filestore}
report_filestore: {report_filestore}
docker_registry: gcr.io/fuzzbench
"""
    output_path.write_text(content)
    logger.info("Wrote experiment config: %s", output_path)


def main():
    parser = argparse.ArgumentParser(
        description="Run a FuzzBench experiment for a transplant benchmark",
    )
    parser.add_argument("benchmark",
                        help="Benchmark name (e.g. opensc_transplant_fuzz_pkcs15_reader)")
    parser.add_argument("--fuzzer", nargs="+", required=True,
                        help="Fuzzer(s) to evaluate (e.g. aflplusplus libfuzzer)")
    parser.add_argument("--experiment-name", required=True,
                        help="Name for this experiment (e.g. transplant-opensc-24h)")
    parser.add_argument("--run-time", type=int, default=86400,
                        help="Fuzzing duration in seconds per trial (default: 86400 = 24h)")
    parser.add_argument("--trials", type=int, default=3,
                        help="Number of trials per fuzzer (default: 3)")
    parser.add_argument("--output-dir",
                        help="Base directory for experiment data (default: /tmp/fuzzbench-data)")
    parser.add_argument("--fuzzbench-dir",
                        help="Path to FuzzBench checkout (default: auto-detect)")
    parser.add_argument("--concurrent-builds", type=int,
                        help="Maximum concurrent FuzzBench builds")
    parser.add_argument("--runners-cpus", type=int,
                        help="CPUs available to local trial runners")
    parser.add_argument("--measurers-cpus", type=int,
                        help="CPUs available to local coverage measurers")
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    fuzzbench_dir = resolve_fuzzbench_dir(args.fuzzbench_dir)
    bench_yaml = fuzzbench_dir / "benchmarks" / args.benchmark / "benchmark.yaml"
    if not bench_yaml.exists():
        logger.error("Benchmark not found: %s", bench_yaml)
        sys.exit(1)

    # Set up output directories (must be absolute — run_experiment.py cwd is fuzzbench/)
    output_base = Path(args.output_dir).resolve() if args.output_dir else Path("/tmp/fuzzbench-data")
    experiment_filestore = output_base / args.experiment_name
    report_filestore = output_base / f"{args.experiment_name}-reports"
    experiment_filestore.mkdir(parents=True, exist_ok=True)
    report_filestore.mkdir(parents=True, exist_ok=True)

    # Generate experiment config
    config_path = experiment_filestore / "experiment_config.yaml"
    generate_experiment_config(
        config_path, experiment_filestore, report_filestore,
        args.trials, args.run_time)

    # Use fuzzbench's venv python if available; it has the pinned
    # google-cloud-* deps that run_experiment.py imports. Falling back to
    # sys.executable (system python3) fails with ImportError because those
    # deps aren't installed system-wide.
    venv_python = fuzzbench_dir / ".venv" / "bin" / "python3"
    python_bin = str(venv_python) if venv_python.exists() else sys.executable

    # Build the run_experiment.py command
    cmd = [
        python_bin, "-u", "experiment/run_experiment.py",
        "--experiment-config", str(config_path),
        "--experiment-name", args.experiment_name,
        "--benchmarks", args.benchmark,
        "--fuzzers", *args.fuzzer,
    ]
    if args.concurrent_builds is not None:
        cmd.extend(["--concurrent-builds", str(args.concurrent_builds)])
    if args.runners_cpus is not None:
        cmd.extend(["--runners-cpus", str(args.runners_cpus)])
    if args.measurers_cpus is not None:
        cmd.extend(["--measurers-cpus", str(args.measurers_cpus)])
    # Always allow uncommitted changes — the benchmark itself is generated code
    cmd.append("--allow-uncommitted-changes")

    logger.info("Starting FuzzBench experiment: %s", args.experiment_name)
    logger.info("  Benchmark: %s", args.benchmark)
    logger.info("  Fuzzers: %s", " ".join(args.fuzzer))
    logger.info("  Trials: %d", args.trials)
    logger.info("  Run time: %ds (%dh)", args.run_time, args.run_time // 3600)
    if args.concurrent_builds is not None:
        logger.info("  Concurrent builds: %d", args.concurrent_builds)
    if args.runners_cpus is not None:
        logger.info("  Runner CPUs: %d", args.runners_cpus)
    if args.measurers_cpus is not None:
        logger.info("  Measurer CPUs: %d", args.measurers_cpus)
    logger.info("  Data: %s", experiment_filestore)
    logger.info("")

    env = os.environ.copy()
    env["PYTHONPATH"] = str(fuzzbench_dir)

    result = subprocess.run(cmd, cwd=fuzzbench_dir, env=env)
    if result.returncode != 0:
        logger.error("Experiment failed (exit %d)", result.returncode)
        sys.exit(1)

    logger.info("")
    logger.info("Experiment complete: %s", experiment_filestore)
    bug_metadata = fuzzbench_dir / "benchmarks" / args.benchmark / "bug_metadata.json"
    logger.info("")
    logger.info("Run triage:")
    logger.info("  python3 script/fuzzbench_triage.py \\")
    logger.info("    --experiment-dir %s \\", experiment_filestore)
    logger.info("    --bug-metadata %s \\", bug_metadata)
    logger.info("    --benchmark %s \\", args.benchmark)
    logger.info("    --output results.csv")


if __name__ == "__main__":
    main()
