#!/usr/bin/env python3
"""
Reads either:
1) Old "results"-style JSON with records containing things like:
   {
     "Detailed Report": "...",
     "Project": "...",
     "Fuzz Target": "...",
     "Job Type": "libfuzzer_asan_i386_..."
   }

2) New OSV-keyed JSON mapping:
   {
     "OSV-2021-485": {
       "introduced": "...",
       "fixed": "...",
       "url": "...",
       "reproduce": {
         "project": "c-blosc2",
         "fuzzing_engine": "libFuzzer",
         "fuzz_target": "",
         "job_type": "libfuzzer_asan_c-blosc2",
         "platform_id": "linux",
         "reproducer_testcase": "https://..."
       }
     },
     ...
   }

Outputs a CSV with columns:
project,fuzz_target,arch,bug_count

Bugs are deduped per (project,fuzz_target,arch) using a stable unique id:
- For OSV-keyed input: the OSV key (e.g., "OSV-2021-485")
- For old records: the Detailed Report URL if present; otherwise a synthetic id
"""

import argparse
import json
import csv
import logging
from pathlib import Path
from collections import defaultdict
import re

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---- Your arch helper (as requested) ----------------------------------------
def get_architecture_name(job_type: str) -> str:
    if 'i386' in job_type:
        return 'i386'
    else:
        return 'x86_64'

# ---- Flexible key sets -------------------------------------------------------
PROJECT_KEYS = ("Project", "project", "project_name")
TARGET_KEYS  = ("Fuzz Target", "Fuzz target", "fuzz_target", "fuzz target", "FuzzTarget")
DETAIL_KEYS  = ("Detailed Report", "detailed report", "detailed_report", "detailedReport", "detail", "url")
JOBTYPE_KEYS = ("Job Type", "job_type", "JobType")
REPRO_CASED  = ("reproduce", "Reproduce")

UNKNOWN_TARGET = "<unknown>"

def pick_first(d: dict, keys):
    for k in keys:
        if k in d and d[k] is not None:
            return d[k]
    return None

def extract_urlish(s: str):
    if not isinstance(s, str):
        return None
    m = re.search(r"https?://[^\s'\"<>]+", s)
    return m.group(0) if m else None

def iterate_old_records(data):
    """Yield (project, fuzz_target, arch, unique_id) from the old 'results' style."""
    # find list of records
    records = None
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            records = data["results"]
        elif isinstance(data.get("items"), list):
            records = data["items"]
        else:
            for v in data.values():
                if isinstance(v, list):
                    records = v
                    break
    elif isinstance(data, list):
        records = data

    if not isinstance(records, list):
        return

    for idx, rec in enumerate(records, 1):
        if not isinstance(rec, dict):
            continue

        project  = pick_first(rec, PROJECT_KEYS)
        target   = pick_first(rec, TARGET_KEYS)
        detailed = pick_first(rec, DETAIL_KEYS)
        job_type = pick_first(rec, JOBTYPE_KEYS) or ""

        if detailed is None:
            # scan all string fields for a URL
            for val in rec.values():
                detailed = extract_urlish(val) or detailed
                if detailed:
                    break

        if not project:
            continue

        project = str(project).strip()
        target = (str(target).strip() if target else "") or UNKNOWN_TARGET
        arch = get_architecture_name(str(job_type))
        unique_id = (str(detailed).strip() if detailed else f"__NO_DETAILED_REPORT__#{idx}")

        yield project, target, arch, unique_id

def iterate_osv_keyed(data):
    """Yield (project, fuzz_target, arch, unique_id) from the new OSV-keyed mapping."""
    if not isinstance(data, dict):
        return
    for osv_id, entry in data.items():
        if not isinstance(entry, dict):
            continue

        # locate reproduce dict (case variants)
        rep = None
        for rk in REPRO_CASED:
            if isinstance(entry.get(rk), dict):
                rep = entry[rk]
                break
        rep = rep or {}

        project  = rep.get("project") or pick_first(entry, PROJECT_KEYS)
        target   = rep.get("fuzz_target") or pick_first(rep, TARGET_KEYS) or pick_first(entry, TARGET_KEYS)
        job_type = rep.get("job_type") or pick_first(entry, JOBTYPE_KEYS) or ""
        unique_id = osv_id or entry.get("url") or rep.get("reproducer_testcase")

        if not project or not unique_id:
            continue

        project = str(project).strip()
        target = (str(target).strip() if target else "") or UNKNOWN_TARGET
        arch = get_architecture_name(str(job_type))
        unique_id = str(unique_id).strip()

        yield project, target, arch, unique_id

# ---- Main --------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Aggregate fuzz bugs by (project, fuzz_target, arch) and write CSV.")
    ap.add_argument("-i", "--input",  required=True, type=Path, help="Input JSON (old 'results' style or OSV-keyed mapping)")
    ap.add_argument("-o", "--output", required=True, type=Path, help="Output CSV path")
    args = ap.parse_args()

    if not args.input.exists():
        logger.error("Input file %s not found", args.input)
        raise SystemExit(2)

    try:
        with args.input.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        logger.exception("Failed to load JSON: %s", e)
        raise SystemExit(2)

    # Aggregate: (project, target, arch) -> set(unique_bug_id)
    counts = defaultdict(set)

    emitted = 0
    for p, t, a, uid in iterate_osv_keyed(data):
        counts[(p, t, a)].add(uid)
        emitted += 1

    if emitted == 0:
        for p, t, a, uid in iterate_old_records(data):
            counts[(p, t, a)].add(uid)
            emitted += 1

    if emitted == 0:
        logger.error("No records recognized in input. Is the JSON in expected format?")
        raise SystemExit(2)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as csvf:
        w = csv.writer(csvf)
        w.writerow(["project", "fuzz_target", "arch", "bug_count"])
        for (proj, tgt, arch), ids in sorted(
            counts.items(),
            key=lambda x: (x[0][0].lower(), x[0][1].lower(), x[0][2].lower())
        ):
            w.writerow([proj, tgt, arch, len(ids)])

    logger.info("Wrote %d rows to %s", len(counts), args.output)

if __name__ == "__main__":
    main()
