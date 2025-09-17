#!/usr/bin/env python3
"""
Fetch OSV IDs for a list of OSS-Fuzz projects and save to JSON.

Usage:
  python fetch_osv_ossfuzz.py -i projects.txt -o osv_map.json
  cat projects.txt | python fetch_osv_ossfuzz.py -o osv_map.json
"""

import argparse
import json
import sys
import time
from typing import List, Dict, Any
import requests

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 5
BACKOFF_BASE = 1.6


def backoff(attempt: int, retry_after: str | None) -> None:
    if retry_after:
        try:
            time.sleep(max(1, int(retry_after)))
            return
        except ValueError:
            pass
    time.sleep(BACKOFF_BASE ** attempt)

def post_with_retries(session: requests.Session, url: str, payload: Dict[str, Any]) -> requests.Response:
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = session.post(url, json=payload, timeout=DEFAULT_TIMEOUT)
            if r.status_code in (429, 500, 502, 503, 504):
                if attempt < MAX_RETRIES:
                    backoff(attempt, r.headers.get("Retry-After"))
                    continue
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            if attempt >= MAX_RETRIES:
                raise
            backoff(attempt, None)
    raise RuntimeError("unreachable")

def read_projects(path: str | None) -> List[str]:
    lines: List[str]
    if path:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]

def chunked(items: List[Any], n: int) -> List[List[Any]]:
    return [items[i:i+n] for i in range(0, len(items), n)]

def fetch_osv_ids_for_projects(projects: List[str]) -> Dict[str, List[str]]:
    """
    Use /v1/querybatch with ecosystem=OSS-Fuzz.
    The response `results` list aligns 1:1 with the submitted queries.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "osv-ossfuzz-fetcher/1.0 (+https://osv.dev)",
        "Accept": "application/json",
    })

    result: Dict[str, List[str]] = {p: [] for p in projects}

    # Batch in reasonable chunks
    for batch in chunked(projects, 100):
        payload = {
            "queries": [
                {"package": {"ecosystem": "OSS-Fuzz", "name": p}}
                for p in batch
            ]
        }
        try:
            resp = post_with_retries(session, OSV_QUERYBATCH, payload)
        except Exception as e:
            # If one batch fails, mark all in that batch empty and continue
            sys.stderr.write(f"Batch error ({', '.join(batch)}): {e}\n")
            continue

        data = resp.json()
        results = data.get("results", [])
        # Align results with the batch order
        for proj, entry in zip(batch, results):
            vulns = entry.get("vulns") or []
            ids = []
            for v in vulns:
                vid = v.get("id")
                if vid:
                    ids.append(vid)
            result[proj] = ids

        # be nice to the API
        time.sleep(0.1)

    return result

def main():
    # sudo -E /home/user/pyenv/venv/bin/python3 /home/user/oss-fuzz-for-select/script/oss-fuzz-api/get_bugs.py -i /home/user/oss-fuzz-vulns/c_projects.txt
    ap = argparse.ArgumentParser(description="Fetch OSV IDs for OSS-Fuzz projects.")
    ap.add_argument("-i", "--input", help="File with project names (one per line). Default: stdin.")
    ap.add_argument("-o", "--output", default="osv_projects.json", help="Output JSON file (default: osv_projects.json)")
    args = ap.parse_args()

    projects = read_projects(args.input)
    if not projects:
        print("No projects provided.", file=sys.stderr)
        sys.exit(1)

    mapping = fetch_osv_ids_for_projects(projects)

    # Save pretty JSON
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(mapping, f, indent=2, sort_keys=True)
    print(f"\nSaved JSON to {args.output}")

if __name__ == "__main__":
    main()
