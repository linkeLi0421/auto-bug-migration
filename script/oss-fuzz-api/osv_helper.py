#!/usr/bin/env python3
"""
Fetch OSS-Fuzz testcase links from OSV IDs by following bugs.chromium.org references.

Usage examples:
  python3 fetch_osv_testcases.py OSV-2021-640
  python3 fetch_osv_testcases.py OSV-2021-640 OSV-2021-1712 -d ./testcases -o summary.json
  python3 fetch_osv_testcases.py -i ids.txt -d ./testcases

Notes:
- This script intentionally ignores top-level 'reproduce' and 'database_specific' fields.
- It only inspects OSV 'references' to find bugs.chromium.org oss-fuzz issues,
  then follows their JS redirect to issues.oss-fuzz.com pages and extracts oss-fuzz.com testcase links.
"""

import argparse
import json
import logging
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional
import html
from urllib.parse import unquote, urlparse, parse_qs
import os

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BUGS_RE = re.compile(r"https://bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=\d+")
# Detect tiny js-redirect pages like:
# const url = "https://issues.oss-fuzz.com/42495817"; window.location = url + hash;
_JS_REDIRECT_RE = re.compile(
    r'window\.location\s*=\s*(?:url\s*\+\s*hash|["\'](?P<url>https?://[^\s"\'<>]+)["\'])',
    re.IGNORECASE
)
_JS_URL_RE = re.compile(r'const\s+url\s*=\s*["\'](?P<url>https?://[^\s"\'<>]+)["\']', re.IGNORECASE)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("fetch_osv_testcases")

GOOGLE_REDIRECT_RE = re.compile(
    r'https?://www\.google\.com/url\?q=(https?%3A%2F%2Foss-fuzz\.com%2F[^"\'\s<>]+)',
    re.IGNORECASE
)

TESTCASE_RE = re.compile(
    r'https://oss-fuzz\.com/(?:download\?testcase_id=\d+|testcase-detail/\d+)',
    re.IGNORECASE
)

# Match the first anchor right after "Detailed Report:"
_DETAILED_RE = re.compile(r'Detailed Report:\s*<a[^>]+href="([^"]+)"', re.IGNORECASE)


def _normalize_issue_html(raw: str) -> str:
    """
    Normalize Issue Tracker HTML/JS so our regex can see real URLs:
    - unescape \u003d, \u0026 etc.
    - HTML-unescape (e.g., &amp;)
    - decode %xx in wrapped URLs we extract
    """
    if not raw:
        return raw

    # Replace common JS-escaped chars found in Issue Tracker JSON
    norm = (raw
            .replace(r'\u003d', '=')
            .replace(r'\u0026', '&')
            .replace(r'\u002F', '/'))

    # HTML-unescape (&amp; -> &, etc.)
    norm = html.unescape(norm)

    # Also expand any google redirector occurrences into actual oss-fuzz links
    # We decode only the captured target; keep the rest untouched.
    def _replace_google(m):
        encoded = m.group(1)
        try:
            return unquote(encoded)  # -> https://oss-fuzz.com/...
        except Exception:
            return encoded

    norm = GOOGLE_REDIRECT_RE.sub(_replace_google, norm)
    return norm


def normalize_testcase_links(links: list[str]) -> list[str]:
    """
    Keep only direct download links.
    - Convert testcase-detail/{id} -> download?testcase_id={id}
    - If testcase?key=<digits>, convert to download?testcase_id=<digits>
    - If testcase?key is non-numeric and a corresponding download link exists, drop the key form.
    - Deduplicate by testcase_id.
    """
    by_id: dict[str, str] = {}

    for url in links:
        # Keep only download?testcase_id=...
        if "/download?testcase_id=" in url:
            case_id = parse_qs(urlparse(url).query).get("testcase_id", [""])[0]
            if case_id:
                by_id[case_id] = f"https://oss-fuzz.com/download?testcase_id={case_id}"

    # Return only the canonical download links
    return list(by_id.values())


def extract_testcase_links_from_html(html_text: str):
    """
    Return a list of testcase URLs found in the issue page, after normalization.
    """
    if not html_text:
        return []

    text = _normalize_issue_html(html_text)

    found = []
    seen = set()

    # 1) Direct matches (download, testcase-detail, or testcase?key=...)
    for m in TESTCASE_RE.findall(text):
        url = m
        # Normalize testcase-detail -> download
        if 'testcase-detail/' in url:
            case_id = url.rsplit('/', 1)[-1]
            url = f'https://oss-fuzz.com/download?testcase_id={case_id}'
        # Keep testcase?key=... as-is (not always downloadable anonymously)
        if url not in seen:
            seen.add(url)
            found.append(url)

    # 2) As a safety net, scan any remaining google redirectors missed above
    for m in GOOGLE_REDIRECT_RE.findall(text):
        url = unquote(m)
        if 'oss-fuzz.com/' in url and url not in seen:
            seen.add(url)
            found.append(url)

    return found


def requests_session_with_retries(total_retries: int = 3, backoff: float = 0.5) -> requests.Session:
    s = requests.Session()
    retries = Retry(
        total=total_retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST"]),
    )
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": "fetch-osv-testcases/1.0"})
    return s


def get_osv_record(session: requests.Session, osv_id: str, timeout: int = 15) -> Optional[Dict]:
    try:
        r = session.get(OSV_VULN_URL.format(osv_id), timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logger.error("Failed to fetch OSV %s: %s", osv_id, e)
        return None


def extract_bug_links_from_record(rec: Dict) -> List[str]:
    bug_urls = []
    for ref in rec.get("references", []):
        url = ref.get("url", "")
        if BUGS_RE.fullmatch(url):
            bug_urls.append(url)
    # dedupe while preserving order
    seen, out = set(), []
    for u in bug_urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def fetch_issue_page(session: requests.Session, url: str, timeout: int = 15, max_follow: int = 3) -> Optional[str]:
    """Fetch an issue page; if it’s a tiny JS redirect, follow to issues.oss-fuzz.com and return final HTML."""
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
        html = r.text

        for _ in range(max_follow):
            m = _JS_REDIRECT_RE.search(html)
            target = None
            if m and m.groupdict().get("url"):
                target = m.group("url")
            if not target:
                m2 = _JS_URL_RE.search(html)
                if m2:
                    target = m2.group("url")

            if target:
                logger.info("Following JS redirect to %s", target)
                r = session.get(target, timeout=timeout)
                r.raise_for_status()
                html = r.text
                continue  # loop in case of chained JS redirects

            # no redirect markers found → return what we have
            return html

        return html
    except Exception as e:
        logger.warning("Failed to fetch issue page %s : %s", url, e)
        return None


def download_testcase(session: requests.Session, link: str, dstdir: Path, osv_id, timeout: int = 60) -> Optional[str]:
    dstdir.mkdir(parents=True, exist_ok=True)
    m = re.search(r"testcase_id=(\d+)", link)
    if m:
        fname = f"testcase_{m.group(1)}"
    else:
        # fallback to last segment
        fname = Path(link).name.replace("/", "_")
    out_path = dstdir / f'testcase-{osv_id}'
    try:
        with session.get(link, timeout=timeout, stream=True) as r:
            r.raise_for_status()
            with open(out_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=16384):
                    if chunk:
                        f.write(chunk)
        logger.info("Downloaded %s -> %s", link, out_path)
        return str(out_path)
    except Exception as e:
        logger.error("Download failed %s: %s", link, e)
        if out_path.exists():
            try:
                out_path.unlink()
            except Exception:
                pass
        return None

def _js_extract_quoted_block(src: str, needle: str) -> Optional[str]:
    """
    Find the JS-quoted string that contains `needle` (e.g., 'Detailed Report:').
    Handles escaped quotes.
    Returns the raw quoted content (without surrounding quotes), still with JS escapes.
    """
    i = src.find(needle)
    if i == -1:
        return None
    # Walk back to the opening quote
    start = i
    while start > 0 and src[start] not in ['"', "'"]:
        start -= 1
    if start == 0:
        return None
    quote = src[start]
    # Walk forward to the matching closing quote, respecting escapes
    j = start + 1
    escaped = False
    while j < len(src):
        ch = src[j]
        if escaped:
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == quote:
            break
        j += 1
    if j >= len(src):
        return None
    return src[start+1:j]  # content without quotes


def _clean_htmlish(s: str) -> str:
    # Decode JS unicode escapes like \u003c
    try:
        s = s.encode("utf-8").decode("unicode_escape")
    except Exception:
        pass

    # Normalize <br> to newlines
    s = re.sub(r"(?i)<br\s*/?>", "\n", s)

    # Replace <a ...>inner</a> with its inner text (usually a URL already)
    s = re.sub(r"(?is)<a\b[^>]*>(.*?)</a>", r"\1", s)

    # Strip any remaining tags
    s = re.sub(r"(?s)<[^>]+>", "", s)

    # HTML entities -> chars
    s = html.unescape(s)

    # Normalize whitespace
    lines = [ln.rstrip() for ln in s.splitlines()]
    # Drop leading NBSP or weird spaces
    lines = [ln.replace("\xa0", " ").rstrip() for ln in lines]
    # Collapse multiple blank lines
    out = []
    blank = 0
    for ln in lines:
        if ln.strip():
            out.append(ln)
            blank = 0
        else:
            blank += 1
            if blank < 2:
                out.append("")
    return "\n".join(out).strip()

def _parse_keyvals(block: str) -> Dict[str, Any]:
    """
    Parse the Detailed Report block into a dict.
    Handles a multi-line 'Crash State:' section specially.
    Leaves anything it can't parse in 'extra'.
    """
    data: Dict[str, Any] = {}
    extra_lines = []
    lines = block.splitlines()

    # find the header line ("Detailed Report: <url>")
    if lines and lines[0].startswith("Detailed Report:"):
        data["Detailed Report"] = lines[0].split("Detailed Report:", 1)[1].strip()
        i = 1
    else:
        i = 0

    # Collect until we hit the disclosure boilerplate (optional)
    crash_state_collecting = False
    crash_state_lines = []
    while i < len(lines):
        ln = lines[i].strip()
        i += 1
        if not ln:
            # blank line ends Crash State block
            if crash_state_collecting:
                break
            else:
                continue

        # Key: value pattern
        m = re.match(r"^([A-Za-z ][A-Za-z 0-9/_-]*?):\s*(.*)$", ln)
        if m:
            key, value = m.group(1).strip(), m.group(2).strip()
            if key == "Crash State":
                crash_state_collecting = True
                crash_state_lines = []
            elif key in ("Regressed", "Reproducer Testcase"):
                # These lines are URLs; keep as-is
                data[key] = value
            else:
                data[key] = value
            continue

        # While collecting Crash State, each non-empty line is a frame
        if crash_state_collecting:
            crash_state_lines.append(ln)
        else:
            extra_lines.append(ln)

    if crash_state_collecting and crash_state_lines:
        data["Crash State"] = crash_state_lines

    if extra_lines:
        data["extra"] = "\n".join(extra_lines).strip()

    return data

def extract_detailed_report(html_text: str) -> Dict[str, Any]:
    """
    End-to-end:
      - locate the JS string containing 'Detailed Report:'
      - unescape & clean to readable text
      - parse into a dict (plus 'raw_text' for reference)
    """
    raw = _js_extract_quoted_block(html_text, "Detailed Report:")
    if not raw:
        return {"raw_text": None, "parsed": {}}

    cleaned = _clean_htmlish(raw)

    # Keep the full text for reference
    parsed = _parse_keyvals(cleaned)

    return {"raw_text": cleaned, "parsed": parsed}


def get_sanitizer_name(job_type: str) -> str:
    """Gets the sanitizer name from a ClusterFuzz job type."""
    if '_asan' in job_type:
        return 'address (ASAN)'

    if '_msan' in job_type:
        return 'memory (MSAN)'

    if '_ubsan' in job_type:
        return 'undefined (UBSAN)'

    raise ValueError('unknown sanitizer')


def process_osv_id(session: requests.Session, osv_id: str, download_dir: Optional[Path], delay: float) -> Dict:
    rec = get_osv_record(session, osv_id)
    if not rec:
        return {}
    if 'fixed' not in str(rec):
        return {}

    bug_links = extract_bug_links_from_record(rec)
    testcase_links: List[str] = []
    downloaded: List[str] = []

    for bug_link in bug_links:
        html = fetch_issue_page(session, bug_link)
        if html:
            detailed_report = extract_detailed_report(html)
            for tc in extract_testcase_links_from_html(html):
                if tc not in testcase_links:
                    testcase_links.append(tc)
        time.sleep(delay)

    if download_dir:
        for tc in testcase_links:
            # normalize testcase-detail to download link
            if "testcase-detail/" in tc and "download?testcase_id=" not in tc:
                m = re.search(r"testcase-detail/(\d+)", tc)
                if m:
                    tc = f"https://oss-fuzz.com/download?testcase_id={m.group(1)}"
            local = download_testcase(session, tc, download_dir, osv_id)
            if local:
                downloaded.append(local)
            time.sleep(delay)
    
    result = detailed_report['parsed']
    
    if result:
        result.update({
            "bug_link": bug_links[0],
            "testcase_link": testcase_links[0],
            "introduced": rec['affected'][0]['ranges'][0]['events'][0]['introduced'],
            "fixed": rec['affected'][0]['ranges'][0]['events'][1].get('fixed', ''),
        })
        return result
    else:
        return {}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Fetch oss-fuzz testcase links via OSV references.")
    ap.add_argument("osv_ids", nargs="*", help="OSV IDs like OSV-2021-640 (space-separated).")
    ap.add_argument("-i", "--input-file", type=Path, help="File with one OSV ID per line.")
    ap.add_argument("-o", "--out", type=Path, default=Path("osv_testcases_summary.json"), help="Output JSON summary path.")
    ap.add_argument("--delay", type=float, default=0.4, help="Delay between HTTP requests (seconds).")
    ap.add_argument("--timeout", type=int, default=15, help="HTTP timeout (seconds).")
    ap.add_argument("--download", type=bool, default=False, help="Whether download testcases.")
    args = ap.parse_args(argv)

    ids: List[str] = []
    if args.input_file:
        if not args.input_file.exists():
            logger.error("Input file %s not found", args.input_file)
            sys.exit(2)
        with open(args.input_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # `data` is a dict: { project_name: [osv_ids...] }
        for project, osv_list in data.items():
            for osv_id in osv_list:
                ids.append(osv_id)
    ids += args.osv_ids
    if not ids:
        ap.print_help()
        sys.exit(2)

    download_dir = os.getenv('TESTCASES')
    if args.download:
        if not download_dir:
            logger.error("TESTCASES env var not set")
            sys.exit(2)
        download_dir = Path(download_dir).expanduser()
    else:
        download_dir = None

    session = requests_session_with_retries()
    out_obj = dict()
    for osv in ids:
        result = process_osv_id(session, osv, download_dir, args.delay)
        if not result:
            continue
        out_obj[osv] = {
            "introduced": result.get("introduced", ""),
            "fixed": result.get("fixed", ""),
            "url": result.get("bug_link", ""),
            "reproduce": {
                "project": result.get("Project", ""),
                "fuzzing_engine": result.get("Fuzzing Engine", ""),
                "fuzz_target": result.get("Fuzz Target", ""),
                "job_type": result.get("Job Type", ""),
                "platform_id": result.get("Platform Id", ""),
                "crash_type": result.get("Crash Type", ""),
                "crash_address": result.get("Crash Address", ""),
                "sanitizer": get_sanitizer_name(result.get("Job Type", "")),
                "reproducer_testcase": result.get("testcase_link", ""),
            }
        }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out_obj, f, indent=2, ensure_ascii=False)
        logger.info("Wrote summary to %s", args.out)


if __name__ == "__main__":
    main()
