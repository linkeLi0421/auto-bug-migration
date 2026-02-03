# How to Download OSS-Fuzz Bugs and Testcases

This guide explains how to use the scripts in the `script/oss-fuzz-api/` directory to fetch bug information and download associated testcases.

## Prerequisites

Before running any scripts, source the environment setup file:

```bash
source script/setenv.sh
```

This sets up environment variables including `$PYTHON_PATH`, `$TESTCASES`, `$BUGINFO_PATH`, etc.

## Step 1: Find Bugs for a Project (`get_bugs.py`)

The `get_bugs.py` script fetches OSV (Open Source Vulnerability) IDs for a given list of OSS-Fuzz projects.

**Usage:**

1.  Create a text file (e.g., `projects.txt`) where each line is the name of an OSS-Fuzz project you want to query.

    ```bash
    echo "c-blosc2" > projects.txt
    ```

2.  Run `get_bugs.py` to fetch the OSV IDs:

    ```bash
    python3 script/oss-fuzz-api/get_bugs.py -i projects.txt -o c-blosc2_bugs.json
    ```

    This command will:
    *   Read project names from `projects.txt`.
    *   Query the OSV API for each project.
    *   Save a JSON file (`c-blosc2_bugs.json`) containing a mapping of project names to their discovered OSV IDs.

## Step 2: Download Bug Details and Testcases (`osv_helper.py`)

The `osv_helper.py` script takes the OSV IDs found in Step 1, fetches detailed bug reports from OSV and linked Chromium bug trackers, and can optionally download the actual reproducer testcase files.

**Usage:**

1.  **Set up the download directory:** Ensure `$TESTCASES` is set (done by `setenv.sh`) and the directory exists:

    ```bash
    mkdir -p "$TESTCASES"
    ```

2.  Run `osv_helper.py` using the JSON output from `get_bugs.py` as input. Use the `--download=True` flag to enable testcase downloads.

    ```bash
    python3 script/oss-fuzz-api/osv_helper.py -i c-blosc2_bugs.json --download=True -o c-blosc2_bug_details.json
    ```

    This command will:
    *   Read OSV IDs from `c-blosc2_bugs.json`.
    *   Fetch detailed information for each bug, including links to bug reports and testcases.
    *   Save a new JSON file (`c-blosc2_bug_details.json`) with all the detailed information.
    *   Download the actual testcase files into the directory specified by `$TESTCASES`.

    You can also specify OSV IDs directly on the command line:

    ```bash
    python3 script/oss-fuzz-api/osv_helper.py OSV-2021-221 --download=True -o OSV-2021-221_details.json
    ```

## Utility Script: Counting Bugs (`count_bugs.py`)

The `count_bugs.py` script is used to aggregate and count bugs from a JSON file (either the old OSS-Fuzz results format or the new OSV-keyed format). It generates a CSV file with bug counts per project, fuzz target, and architecture. This script does **not** download any files.

**Usage:**

```bash
python3 script/oss-fuzz-api/count_bugs.py -i c-blosc2_bug_details.json -o c-blosc2_counts.csv
```

This will:
*   Read the detailed bug information from `c-blosc2_bug_details.json`.
*   Generate a CSV file (`c-blosc2_counts.csv`) summarizing the number of unique bugs.