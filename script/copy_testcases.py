#!/usr/bin/env python3
import glob
import os
import shutil
from pathlib import Path
import sys

# 1. Configure source folder and pattern
if len(sys.argv) < 2:
    print("Usage: copy_testcases.py <source_dir>")
    sys.exit(1)

SOURCE_DIR = sys.argv[1]
PATTERN    = 'testcase*'              # matches any file starting with "testcase"

# 2. Destination: ~/testcases
DEST_DIR = Path.home() / 'testcases'
DEST_DIR.mkdir(parents=True, exist_ok=True)

# 3. Build full glob path and find matches recursively
glob_path = os.path.join(SOURCE_DIR, '**', PATTERN)
matches = glob.glob(glob_path, recursive=True)

# 4. Copy each match to DEST_DIR
for src_path in matches:
    if os.path.isfile(src_path):  # skip directories
        filename = os.path.basename(src_path)
        dst_path  = DEST_DIR / filename
        print(f'Copying {src_path} → {dst_path}')
        shutil.copy2(src_path, dst_path)
