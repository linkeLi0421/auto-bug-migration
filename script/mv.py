import argparse
import os
import shutil
import sys

#!/usr/bin/env python3
"""
mv.py

Given a source directory, move all `.i` files to a destination directory,
preserving the relative directory structure.
"""


def move_i_files(src_root: str, dst_root: str):
    src_root = os.path.abspath(src_root)
    dst_root = os.path.abspath(dst_root)

    if not os.path.isdir(src_root):
        print(f"Source directory does not exist: {src_root}", file=sys.stderr)
        sys.exit(1)

    for dirpath, _, filenames in os.walk(src_root):
        for fname in filenames:
            if fname.lower().endswith('.i'):
                src_file = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(dirpath, src_root)
                dst_dir = os.path.join(dst_root, rel_path)
                os.makedirs(dst_dir, exist_ok=True)

                dst_file = os.path.join(dst_dir, fname)
                print(f"Moving {src_file} -> {dst_file}")
                shutil.move(src_file, dst_file)

def parse_args():
    p = argparse.ArgumentParser(
        description="Move all .i files from a source to a destination directory, preserving structure."
    )
    p.add_argument("source", help="Path to the source directory")
    p.add_argument("destination", help="Path to the destination directory")
    return p.parse_args()

def main():
    args = parse_args()
    move_i_files(args.source, args.destination)

if __name__ == "__main__":
    main()