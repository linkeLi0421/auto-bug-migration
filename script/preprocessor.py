import os
import json
import subprocess
import argparse


def preprocess_entry(entry):
    args = entry.get("arguments", [])
    if "-c" not in args:
        return

    # Build new argument list: replace -c with -E, drop -o <out>
    new_args = []
    skip = False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "-c":
            new_args.append("-E")
        elif a == "-o":
            skip = True
        else:
            new_args.append(a)

    # Determine source and output paths
    src = entry.get("file")
    if not src:
        return

    # Output file: same directory, same base name with .i extension
    src_base = os.path.basename(src)
    out_base = os.path.splitext(src_base)[0] + ".i"
    new_args.extend(["-o", out_base])

    cwd = entry.get("directory", os.getcwd())
    print(f"Preprocessing {src} -> {out_base}")
    try:
        subprocess.run(new_args, cwd=cwd, check=True)
    except FileNotFoundError:
        print(f"Skipping {src}: missing file or directory")
        return


def main():
    parser = argparse.ArgumentParser(
        description="Preprocess all entries in compile_commands.json"
    )
    parser.add_argument(
        "compile_commands",
        nargs="?",
        default="compile_commands.json",
        help="Path to compile_commands.json",
    )
    args = parser.parse_args()

    with open(args.compile_commands, "r") as f:
        data = json.load(f)

    for entry in data:
        try:
            preprocess_entry(entry)
        except subprocess.CalledProcessError as e:
            print(f"Error preprocessing {entry.get('file')}: {e}")


if __name__ == "__main__":
    main()