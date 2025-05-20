import re
import sys
import argparse
import subprocess
from collections import defaultdict
from typing import List, Tuple, Dict

#!/usr/bin/env python3
"""
symbolizer.py - Parse trace files containing memory offset information.

This script parses trace output from fuzzing runs, extracting offset and 
caller offset information, and uses llvm-symbolizer to convert offsets to
symbol names and source locations.
"""

def symbolize(offsets, binary_path):
    # Prepare input for llvm-symbolizer
    output_data = []
    
    for offset in offsets:
        cmd = f"{binary_path} {offset}"
        proc = subprocess.Popen(['/out/llvm-symbolizer', cmd], 
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                universal_newlines=True)
        output, error = proc.communicate(timeout=30)
        if error:
            print(f"Symbolizer error: {error}", file=sys.stderr)
    
        # Process output
        lines = output.strip().split('\n')
        symbol = lines[0]
        location = lines[1]
        output_data.append((symbol, location))
    return output_data


def parse_trace_file(file_path: str) -> List[Tuple[str, str]]:
    """
    Parse the trace file and extract offset and caller offset pairs.
    
    Args:
        file_path: Path to the trace file
        
    Returns:
        List of (offset, caller_offset) tuples
    """
    offset_pattern = re.compile(r'offset: ([0-9a-f]+)')
    func_offset_list = []
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            matches = offset_pattern.findall(content)
            func_offset_list = [offset for offset in matches]
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error processing file: {e}")
        
    return func_offset_list


def main():
    # python3 /home/user/oss-fuzz-for-select/script/symbolizer.py -b /home/user/oss-fuzz-for-select/oss-fuzz/build/out/c-blosc2/decompress_chunk_fuzzer -o ./tmp_trace  /home/user/oss-fuzz-for-select/data/target_trace-9ba29ef1584b7c29f5303dce51909a52da4837ee-testcase-OSV-2020-2183.txt --source_path /src/c-blosc2
    """Main function to run the symbolizer."""
    parser = argparse.ArgumentParser(description='Parse trace files containing offset information.')
    parser.add_argument('trace_file', nargs='?', help='Path to the trace file')
    parser.add_argument('-o', '--output', required=True, help='Output file path (default: stdout)')
    parser.add_argument('-b', '--binary', required=True, help='Path to the binary for symbolization')
    parser.add_argument('--source_path', help='Path to the source code directory, used for get relative path')
    args = parser.parse_args()
    
    # If no trace file is provided, read from stdin
    if args.trace_file:
        func_offset_list = parse_trace_file(args.trace_file)
    
    if not func_offset_list:
        print("No offset information found in the input.")
        return
    
    # Analyze the trace data
    symbols = {}
    symbols = symbolize(list(func_offset_list), args.binary)

    # Prepare output
    output_lines = [f"Trace Analysis Summary:", f"-----------------------", ""]
    output_lines.append(f"Found {len(symbols)} function entries.")
    output_lines.append("")
    for symbol, location in symbols:
        if args.source_path:
            # Get relative path
            location = location.replace(args.source_path, "")
        output_lines.append(f"Entering function: {symbol} Location: {location}")
    write_output = "\n".join(output_lines)
    with open(args.output, 'w') if args.output else sys.stdout as f:
        f.write(write_output)
    
if __name__ == "__main__":
    main()