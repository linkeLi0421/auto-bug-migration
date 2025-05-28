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

def symbolize_funcs(all_offsets, binary_path):
    # Prepare input for llvm-symbolizer
    offset_to_symbol = {}
    
    # Batch process all offsets in a single call
    cmd_input = '\n'.join([f"{binary_path} {offset}" for offset in all_offsets])
    
    proc = subprocess.Popen(['/out/llvm-symbolizer'], 
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          universal_newlines=True)
    output, error = proc.communicate(input=cmd_input, timeout=30)
    
    if error:
        print(f"Symbolizer error: {error}", file=sys.stderr)
    
    # Process output - each symbol/location pair takes two lines
    output_lines = output.strip().split('\n\n')
    for i in range(len(output_lines)):
        output_line = output_lines[i]
        offset = all_offsets[i]
        lines = output_line.split('\n')
        if len(lines) < 2:
            continue
        symbol = lines[0].strip()
        location = lines[1].strip()
        offset_to_symbol[offset] = (symbol, location)
    
    return offset_to_symbol


def parse_trace_file(file_path: str) -> List[str]:
    """
    Parse the trace file and extract offset information.
    
    Args:
        file_path: Path to the trace file
        
    Returns:
        List of offsets found in the file
    """
    offset_pattern = re.compile(r'offset: ([0-9a-f]+) called by: ([0-9a-f]+)')
    trace_offset_list = []
    caller_to_callees = defaultdict(list)
    all_offsets = set()
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            for match in offset_pattern.finditer(content):
                offset = match.group(1)
                caller_offset = match.group(2)
                trace_offset_list.append(offset)
                caller_to_callees[caller_offset].append(offset)
                all_offsets.add(offset)
                all_offsets.add(caller_offset)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error processing file: {e}")
        
    return list(all_offsets), trace_offset_list, caller_to_callees


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
        all_offsets, trace_offset_list, caller_to_callees = parse_trace_file(args.trace_file)
    
    if not trace_offset_list:
        print("No offset information found in the input.")
        return
    
    # Analyze the trace data
    offset_to_symbol = symbolize_funcs(all_offsets, args.binary)
    
    # Process caller relationships
    for caller_offset, callee_offsets in caller_to_callees.items():
        print(f"Caller: {offset_to_symbol[caller_offset]} {caller_offset}")
        for callee_offset in callee_offsets:
            if callee_offset in offset_to_symbol:
                print(f"  -> Callee: {offset_to_symbol[callee_offset]} {callee_offset}")
                
    for trace_offset in trace_offset_list:
        if trace_offset in offset_to_symbol:
            symbol, location = offset_to_symbol[trace_offset]
            print(f"Trace Offset: {trace_offset} Symbol: {symbol} Location: {location}")

    # Prepare output
    output_lines = [f"Trace Analysis Summary:", f"-----------------------", ""]
    output_lines.append(f"Found {len(trace_offset_list)} function entries.")
    output_lines.append("")
    for trace_offset in trace_offset_list:
        symbol, location = offset_to_symbol[trace_offset]
        if args.source_path:
            # Get relative path
            location = location.replace(args.source_path, "")
        output_lines.append(f"Entering function: {symbol} Location: {location}")
    write_output = "\n".join(output_lines)
    with open(args.output, 'w') if args.output else sys.stdout as f:
        f.write(write_output)
    
if __name__ == "__main__":
    main()