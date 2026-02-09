#!/usr/bin/env python3
"""
symbolizer.py - Parse trace files containing memory offset information.

This script parses trace output from fuzzing runs, extracting offset and
caller offset information, and uses llvm-symbolizer to convert offsets to
symbol names and source locations.
"""
import re
import sys
import os
import shutil
import argparse
import subprocess
from collections import defaultdict
from typing import List, Tuple, Dict

def symbolize_funcs(all_offsets, binary_path):
    # Prepare input for llvm-symbolizer
    offset_to_symbol = {}

    if not os.path.exists('/out/llvm-symbolizer'):
        llvm_symbolizer_path = shutil.which('llvm-symbolizer')
    else:
        llvm_symbolizer_path = '/out/llvm-symbolizer'

    # Use 0x prefix so llvm-symbolizer reliably parses each address as hex
    cmd_input = '\n'.join(["{} 0x{}".format(binary_path, offset) for offset in all_offsets])

    proc = subprocess.Popen([llvm_symbolizer_path],
                          stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          universal_newlines=True)
    output, error = proc.communicate(input=cmd_input, timeout=30)

    if error:
        print("Symbolizer error: {}".format(error), file=sys.stderr)

    # llvm-symbolizer outputs one block per query, blocks separated by blank lines.
    # Parse by consuming lines sequentially rather than splitting on '\n\n'
    # which breaks when a block contains extra blank lines.
    lines = output.split('\n')
    idx = 0       # current position in lines
    query = 0     # current query index

    while query < len(all_offsets) and idx < len(lines):
        # Skip blank lines between blocks
        while idx < len(lines) and lines[idx].strip() == '':
            idx += 1
        if idx >= len(lines):
            break

        # Read the symbol line
        symbol = lines[idx].strip()
        idx += 1

        # Read the location line (may be absent if symbolizer fails)
        location = '??:0:0'
        if idx < len(lines) and lines[idx].strip() != '':
            location = lines[idx].strip()
            idx += 1

        offset_to_symbol[all_offsets[query]] = (symbol, location)
        query += 1

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
        print("Error: File '{}' not found.".format(file_path))
    except Exception as e:
        print("Error processing file: {}".format(e))
        
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
    call_relation_lines = ['Call Relation Summary:', '-----------------------', '']
    unknown = ('??', '??:0:0')
    for caller_offset, callee_offsets in caller_to_callees.items():
        call_relation_lines.append("Caller: {} {}".format(offset_to_symbol.get(caller_offset, unknown), caller_offset))
        for callee_offset in callee_offsets:
            call_relation_lines.append("  -> Callee: {} {}".format(offset_to_symbol.get(callee_offset, unknown), callee_offset))

                
    for trace_offset in trace_offset_list:
        if trace_offset in offset_to_symbol:
            symbol, location = offset_to_symbol[trace_offset]
            print("Trace Offset: {} Symbol: {} Location: {}".format(trace_offset, symbol, location))

    # Prepare output
    output_lines = call_relation_lines + ["Trace Analysis Summary:", "-----------------------", ""]
    output_lines.append("Found {} function entries.".format(len(trace_offset_list)))
    output_lines.append("")
    for trace_offset in trace_offset_list:
        symbol, location = offset_to_symbol.get(trace_offset, unknown)
        if args.source_path:
            # Get relative path
            location = location.replace(args.source_path, "")
        output_lines.append("Entering function: {} Location: {}".format(symbol, location))
    write_output = "\n".join(output_lines)
    with open(args.output, 'w') if args.output else sys.stdout as f:
        f.write(write_output)
    
if __name__ == "__main__":
    main()