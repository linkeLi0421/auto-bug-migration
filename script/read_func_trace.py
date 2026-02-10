import sys
import os
import json
import argparse

def load_signature_changes(signature_file):
    """
    Load signature changes from JSON file and keep all candidate replacements.
    
    Args:
        signature_file (str): Path to JSON file containing signature changes
        
    Returns:
        dict: Mapping from old function name to list of possible new names
    """
    if not signature_file:
        return {}
    
    try:
        with open(signature_file, 'r') as f:
            signature_pairs = json.load(f)
        
        signature_map = {}
        for pair in signature_pairs:
            if len(pair) >= 2:
                old_func, new_func = pair[0], pair[1]
                clean_old = old_func.strip()
                clean_new = new_func.strip()
                signature_map.setdefault(clean_old, [])
                if clean_new not in signature_map[clean_old]:
                    signature_map[clean_old].append(clean_new)
        
        print(f"Loaded {len(signature_map)} signature groups from {signature_file}")
        return signature_map
    
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load signature changes from {signature_file}: {e}")
        return {}

def apply_signature_changes(functions, signature_map):
    """
    Apply signature changes to function set.
    
    Args:
        functions (set): Set of function names
        signature_map (dict): Mapping from old to list of new function names
        
    Returns:
        set: Updated set of function names with signature changes applied
    """
    if not signature_map:
        return functions
    
    updated_functions = set()
    additions = 0
    
    for func in functions:
        clean_func = func.split(' ')[0].split('(')[0]  # Remove params and extra info
        updated_functions.add(clean_func)
        
        for new_func in signature_map.get(clean_func, []):
            if new_func not in updated_functions:
                additions += 1
            updated_functions.add(new_func)
    
    if additions > 0:
        print(f"Added {additions} candidate functions based on signature changes")
    
    return updated_functions

def read_func_trace(file_path):
    """
    Read function trace data from the specified file.
    
    Args:
        file_path (str): Path to the trace file
        
    Returns:
        set: Set of function names found in the trace
    """
    function_names = set()
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if "Entering function:" in line:
                    function_name = line.split("Entering function:")[1].strip().split(' ')[0].split('(')[0]
                    function_names.add(function_name)
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error reading trace file: {str(e)}")
    
    return function_names

def create_allowlist(functions, output_file=None):
    """
    Create allowlist content from function set.
    
    Args:
        functions (set): Set of function names
        output_file (str): Optional output file path
        
    Returns:
        str: Allowlist content
    """
    allowlist_content = ""
    for func in sorted(functions):  # Sort for consistent output
        allowlist_content += f"fun:{func}\n"
    allowlist_content += "src:*\n"
    
    if output_file:
        try:
            with open(output_file, 'w') as f:
                f.write(allowlist_content)
            print(f"Allowlist written to: {output_file}")
        except Exception as e:
            print(f"Error writing allowlist to {output_file}: {e}")
    
    return allowlist_content

def main():
    """Main function with argument parsing and orchestration."""
    parser = argparse.ArgumentParser(
        description='Process function traces and create allowlist with optional signature changes'
    )
    parser.add_argument(
        'trace_file', 
        help='Path to the trace file containing function traces'
    )
    parser.add_argument(
        '-o', '--output', 
        help='Output file path for allowlist (default: print to stdout)'
    )
    parser.add_argument(
        '--signature-changes', '--signature_change_list',
        help='JSON file containing signature changes (e.g., OSV-2020-2184_54a733.json)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Validate input file
    if not os.path.isfile(args.trace_file):
        print(f"Error: '{args.trace_file}' is not a valid file")
        sys.exit(1)
    
    if args.verbose:
        print(f"Reading function traces from: {args.trace_file}")
    
    # Read function traces
    function_set = read_func_trace(args.trace_file)
    
    if args.verbose:
        print(f"Found {len(function_set)} unique functions in trace")
    
    # Load signature changes if provided
    signature_map = load_signature_changes(args.signature_changes)
    
    # Apply signature changes
    updated_functions = apply_signature_changes(function_set, signature_map)
    
    # Create allowlist
    allowlist_content = create_allowlist(updated_functions, args.output)
    
    # Print to stdout if no output file specified
    if not args.output:
        print(allowlist_content)

if __name__ == '__main__':
    main()
