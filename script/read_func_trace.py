import sys
import os

def read_func_trace(file_path):
    """
    Read function trace data from the specified file.
    
    Args:
        file_path (str): Path to the trace file
        
    Returns:
        dict: Dictionary of addresses mapped to function and line information
    """
    function_names = set()
    seen_llvm_inputoutput = False
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                if "Entering function:" in line:
                    function_name = line.split("Entering function:")[1].strip()
                    if "LLVMFuzzerTestOneInput" in function_name:
                        seen_llvm_inputoutput = True
                        continue
                    if seen_llvm_inputoutput:
                        function_names.add(function_name)
        
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found")
    except Exception as e:
        print(f"Error reading trace file: {str(e)}")
    
    return function_names

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 read_func_trace.py <trace_file_path>")
        sys.exit(1)
        
    file_path = sys.argv[1]
        
    if not os.path.isfile(file_path):
        print(f"Error: '{file_path}' is not a valid file")
        sys.exit(1)
        
    print(f"Processing trace file: {file_path}")
    function_set = read_func_trace(file_path)
    print(f"Found {len(function_set)} function entries")
        
    # Write functions to allowlist.txt
    allowlist_content = ""
    for func in function_set:
        allowlist_content += f"fun:{func}\n"
    allowlist_content += "src:*\n"

    with open("allowlist.txt", "w") as f:
        f.write(allowlist_content)
        
    print(f"Wrote {len(function_set)} functions to allowlist.txt")