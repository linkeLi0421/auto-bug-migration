import argparse
import subprocess
import sys

from compare_trace import extract_function_calls
from compare_trace import compare_traces


def demangle_cpp_symbol(mangled_symbol: str) -> str:
    """
    Demangles a C++ mangled symbol using the c++filt command-line tool.

    Args:
        mangled_symbol: The mangled C++ symbol string.

    Returns:
        The demangled, readable C++ function signature string,
        or an error message if demangling fails.
    """
    try:
        # Run c++filt as a subprocess.
        # We pass the symbol via standard input to avoid shell issues with special characters.
        process = subprocess.run(
            ['c++filt'],
            input=mangled_symbol,
            capture_output=True,
            text=True, # Decode stdout/stderr as text
            check=True # Raise an exception if c++filt returns a non-zero exit code
        )
        # c++filt outputs the demangled name to standard output
        demangled_name = process.stdout.strip()
        return demangled_name
    except FileNotFoundError:
        return "Error: c++filt command not found. Please ensure it's installed and in your PATH."
    except subprocess.CalledProcessError as e:
        return f"Error demangling symbol: {e.stderr.strip()}"
    except Exception as e:
        return f"An unexpected error occurred: {e}"


def print_func_name(func: str) -> None:
    if func.startswith("_Z"):
        # C++ mangle
        print(demangle_cpp_symbol(func))
        return
    print(func)


def main():
    # trace files => common funcs
    parser = argparse.ArgumentParser(description="Compare traces from two files.")
    parser.add_argument("file1", help="Path to the first trace file")
    parser.add_argument("file2", help="Path to the second trace file")
    parser.add_argument("--file3", help="Path to the optional third trace file", default=None)
    args = parser.parse_args()
    
    trace1 = extract_function_calls(args.file1)
    trace2 = extract_function_calls(args.file2)
    if args.file3:
        trace3 = extract_function_calls(args.file3)

    common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)
    common_funcs12 = {func for _, func in common_part}
    
    if args.file3:
        common_part, remaining_trace1, remaining_trace3 = compare_traces(trace1, trace3)
        common_funcs = {func for _, func in common_part if func in common_funcs12}
    else:
        common_funcs = common_funcs12
        
    for func in common_funcs:
        print_func_name(func)


if __name__ == "__main__":
    main()