import argparse
from compare_trace import extract_function_calls
from compare_trace import compare_traces

def main():
    parser = argparse.ArgumentParser(description="Compare traces from two files.")
    parser.add_argument("file1", help="Path to the first trace file")
    parser.add_argument("file2", help="Path to the second trace file")
    args = parser.parse_args()
    
    trace1 = extract_function_calls(args.file1)
    trace2 = extract_function_calls(args.file2)

    common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)
    remaining_funcs1 = {func for _, func in remaining_trace1}
    remaining_funcs2 = {func for _, func in remaining_trace2}
    common_funcs = remaining_funcs1.intersection(remaining_funcs2)
        
    for func in common_funcs:
        print(func)

if __name__ == "__main__":
    main()