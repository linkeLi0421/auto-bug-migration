import sys

def extract_function_calls(file_path):
    """Extract 'Entering function' lines with their positions from the given file, keeping only one adjacent same function."""
    with open(file_path, 'r') as file:
        lines = [(index + 1, line.strip()) for index, line in enumerate(file) if line.startswith("Entering function")]
        filtered_lines = []
        for i, (pos, func) in enumerate(lines):
            if i == 0 or func != lines[i - 1][1]:  # Keep only if it's the first or different from the previous
                filtered_lines.append((pos, func.split(': ')[1]))  # Extract the function name
        return filtered_lines

def compare_traces(trace1, trace2):
    """Find the first difference and return the common part and all functions after it."""
    common_part = []
    min_length = min(len(trace1), len(trace2))
    for i in range(min_length):
        if trace1[i][1] != trace2[i][1]:
            return common_part, trace1[i:], trace2[i:]
        common_part.append(trace1[i])
    # If no difference is found in the common length, return remaining functions
    return common_part, trace1[min_length:], trace2[min_length:]

def main():
    if len(sys.argv) != 3:
        print("Usage: python compare_trace.py <file1> <file2>")
        sys.exit(1)

    file1, file2 = sys.argv[1], sys.argv[2]
    trace1 = extract_function_calls(file1)
    trace2 = extract_function_calls(file2)

    common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)

    remaining_funcs1 = {func for _, func in remaining_trace1}
    remaining_funcs2 = {func for _, func in remaining_trace2}
    common_funcs = remaining_funcs1.intersection(remaining_funcs2)
    for func in common_funcs:
        print(f"fun:{func}")
    print(f"src:*")

if __name__ == "__main__":
    main()
