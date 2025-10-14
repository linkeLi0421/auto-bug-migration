import argparse

def extract_function_calls(file_path):
    """Extract 'Entering function' lines with their positions from the given file, keeping only one adjacent same function."""
    with open(file_path, 'r') as file:
        lines = [(index + 1, line.strip().split('Location:')[0], line.strip().split(' Location: ')[1]) for index, line in enumerate(file) if line.startswith("Entering function")]
        filtered_lines = []
        for i, (pos, func, loc) in enumerate(lines):
            if i == 0 or func != lines[i - 1][1]:  # Keep only if it's the first or different from the previous
                filtered_lines.append((pos, func.split(': ')[1] + loc))  # Extract the function name
        return filtered_lines


def compare_traces(trace1, trace2, signature_change_list=None):
    """Find the first difference and return the common part and all functions after it."""
    common_part = []
    min_length = min(len(trace1), len(trace2))
    for i in range(min_length):
        func1 = trace1[i][1].split(' ')[0]
        func2 = trace2[i][1].split(' ')[0]
        if func1 != func2 and not (signature_change_list and any((func1, func2) == sig_pair or (func2, func1) == sig_pair for sig_pair in signature_change_list)) and (func2 != f'__revert_{func1}'):
            return common_part
        common_part.append(trace1[i])
        common_part.append(trace2[i])
    # If no difference is found in the common length, return remaining functions
    return common_part


def main():
    parser = argparse.ArgumentParser(description="Compare traces from two files.")
    parser.add_argument("file1", help="Path to the first trace file")
    parser.add_argument("file2", help="Path to the second trace file")
    parser.add_argument("--two_bug_mode", action="store_true", help="Enable two buggy mode, false means one buggy one base commit trace to compare")
    args = parser.parse_args()

    trace1 = extract_function_calls(args.file1)
    trace2 = extract_function_calls(args.file2)
    print(f'trace1: {trace1[:100]}')
    print(f'trace2: {trace2[:100]}')

    common_part = compare_traces(trace1, trace2)

    if args.two_bug_mode:
        for _, func in common_part:
            print(f"fun:{func}")
    else:
        for func in common_part:
            print(f'fun:{func}')
    print(f"src:*")


if __name__ == "__main__":
    main()
