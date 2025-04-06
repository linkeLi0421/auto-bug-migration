import pandas as pd
import sys
import argparse
import json
import os

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Find bug border commits in CSV data.')
    parser.add_argument('file', help='Path to the CSV file to process')
    args = parser.parse_args()

    # Load the CSV file from command line argument
    try:
        df = pd.read_csv(args.file)
    except FileNotFoundError:
        print(f"Error: File '{args.file}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    # Rename the first column to 'commit' for clarity
    df = df.rename(columns={df.columns[0]: "commit"})

    # Bug columns (POC names) are all columns except the first one.
    bug_columns = df.columns[1:]

    # To store results as a dictionary for JSON output
    results = {}

    for bug in bug_columns:
        # We assume the commits are in chronological order.
        # We'll iterate and check for a border between "0|1" and "1|1"
        # For each bug, check the row values sequentially.
        for i in range(1, len(df)):
            prev_value = df.loc[i - 1, bug]
            curr_value = df.loc[i, bug]
            # Check if the previous commit had "0|1" and the current one "1|1"
            # Check if there's at least one "1|1" in the previous rows for this bug
            previous_one_one = df.loc[:i-1, bug][df.loc[:i-1, bug] == "1|1"]
            
            if prev_value == "0|1" and curr_value == "1|1" and not previous_one_one.empty:
                # Find the closest "1|1" commit to the base commit in previous rows
                closest_index = previous_one_one.index[-1]
                results[bug] = {
                    "base": df.loc[i-1, "commit"][:6],
                    "buggy1": df.loc[i, "commit"][:6],
                    "buggy2": df.loc[closest_index, "commit"][:6]
                }
                # Once the border is found, break out of this bug's loop.
                break
    # Extract the base filename from the input file path
    input_filename = os.path.basename(args.file)
    output_filename = os.path.splitext(input_filename)[0] + '_results.json'
    
    # Write the results to a JSON file
    with open(output_filename, 'w') as f:
        json.dump(results, indent=4, fp=f)
    
    print(f"Results written to {output_filename}")

if __name__ == "__main__":
    main()
