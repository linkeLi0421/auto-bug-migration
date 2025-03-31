import os
import json
import glob
import sys

def merge_bug_json_files(directory_path, output_file='merged_bugs.json'):
    """
    Merges all 'bug_info.json' files in the given directory into a single JSON object
    with bug IDs as keys.
    
    Args:
        directory_path (str): Path to the directory containing bug_info.json files
        output_file (str): Name of the output file
    """
    # Convert to absolute path if not already
    directory_path = os.path.abspath(directory_path)
    
    # Find all bug_info.json files
    bug_files = glob.glob(os.path.join(directory_path, '**/bug_info.json'), recursive=True)
    
    if not bug_files:
        print(f"No 'bug_info.json' files found in {directory_path}")
        return
    
    # Initialize dictionary to store all bug data with bug IDs as keys
    all_bugs = {}
    bug_count = 0
    
    # Read and merge each bug file
    for file_path in bug_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
                # Handle both single bug objects and arrays of bugs
                if isinstance(data, list):
                    for bug_obj in data:
                        for bug_id, bug_info in bug_obj.items():
                            all_bugs[bug_id] = bug_info
                            bug_count += 1
                else:
                    for bug_id, bug_info in data.items():
                        all_bugs[bug_id] = bug_info
                        bug_count += 1
                    
            print(f"Processed: {file_path}")
        except json.JSONDecodeError:
            print(f"Error: Could not parse JSON in {file_path}")
        except Exception as e:
            print(f"Error processing {file_path}: {str(e)}")
    
    # Write merged data to output file
    with open(output_file, 'w') as f:
        json.dump(all_bugs, f, indent=2)
    
    print(f"Successfully merged {bug_count} bug entries into {output_file}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        directory = sys.argv[1]
        output = sys.argv[2] if len(sys.argv) > 2 else 'merged_bugs.json'
        merge_bug_json_files(directory, output)
    else:
        print("Usage: python merge_bug_json.py <directory_path> [output_file]")