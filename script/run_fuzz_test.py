import argparse
import subprocess
import sys
import json

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run fuzzing tests with trace collection')
    parser.add_argument('--target_bugs', required=False,
                        help='JSON config file containing commit and test input info')
    parser.add_argument('--bug_info', required=False,
                        help='JSON config all bug info details')
    return parser.parse_args()

def read_json_file(file_path):
    with open(file_path, "r") as f:
        bug_data = json.load(f)
    
    return bug_data

def run_fuzz_test(args):
    # Check if config file is provided
    bug_data = read_json_file(args.target_bugs)
    bug_info_dataset = read_json_file(args.bug_info)
    
    for bug_id, commits in bug_data.items():
        base_commit = commits['base']
        buggy_commit = commits['buggy']
        
        bug_info = bug_info_dataset[bug_id]
        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        target = bug_info['reproduce']['project']
        fuzzer = bug_info['reproduce']['fuzz_target']
        
        # Build the command
        cmd = ['python3', 'infra/helper.py', 'collect_trace']
    
        cmd.extend(['--sanitizer', sanitizer])
    
        cmd.extend(['--base_commit', base_commit])
    
        cmd.extend(['--buggy_commit', buggy_commit])
    
        cmd.extend(['--allowlist', '/home/yun/tmp_corpus'])
    
        cmd.extend(['--test_input', 'testcase-' + bug_id])
    
        cmd.extend(['-e', 'ASAN_OPTIONS=detect_leaks=0'])
        
        cmd.append(target)

        cmd.append(fuzzer)
        
        # Print the command being executed
        print("Running command:", " ".join(cmd))
        # Execute the command
        try:
            result = subprocess.run(cmd, check=True, text=True)
            print(f"Command completed with exit code {result.returncode}")
            return result.returncode
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")
            return e.returncode

if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(run_fuzz_test(args))
