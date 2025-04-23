import argparse
import subprocess
import sys
import json
import os
import signal
from buildAndtest import checkout_latest_commit

py3 = "/home/user/pyenv/venv/bin/python3"

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run fuzzing tests with trace collection')
    parser.add_argument('--target_bugs', required=False,
                        help='JSON config file containing commit and test input info')
    parser.add_argument('--bug_info', required=False,
                        help='JSON config all bug info details')
    parser.add_argument('--build_csv', required=False,
                        help='this file contains a target project commit id and corresponding commit id')
    return parser.parse_args()

def read_json_file(file_path):
    with open(file_path, "r") as f:
        bug_data = json.load(f)
    
    return bug_data

def run_fuzz_test(args):
    # Check if config file is provided
    bug_data = read_json_file(args.target_bugs)
    bug_info_dataset = read_json_file(args.bug_info)
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
    
    checkout_latest_commit(ossfuzz_path)
    for test_id, bug_info in bug_data.items():
        two_bug_mode = False
        bug_id = bug_info['id']
        base_commit = bug_info['base']
        if 'buggy' in bug_info:
            buggy_commit = bug_info['buggy']
        else:
            buggy_commit1 = bug_info.get('buggy1')
            buggy_commit2 = bug_info.get('buggy2')
            two_bug_mode = True

        bug_info = bug_info_dataset[bug_id]
        sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
        target = bug_info['reproduce']['project']
        fuzzer = bug_info['reproduce']['fuzz_target']
        
        target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
        print(target_dockerfile_path)
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)
        
        # Run the command to get the dictionary for the target
        get_dict_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'get_dict', target, '--commit', base_commit, '--build_csv', args.build_csv]

        # Print the command being executed
        print("Running command:", " ".join(get_dict_cmd))

        # Execute the command
        try:
            subprocess.run(get_dict_cmd, check=True, text=True)
            print(f"Successfully retrieved dictionary for target: {target}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to retrieve dictionary for target: {target} with exit code {e.returncode}")
        return
        target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)

        # Build the command
        cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace']
    
        cmd.extend(['--sanitizer', sanitizer])
    
        cmd.extend(['--base_commit', base_commit])
    
        if two_bug_mode:
            cmd.extend(['--buggy_commit1', buggy_commit1])
            cmd.extend(['--buggy_commit2', buggy_commit2])
            cmd.extend(['--two_bug_mode'])
        else:
            cmd.extend(['--buggy_commit1', buggy_commit])
            cmd.extend(['--buggy_commit2', base_commit])
    
        testcases_env = os.getenv('TESTCASES', '')
        if testcases_env:
            cmd.extend(['--testcases', testcases_env])
        else:
            print("TESTCASES environment variable not set. Exiting.")
            exit(1)
    
        cmd.extend(['--build_csv', args.build_csv])
    
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
        except subprocess.CalledProcessError as e:
            print(f"Command failed with exit code {e.returncode}")
        
        # def restore_dockerfile(signal_received, frame):
        #     with open(target_dockerfile_path, 'w') as dockerfile:
        #         dockerfile.write(dockerfile_content)
        #     print(f"Restored original Dockerfile for {target_dockerfile_path}")
        #     sys.exit(0)

        # Register signal handlers to restore Dockerfile on termination
        # signal.signal(signal.SIGINT, restore_dockerfile)  # Handle Ctrl+C
        # signal.signal(signal.SIGTERM, restore_dockerfile)  # Handle termination signals

if __name__ == "__main__":
    args = parse_arguments()
    sys.exit(run_fuzz_test(args))
