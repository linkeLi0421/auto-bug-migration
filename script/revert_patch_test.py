import csv
import re
import sys
import argparse
import subprocess
import sys
import json
import os
from buildAndtest import checkout_latest_commit
from run_fuzz_test import read_json_file
from run_fuzz_test import py3
from compare_trace import extract_function_calls
from compare_trace import compare_traces

def parse_arguments():
    parser = argparse.ArgumentParser(description='Run fuzzing tests with trace collection')
    parser.add_argument('target_test_result',
                        help='Csv file that contains all poc test result on all commits of a target project')
    parser.add_argument('--bug_info', required=True,
                        help='JSON config all bug info details')
    parser.add_argument('--build_csv', required=True,
                        help='this file contains a target project commit id and corresponding commit id')
    return parser.parse_args()

def parse_csv_file(file_path):
    with open(file_path, 'r') as file:
        csv_content = file.read()
    return parse_csv_data(csv_content)

def parse_csv_data(csv_content):
    lines = csv_content.strip().split('\n')
    headers = lines[0].split(',')
    data = []
    
    for line in lines[1:]:
        values = line.split(',')
        if len(values) >= 2:  # Ensure there are at least commit ID and one OSV column
            row = {
                'commit_id': values[0],
                'osv_statuses': {},  # Store all OSV statuses in a dictionary
                'poc_count': values[-1] if values[-1] else 0
            }
            
            # Process all OSV columns (skipping first and last columns)
            for i in range(1, len(values) - 1):
                if i < len(headers):
                    bug_id = headers[i]
                    row['osv_statuses'][bug_id] = values[i] if values[i] else None
            
            data.append(row)
    
    return data

def find_transitions(data):
    transitions = []
    
    for i in range(len(data) - 1):
        current = data[i]
        next_commit = data[i + 1]
        
        # Check for transitions in each OSV
        for bug_id, status in current['osv_statuses'].items():
            if status and re.match(r'1\|.+', status) and bug_id in next_commit['osv_statuses']:
                if next_commit['osv_statuses'][bug_id] == "0|0" or next_commit['osv_statuses'][bug_id] == "0|1":
                    transitions.append((current, next_commit, bug_id))
    
    return transitions

def rever_patch_test(args):
    csv_file_path = args.target_test_result
    bug_info_dataset = read_json_file(args.bug_info)
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    ossfuzz_path = os.path.abspath(os.path.join(current_file_path, '..', 'oss-fuzz'))
    checkout_latest_commit(ossfuzz_path)

    parsed_data = parse_csv_file(csv_file_path)
    transitions = find_transitions(parsed_data)
    
    for commit, next_commit, bug_id in transitions:
        bug_info = bug_info_dataset[bug_id]
        target = bug_info['reproduce']['project']
        fuzzer = bug_info['reproduce']['fuzz_target']
        trace_path1 = f'target_trace-{commit['commit_id']}-testcase-{bug_id}.txt'
        trace_path2 = f'target_trace-{next_commit['commit_id']}-testcase-{bug_id}.txt'
    
        target_dockerfile_path = f'{ossfuzz_path}/projects/{target}/Dockerfile'
        print(target_dockerfile_path)
        # Replace '--depth=1' in the Dockerfile
        with open(target_dockerfile_path, 'r') as dockerfile:
            dockerfile_content = dockerfile.read()
        
        dockerfile_content = dockerfile_content.replace('--depth 1', '')
        updated_content = dockerfile_content.replace('--depth=1', '')
        
        with open(target_dockerfile_path, 'w') as dockerfile:
            dockerfile.write(updated_content)
    
        collect_trace_cmd = [py3, f'{current_file_path}/fuzz_helper.py', 'collect_trace', '--commit', commit['commit_id']]
        testcases_env = os.getenv('TESTCASES', '')
        if testcases_env:
            collect_trace_cmd.extend(['--testcases', testcases_env])
        else:
            print("TESTCASES environment variable not set. Exiting.")
            exit(1)

        collect_trace_cmd.extend(['--build_csv', args.build_csv])

        collect_trace_cmd.extend(['--test_input', 'testcase-' + bug_id])

        collect_trace_cmd.append(target)

        collect_trace_cmd.append(fuzzer)
    
        if not os.path.exists(trace_path1):
            # Print the command being executed
            print("Running command:", " ".join(collect_trace_cmd))
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, text=True)
                print(f"Command completed with exit code {result.returncode}")
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
                
        if not os.path.exists(trace_path2):
            collect_trace_cmd[4] = next_commit['commit_id']
            # Print the command being executed
            print("Running command:", " ".join(collect_trace_cmd))
            # Execute the command
            try:
                result = subprocess.run(collect_trace_cmd, check=True, text=True)
                print(f"Command completed with exit code {result.returncode}")
            except subprocess.CalledProcessError as e:
                print(f"Command failed with exit code {e.returncode}")
        
        trace1 = extract_function_calls(trace_path1)
        trace2 = extract_function_calls(trace_path2)
        common_part, remaining_trace1, remaining_trace2 = compare_traces(trace1, trace2)
        
        print(common_part)
        break
    
    
if __name__ == "__main__":
    args = parse_arguments()
    rever_patch_test(args)