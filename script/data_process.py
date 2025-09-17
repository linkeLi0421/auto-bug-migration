import pandas as pd
import argparse
import os
import json


def load_bug_targets(filepath: str) -> dict:
    """
    Load a JSON file and return a dict mapping bug_id -> fuzz_target.
    
    Args:
        filepath (str): Path to the JSON file.
        
    Returns:
        dict: { bug_id: fuzz_target }
    """
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    result = {}
    for bug_id, bug_data in data.items():
        job_type = bug_data['reproduce']['job_type']
        if len(job_type.split('_')) > 3:
            arch = job_type.split('_')[2]
            if arch != 'x86_64':
                continue
        fuzz_target = bug_data.get("reproduce", {}).get("fuzz_target")
        result[bug_id] = fuzz_target

    return result


if __name__ == '__main__':
    # sudo -E /home/user/pyenv/venv/bin/python3 /home/user/oss-fuzz-for-select/script/data_process.py hdf5 /home/user/merged_bugs.json
    parser = argparse.ArgumentParser()
    parser.add_argument('target', type=str)
    parser.add_argument('bug_info', type=str)
    args = parser.parse_args()

    bug_targets = load_bug_targets(args.bug_info)

    log_path = os.getenv('LOG_PATH')
    csv_path = os.path.join(log_path, args.target + '.csv')
    df = pd.read_csv(csv_path)
    new_files = dict()
    for bug_id, column in df.items():
        if bug_id in bug_targets:
            new_files.setdefault(bug_targets[bug_id], {'commit_id': df['commit id']}).update({bug_id: column})
            
    for fuzz_target, data in new_files.items():
        df = pd.DataFrame(data)
        df.to_csv(os.path.join(log_path, args.target + f'_{fuzz_target}.csv'), index=False)
        print(f'Write {fuzz_target} to {log_path}')