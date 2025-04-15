import git
import argparse
import os
import glob
import json
from datetime import datetime, timedelta
import subprocess
import csv
import logging

sanitizer_mapping = {
    'address (ASAN)': 'address'
}

os.environ["ASAN_OPTIONS"] = "detect_leaks=0"

project_end_commit = {
    'c-blosc2': '34db770e436aa4ceaa9b9110948f8dac1f1f443d',
    'libdwarf': '623511122046fca0aefcfbd86f9e41338e95b083',
    'libavc': '3916f3eea4a89090d017aa04981022e1cb49f207',
    'libaom': '5f6ce718d903dca3e49c5c10db0859a394c9be84',
    'jq': '94fd973ebbb49cb00c5f21359c7a57d6f9047e94',
    'cyclonedds': '569d690d3c6f35a15bb72ac62a83539fffda4894',
    'hunspell': '99ba9b5e47a5d5fd851c7986f714d5dd60102625',
    'exiv2': '10dfab262cb470e19e504047887f4a21e75971a0',
    'lcms': 'e19dc49853f7a9e23501b4579fe6274c4fd8f4a9',
    'libexif': '8f013418c2ee71f7aaa81b1699e48d9d3c22dd9b',
    'libjxl': '92c8bef189dd742104f009ea4c3cb1d6a7255e21',
    'libultrahdr': 'bf2aa439eea9ad5da483003fa44182f990f74091',
    'libxml2': '38f475072aefe032fff1dc058df3e56c1e7062fa',
    'ndpi': 'c49d126d3642d5b1f5168d049e3ebf0ee3451edc',
    'openexr': '6cb7d97b2080134def6058dfcbff47abf988fe03',
    'opensc': 'f923dc712516551ce0f17496cfa220b1536f4a6f',
    'quickjs': '6e2e68fd0896957f92eb6c242a2e048c1ef3cae0',
    'mongoose': '4258f6256001f7635f3622aed21867758f5a3fec',
    'espeak-ng': '034807a91dc2abb86ed2012121ca8dbc691dcdb4',
    'harfbuzz': 'e9348cd76d38f72cf881cc860035403220ffbe0b',
    'arduinojson': 'deab127a2fc846c80fe4691489e54fcf9fe2f95f'
}

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)


def get_folder_names(directory):
    folder_names = []
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        if os.path.isdir(item_path):
            folder_names.append(item)
    return folder_names


def get_commit_timestamp(repo_path, commit_hash):
    """
    Get the timestamp of a commit in a Git repository.

    Args:
        repo_path (str): The path to the Git repository.
        commit_hash (str): The hash of the commit.

    Returns:
        : The timestamp of the commit.
    """
    # Open the repository
    repo = git.Repo(repo_path)

    # Get the commit object
    commit = repo.commit(commit_hash)

    # Get the commit timestamp (author date or commit date)
    commit_timestamp = commit.committed_datetime  # or use .authored_datetime for author date

    return commit_timestamp


def get_pocs(folder_path):
    # Initialize an empty list to store all the POC data, return the lastest commit also
    poc = []
    lastest_commit = None
    latsest_time = None

    # Use glob to search for all bug_info.json files recursively in subdirectories
    json_files = glob.glob(os.path.join(folder_path, '**', 'bug_info.json'), recursive=True)

    # Loop through each file and read the JSON data
    for file in json_files:
        with open(file, 'r') as f:
            data = json.load(f)
            
            # Extract information for each bug in the JSON data
            for bug_id, bug_info in data.items():
                bug_data = {
                    "poc_name": bug_id,
                    "introduced_commit": bug_info["introduced"],
                    "fixed_commit": bug_info["fixed"]
                }
                

                # Get the timestamp for both introduced and fixed commits
                introduced_timestamp = get_commit_timestamp(repo_path, bug_info["introduced"])
                fixed_timestamp = get_commit_timestamp(repo_path, bug_info["fixed"])
                if latsest_time == None or fixed_timestamp > latsest_time:
                    lastest_commit = bug_info["fixed"]
                    latsest_time = introduced_timestamp

                # Add timestamps to the data structure
                bug_data["introduced_timestamp"] = introduced_timestamp
                bug_data["fixed_timestamp"] = fixed_timestamp
                # Append the extracted data to the poc list
                poc.append(bug_data)

    sorted_poc = sorted(poc, key=lambda x: x["introduced_timestamp"])
    return sorted_poc, lastest_commit


def find_max_valid_period(pocs):
    """
    Find the time period when the most POCs are valid by counting overlaps.

    Args:
        poc (list): The list of POCs, each containing `introduced_timestamp` and `fixed_timestamp`.

    Returns:
        (start_time, end_time): The time period with the maximum number of valid POCs.
    """
    # Create a list of events (start and end times)
    events = []
    for bug in pocs:
        introduced = bug['introduced_timestamp']
        fixed = bug['fixed_timestamp']

        # Add start and end events
        events.append((introduced, 'start'))
        events.append((fixed, 'end'))

    # Sort events based on time. In case of tie (same time), 'end' should come before 'start'
    events.sort(key=lambda x: (x[0], x[1] == 'start'))

    # Now sweep through the events to find the maximum overlap
    max_overlap = 0
    current_overlap = 0
    best_start = None
    best_end = None

    # Sweep through the events
    for event_time, event_type in events:
        if event_type == 'start':
            current_overlap += 1
            # Update max_overlap if necessary
            if current_overlap > max_overlap:
                max_overlap = current_overlap
                best_start = event_time
        else:  # event_type == 'end'
            if current_overlap == max_overlap:
                best_end = event_time
            current_overlap -= 1

    return best_start, best_end, max_overlap


def find_pocs_in_time_period(pocs, start_time, end_time):
    """
    Find all POCs that are valid within the given time period.

    Args:
        poc (list): The list of POCs, each containing `introduced_timestamp` and `fixed_timestamp`.
        start_time (datetime): The start of the valid time period.
        end_time (datetime): The end of the valid time period.

    Returns:
        valid_pocs (list): A list of POCs that are valid during the time period.
    """
    valid_pocs = []

    # Iterate over each POC to check if it's valid within the given time period
    for p in pocs:
        introduced = p['introduced_timestamp']
        fixed = p['fixed_timestamp']
        
        # Check if the POC is within the valid time period
        if introduced <= end_time and fixed >= start_time:
            valid_pocs.append(p)

    return valid_pocs


def do_bug_build(target_path, bug_path, commit_id):
    '''
    Run helper.py build_image and build_fuzzers
    ''' 
    
    json_files = glob.glob(os.path.join(bug_path, '**', 'bug_info.json'), recursive=True)
    sanitizers = set()
    csv_file_path = os.path.join(log_path, target + '_fail_to_build.csv')
    csv_file = open(csv_file_path, mode='a', newline='')
    writer = csv.writer(csv_file)
    write_header = not os.path.exists(csv_file_path) or os.stat(csv_file_path).st_size == 0
    if write_header:
        writer.writerow(["Target", "Commit ID", "Sanitizer"])
    
    for json_file_path in json_files:
        with open(json_file_path) as f:
            data = json.load(f)
        for bug_id, bug_info in data.items():
            sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
            sanitizers.add(sanitizer)
    os.chdir(target_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8')
    subprocess.run(["git", "checkout", '-f', commit_id], encoding='utf-8')
    for sanitizer in sanitizers:
        if os.path.exists(storage_path + target + '-' + commit_id + '-' + sanitizer):
            return

        os.chdir(oss_fuzz_path)
        cmd = [
            "python3", "infra/helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer,
            target
        ]

        logger.info(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True)
        if "Building fuzzers failed" in result.stdout.lower() or "Building fuzzers failed" in result.stderr.lower():
            logger.info(result.stdout)
            logger.info(result.stderr)
            logger.info(f"Failed to build {target}-{commit_id} with sanitizer {sanitizer}")
            row = [target, commit_id, sanitizer]
            writer.writerow(row)
        else:
            # Create directory for storing output files if it doesn't exist
            os.makedirs(storage_path, exist_ok=True)
            subprocess.run(["mv", "-T", oss_fuzz_path + "/build/out/" + target, storage_path + target + '-' + commit_id + '-' + sanitizer], encoding='utf-8')
    csv_file.close()


def is_second_day_or_greater(t1, t2):
    # Start of the second day (midnight of t1's date + 1 day)
    start_second_day = t1.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
    
    # Check if t2 is on or after the second day
    return t2 >= start_second_day


def is_ancestor(repo_path, commit_id, ancestor_id):
    '''
    check if ancestor_id is an ancestor of commit_id
    '''
    repo = git.Repo(repo_path)
    # Get commit objects
    commit_a = repo.commit(commit_id)
    commit_b = repo.commit(ancestor_id)
    common_ancestor = repo.git.merge_base(commit_a, commit_b)
    if common_ancestor == commit_b.hexsha:
        return True
    else:
        return False

def do_bug_test(target_path, bug_path, commit_id, writer, is_hot_commit, commit_trigger_count):
    '''
    Run helper.py reproduce
    '''
    os.chdir(oss_fuzz_path)
    json_files = glob.glob(os.path.join(bug_path, '**', 'bug_info.json'), recursive=True)

    commit_time = get_commit_timestamp(target_path, commit_id)
    
    row = [commit_id]
    bug_exist_count = 0
    
    for json_file_path in json_files:
        dir_path = os.path.dirname(json_file_path)
        testcases_folder_path = os.path.join(dir_path, "testcases")
        with open(json_file_path) as f:
            data = json.load(f)
        for bug_id, bug_info in data.items():
            poc_path = os.path.join(testcases_folder_path, 'testcase-' + bug_id)
            introduced_timestamp = get_commit_timestamp(repo_path, bug_info["introduced"])
            fixed_timestamp = get_commit_timestamp(repo_path, bug_info["fixed"])
            fuzzing_engine = bug_info['reproduce']['fuzzing_engine']
            fuzz_target = bug_info['reproduce']['fuzz_target']
            sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]

            bug_exist = is_ancestor(repo_path, commit_id, bug_info["introduced"])\
              and is_ancestor(repo_path, bug_info["fixed"], commit_id) and commit_id != bug_info["fixed"]  
            if bug_exist:
                bug_exist_count += 1

            source_dir = storage_path + target + '-' + commit_id + '-' + sanitizer

            if os.path.exists(source_dir):
                pass
            else:
                logger.error(f"Source directory or file does not exist: {source_dir}")
                return
            
            # Too Slow 
            # os.makedirs(os.path.join(oss_fuzz_path, "build/out"), exist_ok=True)
            # target_path = os.path.join(oss_fuzz_path, "build/out", target)
            # if os.path.exists(target_path) or os.path.islink(target_path):
            #     os.remove(target_path)
            # os.symlink(source_dir, target_path)
            # cmd = [
            #     "python3", "infra/helper.py", "reproduce",
            #     target, fuzz_target, poc_path
            # ]
            
            # some bug not stable
            source_path = os.path.join(source_dir, fuzz_target)
            cmd = [
                source_path, poc_path
            ]
            logger.info(' '.join(cmd))
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if 'Sanitizer' in result.stdout or 'Sanitizer' in result.stderr:
                    # poc works
                    if bug_exist:
                        row.append('1|1')
                    else:
                        row.append('1|0')
                    commit_trigger_count[commit_id] += 1
                else:
                    # poc doesn't work
                    if bug_exist:
                        row.append('0|1')
                    else:
                        row.append('0|0')
            except subprocess.TimeoutExpired:
                logger.info(f"Timeout occurred while running command: {' '.join(cmd)}")
                result = None
                row.append('time out')
            except Exception as e:
                logger.info(f"An error occurred while running command: {' '.join(cmd)}")
                logger.info(f"Error message: {str(e)}")
                row.append('')
                result = None
    row.append(bug_exist_count)
    writer.writerow(row)


def get_commits_between(repo_path, start_commit, end_commit):
    """
    Get all commit IDs between two given commits in a Git repository.

    Args:
        repo_path (str): Path to the Git repository.
        start_commit (str): The starting commit ID (older).
        end_commit (str): The ending commit ID (newer).

    Returns:
        list: A list of commit hashes between the given commits.
    """
    repo = git.Repo(repo_path)
    
    # Get commits between the specified commits, including the start and end commits
    commits = list(repo.iter_commits(f"{start_commit}..{end_commit}"))
    
    # Make sure start_commit and end_commit are in the list
    start_commit_obj = repo.commit(start_commit)
    end_commit_obj = repo.commit(end_commit)
    
    commits.append(start_commit_obj)
    commits.append(end_commit_obj)
    commit_hexes = [c.hexsha for c in commits]
    return commit_hexes


if __name__ == "__main__":
    # sudo ~/script/myenv/bin/python3 /home/yun/script/test.py --bug  ~/tasks-simple/libavc/ --repo /home/yun/tasks-git/libavc/ --target libavc --mode test &> /home/yun/test-log/libavc_test_log
    # sudo ~/script/myenv/bin/python3 /home/yun/script/test.py --bug  ~/tasks-simple/libavc/ --repo /home/yun/tasks-git/libavc/ --target libavc --mode test &> /home/yun/test-log/libavc_build_log
    parser = argparse.ArgumentParser()
    parser.add_argument("--bug", help="Path to the folder")
    parser.add_argument("--repo", help="Path to the repository")
    parser.add_argument("--target", help="Name of the target")
    parser.add_argument("--mode", choices=["build", "test", "both"], default="both",
                       help="Specify the operation mode: 'build' for building only, 'test' for testing only, or 'both' for both operations")
    args = parser.parse_args()
    target = args.target
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    oss_fuzz_path = os.path.dirname(current_file_path)
    log_path = '/home/yun/log'
    storage_path = '/mnt/nas/linke/' + target + '/'
        
    repo_path = args.repo
    bug_path = args.bug
    poc_list, lastest_commit = get_pocs(bug_path)
    print(lastest_commit)
    
    target_dockerfile_path = f'{current_file_path}/../projects/{target}/Dockerfile'
    # Replace '--depth=1' in the Dockerfile
    with open(target_dockerfile_path, 'r') as dockerfile:
        dockerfile_content = dockerfile.read()
    updated_content = dockerfile_content.replace('--depth 1', '')
    with open(target_dockerfile_path, 'w') as dockerfile:
        dockerfile.write(updated_content)
    print(f"Updated Dockerfile for {target_dockerfile_path} to remove --depth 1")
    
    do_stat = True
    if do_stat:
        # Do summary statistics
        start_time, end_time, max_poc_num = find_max_valid_period(poc_list)
        logger.info(f"Time period with most valid POCs: {start_time} to {end_time}, {max_poc_num} POCs are valid.")
        logger.info(end_time - start_time)
        pocs_work = find_pocs_in_time_period(poc_list, start_time, end_time)
        os.chdir(repo_path)
        subprocess.run(["git", "clean", "-fdx"], encoding='utf-8')
        subprocess.run(["git", "checkout", '-f', project_end_commit[target]], encoding='utf-8')

        repo = git.Repo(repo_path)
        hot_commits = list(repo.iter_commits(since=start_time, until=end_time))
        hot_commits = set([commit.hexsha for commit in hot_commits])
    
    commits = get_commits_between(repo_path, poc_list[0]['introduced_commit'], project_end_commit[target])
    print(f'from {poc_list[0]["introduced_commit"]} to {project_end_commit[target]}')
    logger.info(len(commits))

    if args.mode in ["build", "both"]:
        for commit in commits:  # from latest to old
            do_bug_build(repo_path, bug_path, commit)
    
    if args.mode in ["test", "both"]:
        commit_trigger_count = {commit: 0 for commit in commits}
        test_csv_file_path = os.path.join(log_path, target + '.csv')
        test_csv_file = open(test_csv_file_path, mode='w', newline='')
        test_writer = csv.writer(test_csv_file)

        json_files = glob.glob(os.path.join(bug_path, '**', 'bug_info.json'), recursive=True)
        csv_header = ['commit id']
        for json_file_path in json_files:
            dir_path = os.path.dirname(json_file_path)
            testcases_folder_path = os.path.join(dir_path, "testcases")
            with open(json_file_path) as f:
                data = json.load(f)
            for bug_id, bug_info in data.items():
                csv_header.append(bug_id)
        csv_header.append('poc count')
        test_writer.writerow(csv_header)  # Write the header
        
        for commit in commits: # from lastest to old
            is_hot_commit = commit in hot_commits
            do_bug_test(repo_path, bug_path, commit, test_writer, is_hot_commit, commit_trigger_count)
        test_csv_file.close()
        
        # Save commit_trigger_count to a new CSV file
        commit_trigger_csv_file_path = os.path.join(log_path, target + '_commit_trigger_count.csv')
        with open(commit_trigger_csv_file_path, mode='w', newline='') as commit_trigger_csv_file:
            commit_trigger_writer = csv.writer(commit_trigger_csv_file)
            commit_trigger_writer.writerow(['commit id', 'trigger count', 'commit time'])  # Write the header
            for commit_id, trigger_count in commit_trigger_count.items():
                commit_trigger_writer.writerow([commit_id, trigger_count, get_commit_timestamp(repo_path, commit_id)])