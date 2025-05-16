import git
from git.exc import BadName, GitCommandError, InvalidGitRepositoryError
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


def git_first_last_commit(folder_path):
    # Initialize variables to store the oldest introduced and newest fixed commits
    oldest_introduced_commit = None
    newest_fixed_commit = None
    oldest_time = None
    newest_time = None

    # Use glob to search for all bug_info.json files recursively in subdirectories
    json_files = glob.glob(os.path.join(folder_path, '**', 'bug_info.json'), recursive=True)

    # Loop through each file and read the JSON data
    for file in json_files:
        with open(file, 'r') as f:
            data = json.load(f)

            # Extract information for each bug in the JSON data
            for bug_id, bug_info in data.items():
                introduced_timestamp = get_commit_timestamp(repo_path, bug_info["introduced"])
                fixed_timestamp = get_commit_timestamp(repo_path, bug_info["fixed"])

                # Update the oldest introduced commit
                if oldest_time is None or introduced_timestamp < oldest_time:
                    oldest_introduced_commit = bug_info["introduced"]
                    oldest_time = introduced_timestamp

                # Update the newest fixed commit
                if newest_time is None or fixed_timestamp > newest_time:
                    newest_fixed_commit = bug_info["fixed"]
                    newest_time = fixed_timestamp

    return oldest_introduced_commit, newest_fixed_commit


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


def do_bug_build(target_path, bug_path, commit_id, month, build_writer):
    '''
    Run helper.py build_image and build_fuzzers
    ''' 
    oss_fuzz_commit = find_matching_commit(target_path, oss_fuzz_path, commit_id, month)
    if not oss_fuzz_commit:
        # commit timestamp add month is newer than Head in oss-fuzz, so we can't find a version of oss-fuzz to build
        return "No appropriate version os oss-fuzz, stop try newer. Try build next version of target project"
        
    os.chdir(oss_fuzz_path)
    subprocess.run(["git", "clean", "-fdx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, encoding='utf-8')
    subprocess.run(["git", "checkout", '-f', oss_fuzz_commit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, encoding='utf-8')
    logger.info(f"Building {target} with oss-fuzz in commit {oss_fuzz_commit} (month = {month})")
    
    target_dockerfile_path = f'{oss_fuzz_path}/projects/{target}/Dockerfile'
    # Replace '--depth=1' in the Dockerfile
    if not os.path.exists(target_dockerfile_path):
        logger.error(f"Target Dockerfile not found: {target_dockerfile_path} will try newer oss-fuzz again.")
        return do_bug_build(target_path, bug_path, commit_id, month+6, build_writer)
    with open(target_dockerfile_path, 'r') as dockerfile:
        dockerfile_content = dockerfile.read()
    updated_content = dockerfile_content.replace('--depth 1', '')
    updated_content = updated_content.replace('--depth=1', '')
    with open(target_dockerfile_path, 'w') as dockerfile:
        dockerfile.write(updated_content)
    
    json_files = glob.glob(os.path.join(bug_path, '**', 'bug_info.json'), recursive=True)
    sanitizers = set()
    archs = set()
    
    for json_file_path in json_files:
        with open(json_file_path) as f:
            data = json.load(f)
        for bug_id, bug_info in data.items():
            sanitizer = bug_info['reproduce']['sanitizer'].split(' ')[0]
            sanitizers.add(sanitizer)
            job_type = bug_info['reproduce']['job_type']
            if len(job_type.split('_')) > 3:
                arch = job_type.split('_')[2]
            else:
                arch = 'x86_64'
            archs.add(arch)
    
    os.chdir(target_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8')
    subprocess.run(["git", "checkout", '-f', commit_id], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for arch in archs:
        arch_str = f"-{arch}" if arch != 'x86_64' else ''
        for sanitizer in sanitizers:
            if sanitizer == 'memory' and arch == 'i386':
                # msan do not support i386
                continue
            if os.path.exists(os.path.join(target_storage_path, target + '-' + commit_id + '-' + sanitizer + arch_str)) and len(os.listdir(os.path.join(target_storage_path, target + '-' + commit_id + '-' + sanitizer + arch_str))) > 3:
                continue

            cmd = [
                "python3", f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer, "--architecture", arch,
                target
            ]

            logger.info(' '.join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True)
            if any(error_pattern in result.stderr or error_pattern in result.stdout for error_pattern in [
                "Building fuzzers failed",
                "Docker build failed",
                "clang++: error:",
                "g++: error:",
                "cmake: error:",
                "fatal error:",
                "undefined reference to",
                "cannot find -l",
                "No such file or directory",
                "error: command",
                "error: 'struct",
                "error: conflicting types",
                "error: invalid conversion",
                "make: *** [Makefile:",
                "ninja: build stopped:",
                "Compilation failed",
                "failed with exit status"
            ]) or result.returncode != 0:
                logger.info(f"Failed to build {target}-{commit_id} with sanitizer {sanitizer} {arch}, will try newer oss-fuzz again.")
                return do_bug_build(target_path, bug_path, commit_id, month+6, build_writer)
            else:
                # build finish here
                logger.info(f"Build finished for {target}-{commit_id} with sanitizer {sanitizer} and architecture {arch}.")
                # Create directory for storing output files if it doesn't exist
                os.makedirs(target_storage_path, exist_ok=True)
                # Create the destination directory if it doesn't exist
                dest_path = os.path.join(target_storage_path, target + '-' + commit_id + '-' + sanitizer + arch_str)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                
                # Move with force option to overwrite if destination exists
                move_result = subprocess.run(["mv", "-f", "-T", oss_fuzz_path + "/build/out/" + target, dest_path], encoding='utf-8')
                if move_result.returncode == 0:
                    build_writer.writerow([target, commit_id, oss_fuzz_commit, sanitizer])

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
    start_commit = repo.commit(commit_id)
    end_commit = repo.commit(ancestor_id)
    common_ancestor = repo.git.merge_base(start_commit, end_commit)
    if common_ancestor == end_commit.hexsha:
        return True
    else:
        return False

def do_bug_test(target_path, bug_path, commit_id, writer, json_files):
    '''
    Run helper.py reproduce
    '''
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
            crash_type = bug_info['reproduce']['crash_type']
            job_type = bug_info['reproduce']['job_type']
            if len(job_type.split('_')) > 3:
                arch = job_type.split('_')[2]
            else:
                arch = 'x86_64'
            arch_str = f"-{arch}" if arch != 'x86_64' else ''

            bug_exist = is_ancestor(repo_path, commit_id, bug_info["introduced"])\
              and is_ancestor(repo_path, bug_info["fixed"], commit_id) and commit_id != bug_info["fixed"]  
            if bug_exist:
                bug_exist_count += 1

            source_dir = os.path.join(target_storage_path, target + '-' + commit_id + '-' + sanitizer + arch_str)

            if os.path.exists(source_dir):
                pass
            else:
                logger.error(f"Source directory or file does not exist: {source_dir}")
                return

            # some bug not stable
            source_path = os.path.join(source_dir, fuzz_target)
            cmd = [
                source_path, poc_path
            ]
            logger.info(' '.join(cmd))
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if 'Sanitizer'.lower() in result.stderr.lower() and crash_type.lower() in result.stderr.lower():
                    # poc works
                    if bug_exist:
                        row.append('1|1')
                    else:
                        row.append('1|0')
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


def get_commits_by_time_window(repo_path, start_commit, end_commit):
    """
    Get all commits with commit times between two specified commits.
    
    Args:
        repo_path (str): Path to Git repository
        start_commit (str): First boundary commit hash
        end_commit (str): Second boundary commit hash
    
    Returns:
        list: Commit hashes in chronological order between the timestamps
    """
    try:
        repo = git.Repo(repo_path)
    except InvalidGitRepositoryError:
        raise ValueError(f"Invalid repository: {repo_path}")

    try:
        a = repo.commit(start_commit)
        b = repo.commit(end_commit)
    except BadName:
        raise ValueError("Invalid commit hash")

    # Get time boundaries
    time_a = a.committed_datetime
    time_b = b.committed_datetime
    start_time = min(time_a, time_b)
    end_time = max(time_a, time_b)

    # Get all commits across all branches
    all_commits = list(repo.iter_commits(all=True))

    # Filter commits within time window
    filtered = [
        c for c in all_commits
        if start_time < c.committed_datetime < end_time
    ]

    # Sort chronologically
    filtered.sort(key=lambda x: x.committed_datetime)

    return [c.hexsha for c in filtered]

def get_commits_between(repo_path, start_commit, end_commit):
    """
    Get all commit IDs between two given commits in a Git repository.

    Args:
        repo_path (str): Path to the Git repository.
        start_commit (str): The starting commit ID (older).
        end_commit (str): The ending commit ID (newer).

    Returns:
        list: A list of commit hashes between the given commits, in chronological order.

    Raises:
        ValueError: For invalid repository path or commit hashes
    """
    try:
        repo = git.Repo(repo_path)
    except InvalidGitRepositoryError:
        raise ValueError(f"'{repo_path}' is not a valid Git repository")

    try:
        start = repo.commit(start_commit)
        end = repo.commit(end_commit)
    except BadName as e:
        raise ValueError(f"Invalid commit hash: {e}")

    # Verify start is an ancestor of end
    try:
        repo.git.merge_base('--is-ancestor', start.hexsha, end.hexsha)
    except GitCommandError as e:
        if e.status == 1:
            # Not in ancestor path
            logger.info(f"start commit {start_commit} is not ancestor of End commit {end_commit}! Use commits that timestamp between them instead.")
            return get_commits_by_time_window(repo_path, start_commit, end_commit)

    rev_list = repo.iter_commits(f"{start.hexsha}..{end.hexsha}", ancestry_path=True)

    # Reverse to get chronological order (oldest first)
    commits = list(rev_list)[::-1]
    commits.insert(0, start)

    return [c.hexsha for c in commits]


def get_next_commits(repo_path, target_commit_hash, num_commits=10):
    # Open the repository
    repo = git.Repo(repo_path)
    
    try:
        # Get the target commit
        target_commit = repo.commit(target_commit_hash)
    except git.BadName:
        logger.info(f"Commit {target_commit_hash} not found.")
        return []
    
    # Get all commits after the target commit (exclusive)
    # Using 'target_commit_hash..HEAD' to specify the commit range
    is_ancestor = repo.git.merge_base('--is-ancestor', target_commit_hash, 'HEAD', with_exceptions=False)
    if is_ancestor != 0:
        commits = list(repo.iter_commits(f"{target_commit_hash}..HEAD"))
    else:
        return target_commit_hash
    
    # Reverse to get chronological order (oldest first)
    commits.reverse()

    # Return the first 'num_commits' commits
    return commits[num_commits] if num_commits < len(commits) else commits[-1]


def get_nth_end_commitefore(repo_path, target_commit_hash, num_commits=10):
    repo = git.Repo(repo_path)
    current_commit = target_commit_hash
    try:
        current_commit = repo.commit(target_commit_hash)
    except git.BadName:
        logger.info(f"Error: Commit {target_commit_hash} not found.")
        return None
    
    for _ in range(num_commits):
        if not current_commit.parents:
            logger.info(f"Error: Only {_} ancestors exist before {target_commit_hash}.")
            return None
        current_commit = current_commit.parents[0]  # Follow first parent (linear history)
    
    return current_commit


def checkout_latest_commit(repo_path):
    """
    Checkout the latest commit of the repository's default branch.
    
    Args:
        repo_path (str): Path to the Git repository
    
    Returns:
        str: Latest commit hash
    
    Raises:
        RuntimeError: If checkout fails
        InvalidGitRepositoryError: If path is not a valid repo
    """
    # Open repository
    repo = git.Repo(repo_path)
    repo.git.reset('--hard')
    repo.git.clean('-fdx')
    
    # Ensure we have latest remote data
    if 'origin' in repo.remotes:
        repo.remotes.origin.fetch()
    
    # Get default branch name (e.g., 'main', 'master')
    default_branch = repo.remotes.origin.refs['HEAD'].ref.remote_head
    
    # Checkout default branch and reset to latest
    repo.git.checkout(default_branch)
    repo.git.reset('--hard', f'origin/{default_branch}')
    
    return repo.head.commit.hexsha

def find_matching_commit(repo1_path: str,
                         repo2_path: str,
                         repo1_commit: str,
                         mon: int) -> str | None:
    """
    Given two local Git repos and a commit SHA in repo1, find the commit in
    repo2 whose timestamp is the latest one on or before the timestamp of
    repo1_commit.
    """
    # 1. Open repo1 and get the specified commit
    repo1 = git.Repo(repo1_path)
    commit1 = repo1.commit(repo1_commit)

    # 2. Extract its committed_datetime
    #    This is a timezone-aware datetime.datetime
    commit_time: datetime = commit1.committed_datetime

    # 3. Open repo2 and run `git log`
    repo2 = git.Repo(repo2_path)
    iso_time = commit_time.isoformat()
    iso_next = (commit_time + timedelta(days=30*mon)).isoformat()
    commits = list(repo2.iter_commits('--all', reverse=True))  # oldest to newest
    for commit in commits:
        commit_time = commit.committed_datetime.isoformat()
        if commit_time > iso_next:
            return commit.hexsha
    return False


if __name__ == "__main__":
    # python3 script/buildAndtest.py --bug  ~/tasks-simple/c-blosc2/ --repo /home/user/tasks-git/c-blosc2/ --target c-blosc2 --mode test &> /home/user/log/c-blosc2_test_log
    parser = argparse.ArgumentParser()
    parser.add_argument("--bug", help="Path to the folder")
    parser.add_argument("--repo", help="Path to the repository")
    parser.add_argument("--target", help="Name of the target")
    parser.add_argument("--mode", choices=["build", "test", "both"], default="both",
                       help="Specify the operation mode: 'build' for building only, 'test' for testing only, or 'both' for both operations")
    args = parser.parse_args()
    target = args.target
    current_file_path = os.path.dirname(os.path.abspath(__file__))
    oss_fuzz_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'oss-fuzz')
    log_path = os.getenv('LOG_PATH')
    if not log_path:
        logger.error("Environment variable 'LOG_PATH' is not set. Run source setenv.sh first. Exiting.")
        exit(1)
    storage_path = os.getenv('STORAGE_PATH')
    if not storage_path:
        logger.error("Environment variable 'STORAGE_PATH' is not set. Run source setenv.sh first. Exiting.")
        exit(1)
    target_storage_path = os.path.join(storage_path, target)
    
    repo_path = args.repo
    bug_path = args.bug
    first_commit, lastest_commit = git_first_last_commit(bug_path)
    checkout_latest_commit(repo_path)
    checkout_latest_commit(oss_fuzz_path)
    
    first_build_commit = first_commit
    last_build_commit = lastest_commit

    commits = get_commits_between(repo_path, first_build_commit, last_build_commit)
    logger.info(f'from {commits[0]} to {commits[-1]}')
    logger.info(len(commits))

    if args.mode in ["build", "both"]:
        # Save build information to CSV
        build_csv_path = os.path.join(log_path, f"{target}_builds.csv")
        
        with open(build_csv_path, mode='w', newline='') as build_csv_file:
            build_writer = csv.writer(build_csv_file)
            
            # Write header if file doesn't exist
            build_writer.writerow(['target', 'commit_id', 'oss_fuzz_commit', 'sanitizer'])
            for commit in commits:  # from latest to old
                do_bug_build(repo_path, bug_path, commit, 1, build_writer)
        
    
    if args.mode in ["test", "both"]:
        test_csv_file_path = os.path.join(log_path, target + '.csv')
        test_csv_file = open(test_csv_file_path, mode='w', newline='')
        test_writer = csv.writer(test_csv_file)

        json_files = glob.glob(os.path.join(bug_path, '**', 'bug_info.json'), recursive=True)
        sorted_json_files = sorted(json_files)
        csv_header = ['commit id']
        for json_file_path in sorted_json_files:
            dir_path = os.path.dirname(json_file_path)
            testcases_folder_path = os.path.join(dir_path, "testcases")
            with open(json_file_path) as f:
                data = json.load(f)
            for bug_id, bug_info in data.items():
                csv_header.append(bug_id)
        csv_header.append('poc count')
        test_writer.writerow(csv_header)  # Write the header
        
        for commit in commits: # from lastest to old
            do_bug_test(repo_path, bug_path, commit, test_writer, sorted_json_files)
        test_csv_file.close()