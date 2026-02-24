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
import sys

sanitizer_mapping = {
    'address (ASAN)': 'address'
}

os.environ["ASAN_OPTIONS"] = "detect_leaks=0"

# Use PYTHON_PATH env var if set, otherwise default to 'python3'
py3 = os.getenv('PYTHON_PATH', 'python3')

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)


def _tail_text(text: str, max_lines: int = 80, max_chars: int = 12000) -> str:
    """Return a bounded tail of command output for readable logs."""
    if not text:
        return ''

    lines = text.splitlines()
    truncated_lines = False
    if len(lines) > max_lines:
        lines = lines[-max_lines:]
        truncated_lines = True

    joined = '\n'.join(lines)
    truncated_chars = False
    if len(joined) > max_chars:
        joined = joined[-max_chars:]
        truncated_chars = True

    prefix = ''
    if truncated_lines or truncated_chars:
        prefix = '[output truncated to tail]\n'
    return prefix + joined


def get_folder_names(directory):
    folder_names = []
    for item in os.listdir(directory):
        item_path = os.path.join(directory, item)
        if os.path.isdir(item_path):
            folder_names.append(item)
    return folder_names


def get_commit_timestamp(repo_path: str, commit_hash: str) -> int:
    repo = git.Repo(repo_path)
    # Resolve short/ambiguous commit to full hash first
    full_hash = resolve_commit_hash(repo_path, commit_hash)
    ts = repo.git.show("-s", "--format=%ct", full_hash).strip()
    return int(ts)


def resolve_commit_hash(repo_path: str, commit_hash: str) -> str:
    """
    Resolve a short or potentially ambiguous commit hash to its full form.
    
    Args:
        repo_path: Path to the git repository
        commit_hash: Short or full commit hash
        
    Returns:
        Full 40-character commit hash
        
    Raises:
        ValueError: If the commit hash is ambiguous or not found
    """
    repo = git.Repo(repo_path)
    try:
        # Try to get the full commit hash using git rev-parse
        full_hash = repo.git.rev_parse("--verify", f"{commit_hash}^{{commit}}")
        return full_hash.strip()
    except GitCommandError as e:
        # If ambiguous or not found, provide a helpful error message
        error_msg = str(e)
        if "ambiguous" in error_msg.lower():
            # Try to get candidates using git rev-list
            try:
                candidates = repo.git.rev_list("--all", "--abbrev-commit", 
                                               f"--grep={commit_hash}", max_count=10)
                if not candidates:
                    # Try with git log on all refs
                    result = subprocess.run(
                        ["git", "-C", repo_path, "log", "--all", "--oneline", 
                         "--no-walk", "--abbrev-commit"],
                        capture_output=True, text=True
                    )
                    lines = result.stdout.strip().split('\n')
                    matches = [l.split()[0] for l in lines if l.startswith(commit_hash)]
                    if matches:
                        raise ValueError(
                            f"Commit hash '{commit_hash}' is ambiguous. "
                            f"Candidates: {', '.join(matches)}. "
                            f"Please use a longer prefix or the full hash."
                        )
            except Exception:
                pass
            raise ValueError(
                f"Commit hash '{commit_hash}' is ambiguous. "
                f"Please use a longer prefix (at least 8-12 characters) or the full 40-character hash."
            )
        raise ValueError(f"Commit hash '{commit_hash}' not found in repository: {error_msg}")


# Base-builder images sorted by date (oldest first)
# Each entry: (date_str, digest, openssl_version)
BASE_BUILDER_IMAGES = [
    ('2019-05-13', 'sha256:bd7e28de7a1f69d828e94220a20f69692d2e3173f0908fbf6067fabdc7b8b947', '1.0.0'),  # testing
    ('2021-08-23', 'sha256:859b694f542dbde5d0cf5aed20668eb201d9fbd93a08c6c5bb5da2347560169f', '1.0.0'),  # xenial
    ('2022-07-30', 'sha256:5b714b0eb717ab8ee6129cb37adb7db76761cb93273d332d29afa62a4cdc7ed3', '1.1'),    # test
    ('2022-08-11', 'sha256:2f5cdbf10998fa95559dbf971e11504a51c5e2a2557aa548ad1c3ac2154934e7', '1.1'),    # old
    ('2022-10-31', 'sha256:4af219498733484fcec27ca3b6ceda96ed38aecb83fcd47f930811f5d5fad1b9', '1.1'),    # introspector
]

# Base-runner images sorted by date (for reproduce compatibility)
# Each entry: (date_str, digest, openssl_version)
# Note: These SHAs are from OSS-Fuzz gcr.io/oss-fuzz-base/base-runner images
# Verify and update these digests as needed for your specific use case
BASE_RUNNER_IMAGES = [
    ('2019-12-01', 'sha256:caba4ce727f6dfe43a68b4554efdd617052ad3b634bbc6e28b97f6e3ca1a92ac', '1.0.0'),  # Dec 2019
    ('2020-01-07', 'sha256:88ceb7b782d6e1e4a126bce5d751c7698493616f006b4b4f5a492f6e0ed0da3e', '1.0.0'),  # Jan 2020, testing
    ('2020-11-01', 'sha256:5aeba6054f1fc806d3fd9a4934e4dfd9092615c8777ed6e5cff5993ff05f4008', '1.0.0'),  # Nov 2020
    ('2021-08-23', 'sha256:83dc2104f6325551cf7b2dd928b63a3545bd283d00c3179827dcd963cff7764b', '1.0.0'),  # Mid 2021, approx xenial timeframe
    ('2022-07-30', 'sha256:3a190cfbada024425c48aebd06558a0e974e819f69625e886b1fe2b1a138064d', '1.1'),    # Mid 2022, test
    # Add more recent images as needed:
    # To find the correct SHA for a specific date, check:
    # - OSS-Fuzz build logs at https://oss-fuzz-build-logs.storage.googleapis.com/
    # - Git history: cd oss-fuzz && git log --grep="base-runner" --since="2022-01-01"
    # - Docker inspect: docker pull gcr.io/oss-fuzz-base/base-runner@sha256:... && docker inspect ...
]


def get_latest_images_before_year(year: int) -> tuple:
    """
    Get the latest base-builder and base-runner image digests before a given year.

    Returns:
        (builder_digest, runner_digest) tuple of sha256 digest strings.
    """
    cutoff = f'{year}-01-01'
    builder = None
    for date_str, digest, _ in BASE_BUILDER_IMAGES:
        if date_str < cutoff:
            builder = digest
    if builder is None:
        builder = BASE_BUILDER_IMAGES[0][1]

    runner = None
    for date_str, digest, _ in BASE_RUNNER_IMAGES:
        if date_str < cutoff:
            runner = digest
    if runner is None:
        runner = BASE_RUNNER_IMAGES[0][1]

    return builder, runner


def get_ossfuzz_commit_before_year(oss_fuzz_path: str, year: int) -> str:
    """
    Get the latest oss-fuzz commit before a given year.

    Args:
        oss_fuzz_path: Path to the oss-fuzz repository
        year: The year cutoff (will find latest commit before Jan 1 of this year)

    Returns:
        The commit hash of the latest oss-fuzz commit before the given year.
    """
    repo = git.Repo(oss_fuzz_path)
    cutoff_date = datetime(year, 1, 1)

    # Get all commits in reverse chronological order
    commits = list(repo.iter_commits('--all'))

    # Find the latest commit before the cutoff date
    for commit in commits:
        commit_time = commit.committed_datetime.replace(tzinfo=None)
        if commit_time < cutoff_date:
            return commit.hexsha

    # If no commit found before cutoff, return the oldest commit
    return commits[-1].hexsha if commits else None


def get_base_builder_for_date(commit_timestamp: int) -> str:
    """
    Get the appropriate base-builder image digest for a given commit timestamp.
    Prefer the closest image at or after the commit date (same-era toolchain),
    and fall back to the latest image before the commit date when needed.
    """
    commit_date = datetime.fromtimestamp(commit_timestamp).date()
    latest_past = None
    nearest_future = None

    for date_str, digest, _ in BASE_BUILDER_IMAGES:
        image_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if image_date <= commit_date:
            latest_past = digest
            continue
        nearest_future = digest
        break

    if nearest_future:
        return nearest_future
    if latest_past:
        return latest_past
    return BASE_BUILDER_IMAGES[0][1]


def get_base_runner_for_date(commit_timestamp: int) -> str:
    """
    Get the appropriate base-runner image digest for a given commit timestamp.
    Prefer the closest image at or after the commit date (same-era runtime),
    and fall back to the latest image before the commit date when needed.
    """
    commit_date = datetime.fromtimestamp(commit_timestamp).date()
    latest_past = None
    nearest_future = None

    for date_str, digest, _ in BASE_RUNNER_IMAGES:
        image_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        if image_date <= commit_date:
            latest_past = digest
            continue
        nearest_future = digest
        break

    if nearest_future:
        return nearest_future
    if latest_past:
        return latest_past
    return BASE_RUNNER_IMAGES[0][1]


def git_first_last_commit(target_bug_ids, bug_infos):
    # Initialize variables to store the oldest fixed and newest fixed commits
    oldest_introduced_commit = None
    newest_fixed_commit = None
    oldest_time = None
    newest_time = None
    
    for bug_id in target_bug_ids:
        bug_info = bug_infos[bug_id]
        if not bug_info["fixed"]:
            continue
        introduced_timestamp = get_commit_timestamp(repo_path, bug_info["introduced"])
        fixed_timestamp = get_commit_timestamp(repo_path, bug_info["fixed"])

        # Update the oldest introduced commit
        if oldest_time is None or fixed_timestamp < oldest_time:
            oldest_introduced_commit = bug_info["introduced"]
            oldest_time = fixed_timestamp

        # Update the newest fixed commit
        if newest_time is None or fixed_timestamp > newest_time:
            newest_fixed_commit = bug_info["fixed"]
            newest_time = fixed_timestamp

    repo = git.Repo(repo_path)
    commit = repo.commit(oldest_introduced_commit)
    oldest_time = None
    for idx, p in enumerate(commit.parents, start=1):
        commit_time = p.committed_datetime
        if oldest_time is None or commit_time < oldest_time:
            start_commit = p.hexsha
            oldest_time = commit_time
    
    return start_commit, newest_fixed_commit


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


def do_bug_build(target_path, target_bug_ids, bug_infos, commit_id, month, build_writer,
                  fixed_builder=None, fixed_runner=None, fixed_ossfuzz_commit=None,
                  max_retry_months=7, retry_month_step=1):
    '''
    Run helper.py build_image and build_fuzzers
    '''
    if fixed_ossfuzz_commit:
        oss_fuzz_commit = fixed_ossfuzz_commit
    else:
        if month > max_retry_months:
            logger.info(f"Reached retry month limit ({max_retry_months}) for {target}-{commit_id}; stop trying newer oss-fuzz commits.")
            return f"Reached retry month limit ({max_retry_months})"
        oss_fuzz_commit = find_matching_commit(target_path, oss_fuzz_path, commit_id, month)
    if not oss_fuzz_commit:
        # commit timestamp add month is newer than Head in oss-fuzz, so we can't find a version of oss-fuzz to build
        return "No appropriate version os oss-fuzz, stop try newer. Try build next version of target project"
        
    os.chdir(oss_fuzz_path)
    subprocess.run(["git", "clean", "-fdx"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, encoding='utf-8')
    subprocess.run(["git", "checkout", '-f', oss_fuzz_commit], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, encoding='utf-8')
    logger.info(f"Building {target} with oss-fuzz in commit {oss_fuzz_commit} (month = {month})")
    
    # Get commit timestamp for automatic image selection
    oss_fuzz_timestamp = get_commit_timestamp(oss_fuzz_path, oss_fuzz_commit)
    logger.info(f"OSS-Fuzz commit timestamp: {datetime.fromtimestamp(oss_fuzz_timestamp).strftime('%Y-%m-%d')}")

    # Remove --depth 1 from Dockerfile to ensure full git history
    target_dockerfile_path = f'{oss_fuzz_path}/projects/{target}/Dockerfile'
    if not os.path.exists(target_dockerfile_path):
        logger.error(f"Target Dockerfile not found: {target_dockerfile_path}")
        if fixed_ossfuzz_commit:
            return "Target Dockerfile missing in fixed oss-fuzz commit."
        return do_bug_build(target_path, target_bug_ids, bug_infos, commit_id,
                            month + retry_month_step, build_writer,
                            fixed_builder=fixed_builder,
                            fixed_runner=fixed_runner,
                            fixed_ossfuzz_commit=fixed_ossfuzz_commit,
                            max_retry_months=max_retry_months,
                            retry_month_step=retry_month_step)

    with open(target_dockerfile_path, 'r') as dockerfile:
        dockerfile_content = dockerfile.read()
    updated_content = dockerfile_content.replace('--depth 1', '')
    updated_content = updated_content.replace('--depth=1', '')
    with open(target_dockerfile_path, 'w') as dockerfile:
        dockerfile.write(updated_content)

    sanitizers = set()
    archs = set()
    for bug_id in target_bug_ids:
        bug_info = bug_infos[bug_id]
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

            if fixed_builder:
                image_args = ["--runner-image", fixed_builder]
            else:
                image_args = ["--runner-image", "auto", "--commit-date", str(oss_fuzz_timestamp)]

            cmd = [
                py3, f"{current_file_path}/fuzz_helper.py", "build_version", "--commit", commit_id, "--sanitizer", sanitizer, "--architecture", arch,
                *image_args,
                target
            ]

            logger.info(' '.join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True)
            if "Sanitizer" not in result.stderr+result.stdout and\
                any(error_pattern in result.stderr or error_pattern in result.stdout for error_pattern in [
                "Building fuzzers failed",
                "Docker build failed",
                "clang++: error:",
                "g++: error:",
                "cmake: error:",
                "fatal error:",
                "undefined reference to",
                "cannot find -l",
                "No such file or directory",
                "error: git",
                "error: 'struct",
                "error: conflicting types",
                "error: invalid conversion",
                "make: *** [Makefile:",
                "ninja: build stopped:",
                "Compilation failed",
                "failed with exit status"
            ]) or result.returncode != 0:
                logger.info(f"Failed to build {target}-{commit_id} with sanitizer {sanitizer} {arch}, will try newer oss-fuzz again.")
                if fixed_ossfuzz_commit:
                    return "Build failed with fixed oss-fuzz commit, no retry."
                return do_bug_build(target_path, target_bug_ids, bug_infos, commit_id,
                                    month + retry_month_step, build_writer,
                                    fixed_builder=fixed_builder,
                                    fixed_runner=fixed_runner,
                                    fixed_ossfuzz_commit=fixed_ossfuzz_commit,
                                    max_retry_months=max_retry_months,
                                    retry_month_step=retry_month_step)
            else:
                # build finish here
                logger.info(f"Build finished for {target}-{commit_id} with sanitizer {sanitizer} and architecture {arch}.")
                # Create directory for storing output files if it doesn't exist
                os.makedirs(target_storage_path, exist_ok=True)
                # Create the destination directory if it doesn't exist
                dest_path = os.path.join(target_storage_path, target + '-' + commit_id + '-' + sanitizer + arch_str)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                subprocess.run(["mv", "-f", "-T", oss_fuzz_path + "/build/out/" + target, dest_path], encoding='utf-8')
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
    try:
        start_commit = repo.commit(commit_id)
        end_commit = repo.commit(ancestor_id)
    except (ValueError, BadName):
        logger.warning(f"Could not resolve commits for ancestry check: {commit_id} / {ancestor_id}")
        return False
    common_ancestor = repo.git.merge_base(start_commit, end_commit)
    if common_ancestor == end_commit.hexsha:
        return True
    else:
        return False

def do_bug_test(target_path, commit_id, writer, filter_bug_ids, bug_infos,
                fixed_runner=None):
    '''
    Run helper.py reproduce
    '''
    commit_time = get_commit_timestamp(target_path, commit_id)
    
    row = [commit_id]
    bug_exist_count = 0
    testcases_env = os.getenv('TESTCASES', '')
    
    for bug_id in filter_bug_ids:
        bug_info = bug_infos[bug_id]
        poc_path = os.path.join(testcases_env, 'testcase-' + bug_id)
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

        # Use fixed runner image or auto-select based on commit time
        if fixed_runner:
            image_args = ['--runner-image', fixed_runner]
        else:
            image_args = ['--runner-image', 'auto', '--commit-date', str(commit_time)]

        cmd = [
            py3, f'{current_file_path}/fuzz_helper.py', 'reproduce', '--fuzzer_path', source_dir,
            *image_args,
            target, fuzz_target, poc_path
        ]
        try:
            logger.info(' '.join(cmd))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",   # or "ignore"
                timeout=60,
            )
            if 'sanitizer' in result.stderr.lower()+result.stdout.lower() and sanitizer in result.stderr.lower()+result.stdout.lower():
                confidence_level = '0.5'
                if crash_type.lower() in result.stderr.lower()+result.stdout.lower():
                    confidence_level = '1'
                # poc works
                if bug_exist:
                    row.append(f'{confidence_level}|1')
                else:
                    row.append(f'{confidence_level}|0')
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


def fetch_missing_commits(repo_path, bug_ids, bug_infos):
    """Fetch any introduced/fixed commits missing from the local repo."""
    repo = git.Repo(repo_path)
    for bug_id in bug_ids:
        bug_info = bug_infos.get(bug_id, {})
        for sha in [bug_info.get("introduced"), bug_info.get("fixed")]:
            if not sha:
                continue
            try:
                repo.commit(sha)
            except (ValueError, BadName):
                logger.info(f"Fetching missing commit {sha[:12]} for {bug_id}...")
                try:
                    repo.remotes.origin.fetch(sha)
                except GitCommandError:
                    logger.warning(f"Could not fetch {sha[:12]} for {bug_id}, skipping.")


def get_commits_for_bug_windows(repo_path, bug_ids, bug_infos):
    """
    Collect all commits that lie between each bug's introduced and fixed commits.

    Returns a chronologically sorted list with duplicates removed.
    """
    repo = git.Repo(repo_path)
    commit_times = {}

    for bug_id in bug_ids:
        bug_info = bug_infos.get(bug_id, {})
        introduced = bug_info.get("introduced")
        fixed = bug_info.get("fixed")

        if not introduced or not fixed:
            logger.info(f"Skip bug {bug_id}: missing introduced/fixed info.")
            continue

        try:
            bug_commits = get_commits_between(repo_path, introduced, fixed)
            logger.info(f"Collected {len(bug_commits)} commits between introduced/fixed windows for bug {bug_id}.")
        except ValueError as exc:
            logger.info(f"Skip bug {bug_id}: {exc}")
            continue

        if fixed not in bug_commits:
            bug_commits.append(fixed)
        if introduced not in bug_commits:
            bug_commits.insert(0, introduced)

        for sha in bug_commits:
            if sha not in commit_times:
                commit_times[sha] = repo.commit(sha).committed_datetime

    commits = [sha for sha, _ in sorted(commit_times.items(), key=lambda item: item[1])]
    return commits


if __name__ == "__main__":
    # python3 script/buildAndtest.py --repo /home/user/tasks-git/c-blosc2/ --target c-blosc2 --mode test &> /home/user/log/c-blosc2_test_log
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", help="Path to the repository")
    parser.add_argument("--target", help="Name of the target")
    parser.add_argument("--mode", choices=["build", "test", "both"], default="both",
                       help="Specify the operation mode: 'build' for building only, 'test' for testing only, or 'both' for both operations")
    parser.add_argument("--fuzzer", help = "Harness to test")
    parser.add_argument("--commit-step", type=int, default=1,
                       help="Sample commits by stride. Example: --commit-step 10 tests every 10th commit.")
    parser.add_argument("--max-retry-months", type=int, default=7,
                       help="Maximum month offset to try for newer oss-fuzz commits after build failures.")
    parser.add_argument("--retry-month-step", type=int, default=1,
                       help="Month increment per retry when selecting newer oss-fuzz commits.")
    parser.add_argument("--fixed-image", type=int, metavar="YEAR", default=None,
                       help="Use fixed Docker images: latest base-builder/base-runner before YEAR (e.g., 2023)")
    args = parser.parse_args()
    if args.commit_step <= 0:
        parser.error("--commit-step must be >= 1")
    if args.max_retry_months <= 0:
        parser.error("--max-retry-months must be >= 1")
    if args.retry_month_step <= 0:
        parser.error("--retry-month-step must be >= 1")
    target = args.target

    current_file_path = os.path.dirname(os.path.abspath(__file__))
    oss_fuzz_path = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'oss-fuzz')

    # Resolve fixed image digests and oss-fuzz commit if requested
    fixed_builder = None
    fixed_runner = None
    fixed_ossfuzz_commit = None
    if args.fixed_image:
        fixed_builder, fixed_runner = get_latest_images_before_year(args.fixed_image)
        fixed_ossfuzz_commit = get_ossfuzz_commit_before_year(oss_fuzz_path, args.fixed_image)
        logger.info(f"Using fixed images and oss-fuzz (latest before {args.fixed_image}):")
        logger.info(f"  base-builder: {fixed_builder}")
        logger.info(f"  base-runner:  {fixed_runner}")
        logger.info(f"  oss-fuzz:     {fixed_ossfuzz_commit}")
    log_path = os.getenv('LOG_PATH')
    if not log_path:
        logger.error("Environment variable 'LOG_PATH' is not set. Run source setenv.sh first. Exiting.")
        exit(1)
    storage_path = os.getenv('STORAGE_PATH')
    if not storage_path:
        logger.error("Environment variable 'STORAGE_PATH' is not set. Run source setenv.sh first. Exiting.")
        exit(1)
    target_storage_path = os.path.join(storage_path, target)
    
    arch = 'x86_64' # We have enough x86 bugs
    repo_path = args.repo
    bug_ids_path = os.getenv("BUGIDS_PATH")
    bug_info_path = os.getenv("BUGINFO_PATH")

    with open(bug_ids_path, "r") as f:
        bug_ids = json.load(f)
        target_bug_ids = bug_ids[target]
    with open(bug_info_path, "r") as f:
        bug_infos = json.load(f)
    
    filter_bug_ids = []
    for bug_id in target_bug_ids:
        # if '2020' not in bug_id and '2021' not in bug_id and '2022' not in bug_id:
        #     continue
        if bug_id not in bug_infos:
            continue
        bug_info = bug_infos[bug_id]
        if 'i386' in bug_info['reproduce']['job_type']:
            continue
        if bug_info['reproduce']['fuzz_target'] != args.fuzzer:
            continue
        filter_bug_ids.append(bug_id)
    
    checkout_latest_commit(repo_path)
    checkout_latest_commit(oss_fuzz_path)
    fetch_missing_commits(repo_path, filter_bug_ids, bug_infos)

    commits = get_commits_for_bug_windows(repo_path, filter_bug_ids, bug_infos)
    if not commits:
        logger.error("No commits found between introduced and fixed for the selected bugs.")
        sys.exit(1)
    logger.info(f'Collected {len(commits)} commits between introduced/fixed windows.')
    logger.info(f'Range preview: {commits[0]} -> {commits[-1]}')
    if args.commit_step > 1:
        sampled_commits = commits[::args.commit_step]
        if commits[-1] not in sampled_commits:
            sampled_commits.append(commits[-1])
        logger.info(f'Sampling commits with step={args.commit_step}: {len(commits)} -> {len(sampled_commits)} commits.')
        commits = sampled_commits
        logger.info(f'Sampled range preview: {commits[0]} -> {commits[-1]}')

    if args.mode in ["build", "both"]:
        # Save build information to CSV
        build_csv_path = os.path.join(log_path, f"{target}_builds.csv")
        
        with open(build_csv_path, mode='w', newline='') as build_csv_file:
            build_writer = csv.writer(build_csv_file)
            
            # Write header if file doesn't exist
            build_writer.writerow(['target', 'commit_id', 'oss_fuzz_commit', 'sanitizer'])
            for commit in commits:  # from latest to old
                do_bug_build(repo_path, filter_bug_ids, bug_infos, commit, 1, build_writer,
                             fixed_builder=fixed_builder, fixed_runner=fixed_runner,
                             fixed_ossfuzz_commit=fixed_ossfuzz_commit,
                             max_retry_months=args.max_retry_months,
                             retry_month_step=args.retry_month_step)
        
    
    if args.mode in ["test", "both"]:
        test_csv_file_path = os.path.join(log_path, target + '.csv')
        test_csv_file = open(test_csv_file_path, mode='w', newline='')
        test_writer = csv.writer(test_csv_file)

        csv_header = ['commit id']
        for bug_id in filter_bug_ids:
            bug_info = bug_infos[bug_id]
            csv_header.append(bug_id)
        csv_header.append('poc count')
        test_writer.writerow(csv_header)  # Write the header
        
        for commit in commits: # from lastest to old
            do_bug_test(repo_path, commit, test_writer, filter_bug_ids, bug_infos,
                        fixed_runner=fixed_runner)
        test_csv_file.close()
