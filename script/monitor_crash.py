#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import time
import shutil
from pathlib import Path
import threading
import queue
import re
import argparse

from read_func_trace import load_signature_changes

SIGNATURE_CACHE = {}
SIGNATURE_DIR = Path(__file__).resolve().parent.parent / "data" / "signature_change_list"
TARGET_CRASH_DIR = Path("/data/target_crashes")
SIGNATURE_OVERRIDE = None
REFERENCE_PATTERNS = []
BUG_ID = "unknown"

# Queue for new crash files that need to be analyzed
crash_queue = queue.Queue()

def _next_target_crash_path(directory, bug_id):
    """Return a unique crash file path in the target directory for the given bug."""
    base_name = f"crash-{bug_id}"
    candidate = directory / base_name
    counter = 1
    while candidate.exists():
        candidate = directory / f"{base_name}-{counter}"
        counter += 1
    return candidate


def analyze_crash_file(crash_file, target_crashes_dir):
    """Run the crash file through the fuzzer to get and analyze ASAN report."""
    print(f"Analyzing crash file: {crash_file}")
    
    # Create a temporary file to capture the ASAN report
    log_file = tempfile.mktemp()
    
    try:
        # Run the fuzzer with the crash file as input (without -ignore_crashes)
        cmd = [
            f"/out/{args.fuzzer}",
            "-runs=1",  # Run exactly once
            crash_file
        ]
        
        # Capture the ASAN report
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=30  # Timeout after 30 seconds
        )
        
        # Save the output
        with open(log_file, 'w') as f:
            f.write(result.stdout)
        
        # Check if this crash matches our target stack trace
        if check_stack_trace(log_file):
            print(f"\n[!] Found target crash: {crash_file}")
            
            # Move the crash file to target directory, renaming to include bug_id
            target_file = _next_target_crash_path(target_crashes_dir, BUG_ID)
            shutil.move(crash_file, target_file)
            
            # Also save the ASAN report
            report_file = Path(f"{target_file}.log")
            with open(report_file, 'w') as f:
                f.write(result.stdout)
            
            print(f"[+] Crash saved to: {target_file}")
            print(f"[+] Report saved to: {report_file}")
            return True
        
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout analyzing crash: {crash_file}")
    except Exception as e:
        print(f"[-] Error analyzing crash: {e}")
    finally:
        # Clean up
        if os.path.exists(log_file):
            os.remove(log_file)
    
    return False

def monitor_output(pipe):
    """Monitor the fuzzer's output for display."""
    try:
        for line in pipe:
            print(line, end='', flush=True)
    except:
        pass

def crash_analyzer_thread(target_crashes_dir, stop_event):
    """Thread that analyzes crashes from the queue."""
    while not stop_event.is_set():
        try:
            # Get a crash file from the queue with timeout
            crash_file = crash_queue.get(timeout=1)
            # Analyze the crash
            if analyze_crash_file(crash_file, target_crashes_dir):
                # If we found a target crash, signal to stop
                stop_event.set()
                print("\n[!] Target stack trace detected! Stopping fuzzer...\n")
                break
            
            # Mark task as done
            crash_queue.task_done()
            
        except queue.Empty:
            # Queue was empty, just continue
            pass
        except Exception as e:
            print(f"[-] Error in analyzer thread: {e}")

def monitor_crashes_thread(artifacts_dir, stop_event):
    """Thread that monitors for new crash files."""
    processed_files = set()
    
    while not stop_event.is_set():
        try:
            # Check for new crash files
            for crash_file in artifacts_dir.glob("crash-*"):
                if crash_file not in processed_files:
                    processed_files.add(crash_file)
                    print(f"[+] New crash found: {crash_file}")
                    crash_queue.put(str(crash_file))
            
            # Short sleep to avoid spinning
            time.sleep(0.5)
            
        except Exception as e:
            print(f"[-] Error in crash monitor thread: {e}")

def _resolve_signature_file(stack_file_path):
    """Return the signature-change file that matches the OSV ID in the stack file."""
    osv_match = re.search(r"(OSV-\d+-\d+)", stack_file_path)
    if not osv_match or not SIGNATURE_DIR.exists():
        return None

    osv_id = osv_match.group(1)
    candidates = sorted(SIGNATURE_DIR.glob(f"{osv_id}_*.json"))

    if not candidates:
        fallback = SIGNATURE_DIR / f"{osv_id}.json"
        if fallback.exists():
            candidates = [fallback]

    if not candidates:
        return None

    commit_tokens = [token.lower() for token in re.findall(r"[0-9a-fA-F]{6,}", stack_file_path)]
    if commit_tokens:
        for token in commit_tokens:
            for candidate in candidates:
                if token in candidate.stem.lower():
                    return candidate

    return candidates[0]

_REVERT_PREFIX_RE = re.compile(r'^__revert_[A-Fa-f0-9]+_')

def _clean_function_name(func):
    """Normalize function names found in stack traces."""
    name = func.split('(')[0].split('+')[0].strip()
    name = _REVERT_PREFIX_RE.sub('', name)
    return name


def _apply_signature_mapping(stack, signature_map):
    """Replace function names in stack using provided signature map."""
    if not signature_map:
        return stack

    updated_stack = []
    for func in stack:
        clean_func = _clean_function_name(func)
        replacements = signature_map.get(clean_func)
        if replacements:
            updated_stack.append(replacements[0])
        else:
            updated_stack.append(clean_func)
    return updated_stack

def _load_signature_map(normalized_path, signature_file=None):
    """Load and cache the signature map for a given stack file."""
    resolved_signature = signature_file or SIGNATURE_OVERRIDE
    if resolved_signature:
        signature_path = Path(resolved_signature).expanduser()
    else:
        signature_path = _resolve_signature_file(normalized_path)

    if not signature_path:
        return {}

    signature_path = str(signature_path)
    if signature_path not in SIGNATURE_CACHE:
        SIGNATURE_CACHE[signature_path] = load_signature_changes(signature_path)
    return SIGNATURE_CACHE.get(signature_path, {})


def extract_function_stack(file_path, signature_file=None, apply_signatures=True, return_signature_map=False):
    stack = []
    normalized_path = os.path.expanduser(file_path[1:]) if file_path.startswith("@") else os.path.expanduser(file_path)
    stack_pattern = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\s]+)", re.IGNORECASE)

    try:
        with open(normalized_path, 'r') as f:
            for line in f:
                match = stack_pattern.search(line)
                if match:
                    stack.append(_clean_function_name(match.group(1)))
                if 'in LLVMFuzzerTestOneInput' in line:
                    break
    except FileNotFoundError:
        print(f"[-] Stack trace file not found: {normalized_path}")
        return stack

    signature_map = _load_signature_map(normalized_path, signature_file)
    processed_stack = _apply_signature_mapping(stack, signature_map) if apply_signatures else stack

    if return_signature_map:
        return processed_stack, signature_map
    return processed_stack

def build_stack_patterns(stack, signature_map):
    """Build per-frame sets of acceptable function names based on signature mappings."""
    patterns = []
    for func in stack:
        clean_func = _clean_function_name(func)
        variants = set([clean_func])
        for replacement in signature_map.get(clean_func, []):
            variants.add(_clean_function_name(replacement))
        patterns.append(variants)
    return patterns


def _stack_matches_patterns(stack, patterns):
    """Check if a stack contains the sequence represented by the pattern list."""
    if not patterns or len(stack) < len(patterns):
        return False

    cleaned_stack = [_clean_function_name(func) for func in stack]
    window = len(patterns)

    for start in range(len(cleaned_stack) - window + 1):
        match = True
        for offset, allowed in enumerate(patterns):
            if cleaned_stack[start + offset] not in allowed:
                match = False
                break
        if match:
            return True
    return False


def check_stack_trace(log_file):
    """Check if the log content contains our reference stack trace."""
    current_stack = extract_function_stack(log_file, apply_signatures=False)
    
    # Check if the stack matches the reference stack
    print('current_stack: ', current_stack)
    return _stack_matches_patterns(current_stack, REFERENCE_PATTERNS)

def main(timeout_hours=10):
    print(f"Starting continuous fuzzer monitoring with {timeout_hours} hours timeout...\n")
    
    # Create a directory for crash artifacts
    artifacts_dir = Path(tempfile.mkdtemp())
    print(f"[+] Saving crash inputs to: {artifacts_dir}")
    
    # Create (or reuse) directory for target crashes
    target_crashes_dir = TARGET_CRASH_DIR
    try:
        target_crashes_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[-] Warning: Could not create target crash directory {target_crashes_dir}: {e}")
    print(f"[+] Saving target crashes to: {target_crashes_dir}")

    # No additional persistence directories needed; TARGET_CRASH_DIR handles storage
    
    # Start the fuzzer with -ignore_crashes=1 to keep it running
    fuzzer_cmd = [
        f"/out/{args.fuzzer}",
        f"-artifact_prefix={artifacts_dir}/",
        "-rss_limit_mb=2560",
        "-timeout=2",
        "/tmpfolder/",
        "-fork=10",  # Fork server mode
        "-ignore_crashes=1",  # Keep running after crashes
        "-use_value_profile=1",
        "-print_final_stats=1",
        "-print_corpus_stats=1",
        "-dict=/data/fuzz.dict"
    ]
    print(' '.join(fuzzer_cmd))
    # Event to signal threads to stop
    stop_event = threading.Event()
    
    # Calculate timeout in seconds
    timeout_seconds = timeout_hours * 60 * 60
    start_time = time.time()
    
    process = None
    try:
        # Start the fuzzer
        process = subprocess.Popen(
            fuzzer_cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        print(f"[+] Fuzzer started with PID: {process.pid}")
        
        # Start a thread to display fuzzer output
        output_thread = threading.Thread(target=monitor_output, args=(process.stdout,))
        output_thread.daemon = True
        output_thread.start()
        
        # Start a thread to monitor for new crashes
        monitor_thread = threading.Thread(
            target=monitor_crashes_thread, 
            args=(artifacts_dir, stop_event)
        )
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start a thread to analyze crashes
        analyzer_thread = threading.Thread(
            target=crash_analyzer_thread,
            args=(target_crashes_dir, stop_event)
        )
        analyzer_thread.daemon = True
        analyzer_thread.start()
        
        print(f"[+] Monitoring for target crashes (timeout: {timeout_hours} hours)...\n")
        
        # Wait for the fuzzer to finish, be stopped, or timeout
        while process.poll() is None and not stop_event.is_set():
            # Check if we've exceeded the timeout
            if time.time() - start_time > timeout_seconds:
                print(f"\n[!] Timeout of {timeout_hours} hour reached. Stopping fuzzer...")
                stop_event.set()
            time.sleep(0.5)
        
        # If stop_event is set but process is still running, terminate it
        if stop_event.is_set() and process.poll() is None:
            print("[+] Terminating fuzzer...")
            process.terminate()
    
    except KeyboardInterrupt:
        print("\n[-] Monitoring stopped by user.")
        stop_event.set()
    
    finally:
        # Make sure the fuzzer is terminated
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        
        # Allow threads to clean up
        stop_event.set()
        time.sleep(1)
        
        # Calculate actual runtime
        runtime_minutes = (time.time() - start_time) / 60
        print(f"\n[+] Fuzzer ran for {runtime_minutes:.2f} minutes")
        print(f"[+] Crash inputs are in: {artifacts_dir}")
        print(f"[+] Target crashes are in: {target_crashes_dir}")
        
        print("[*] Note: Artifact directories were not deleted for your analysis.")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Monitor fuzzing for specific crash patterns')
    parser.add_argument('stack_file', help='Path to a file containing a crash stack trace to extract reference stack')
    parser.add_argument('fuzzer', help='Path to the fuzzer binary to execute')
    parser.add_argument('--run_times', type=int, default=10, help='Number of times to run the monitoring (default: 10)')
    parser.add_argument('--fuzz_time', type=float, default=10.0, help='Per-run fuzzing timeout in hours (default: 10)')
    parser.add_argument('--signature-changes', dest='signature_changes', help='Path to JSON file that maps old function names to new ones')
    args = parser.parse_args()

    SIGNATURE_OVERRIDE = args.signature_changes

    bug_match = re.search(r"(OSV-\d+-\d+)", args.stack_file)
    BUG_ID = bug_match.group(1) if bug_match else "unknown"

    # Set the reference stack trace
    print(f"Extracting function stack from: {args.stack_file}")
    raw_reference_stack, reference_signature_map = extract_function_stack(
        args.stack_file, apply_signatures=False, return_signature_map=True
    )
    REFERENCE_PATTERNS = build_stack_patterns(raw_reference_stack, reference_signature_map)
    print('Bug Stack (original functions):\n', raw_reference_stack)
    
    if len(raw_reference_stack) == 0 or len(REFERENCE_PATTERNS) == 0:
        print("Error: The reference stack trace is empty. Please provide a valid stack trace file.")
        exit(1)

    runs = args.run_times
    runtime_list = []
    
    print(f"Running main() {runs} times...")
    
    for i in range(runs):
        print(f"Run {i+1}/{runs}")
        start_time = time.time()
        main(timeout_hours=args.fuzz_time)
        run_time = time.time() - start_time
        if run_time > 43200:
            print("Time limit reached. Stopping runs.")
            break
        runtime_list.append(run_time)
        print(f"Run {i+1} completed in {run_time:.2f} seconds")
        # Skip cleanup so crash artifacts remain available for inspection
    
    # Sort the list to easily exclude the smallest and largest values
    sorted_numbers = sorted(runtime_list)

    # Remove the first (smallest) and last (largest) elements
    trimmed_list = sorted_numbers[1:-1] if len(sorted_numbers) > 2 else sorted_numbers

    # Calculate the average of the trimmed list
    avg_time = sum(trimmed_list) / len(trimmed_list)
    
    print(f"\nAverage execution time over {runs} runs: {avg_time:.2f} seconds")
    print(f"Execution times: {runtime_list}")
