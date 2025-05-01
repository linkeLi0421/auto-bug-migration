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

# Queue for new crash files that need to be analyzed
crash_queue = queue.Queue()

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
            
            # Copy the crash file to target directory
            target_file = target_crashes_dir / os.path.basename(crash_file)
            shutil.copy2(crash_file, target_file)
            
            # Also save the ASAN report
            report_file = target_crashes_dir / f"{os.path.basename(crash_file)}.log"
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

def extract_function_stack(file_path):
    stack = []

    with open(file_path, 'r') as f:
        for line in f:
            if re.search(r"#\d+", line):
                function_name = ''.join(line.split(' ')[7:-1])
                stack.append(function_name)
            if 'in LLVMFuzzerTestOneInput' in line:
                break
    return stack

def check_stack_trace(log_file):
    """Check if the log content contains our reference stack trace."""
    current_stack = extract_function_stack(log_file)
    
    # Check if the stack matches the reference stack
    print('current_stack: ', current_stack)
    if len(current_stack) >= len(REFERENCE_STACK):
        for i in range(len(current_stack) - len(REFERENCE_STACK) + 1):
            if current_stack[i:i+len(REFERENCE_STACK)] == REFERENCE_STACK:
                return True
    
    return False

def main(timeout_hours=12):
    print(f"Starting continuous fuzzer monitoring with {timeout_hours} hours timeout...\n")
    
    # Create a directory for crash artifacts
    artifacts_dir = Path(tempfile.mkdtemp())
    print(f"[+] Saving crash inputs to: {artifacts_dir}")
    
    # Create a directory for target crashes
    target_crashes_dir = Path(tempfile.mkdtemp())
    print(f"[+] Saving target crashes to: {target_crashes_dir}")
    
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
        
        # Move target crashes to /out directory
        out_target_dir = Path("/data/target_crashes")
        out_target_dir.mkdir(exist_ok=True)
        for target_file in target_crashes_dir.glob("*"):
            dest_file = out_target_dir / target_file.name
            try:
                shutil.copy2(target_file, dest_file)
                print(f"  - Moved target crash {target_file.name}")
            except Exception as e:
                print(f"  - Failed to move target crash {target_file.name}: {e}")
        print(f"[+] All target crashes moved to: {out_target_dir}")
        print("[*] Note: These directories were not deleted for your analysis.")

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Monitor fuzzing for specific crash patterns')
    parser.add_argument('stack_file', help='Path to a file containing a crash stack trace to extract reference stack')
    parser.add_argument('fuzzer', help='Path to the fuzzer binary to execute')
    args = parser.parse_args()

    # Set the reference stack trace
    print(f"Extracting function stack from: {args.stack_file}")
    global REFERENCE_STACK
    REFERENCE_STACK = extract_function_stack(args.stack_file)
    print('Bug Stack:\n', REFERENCE_STACK)
    
    if len(REFERENCE_STACK) == 0:
        print("Error: The reference stack trace is empty. Please provide a valid stack trace file.")
        exit(1)
    
    runs = 10
    runtime_list = []
    
    print(f"Running main() {runs} times...")
    
    for i in range(runs):
        print(f"Run {i+1}/{runs}")
        start_time = time.time()
        main()
        run_time = time.time() - start_time
        if run_time > 43200:
            print("Time limit reached. Stopping runs.")
            break
        runtime_list.append(run_time)
        print(f"Run {i+1} completed in {run_time:.2f} seconds")
        # Clean up files in /tmpfolder/ except testcase files
        print("Cleaning up /tmpfolder/ directory...")
        tmpfolder = Path("/tmpfolder/")
        if tmpfolder.exists() and tmpfolder.is_dir():
            for file_path in tmpfolder.glob("*"):
                if file_path.is_file() and not file_path.name.startswith("testcase"):
                    try:
                        file_path.unlink()
                    except Exception as e:
                        print(f"Failed to remove {file_path}: {e}")
            print("Cleanup completed")
        else:
            print("Warning: /tmpfolder/ directory not found")
    
    # Sort the list to easily exclude the smallest and largest values
    sorted_numbers = sorted(runtime_list)

    # Remove the first (smallest) and last (largest) elements
    trimmed_list = sorted_numbers[1:-1]

    # Calculate the average of the trimmed list
    avg_time = sum(trimmed_list) / len(trimmed_list)
    
    print(f"\nAverage execution time over {runs} runs: {avg_time:.2f} seconds")
    print(f"Execution times: {runtime_list}")