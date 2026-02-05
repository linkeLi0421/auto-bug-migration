#!/bin/bash
# Python interpreter path (defaults to system python3 if not set)
export LOG_PATH="/users/linke/log"
export STORAGE_PATH="/mnt/nas/linke"
export TESTCASES="/users/linke/oss-fuzz-for-select/pocs/tmp"
export REPO_PATH="/users/linke/tasks-git"
# Separate repo paths for V1 (old commit) and V2 (new commit) source trees
# These are used by the react agent to read source code from both versions
export V1_REPO_PATH="/users/linke/tasks-git-v1"
export V2_REPO_PATH="/users/linke/tasks-git-v2"
export GUMTREE_PATH="/users/linke/gumtree-4.0.0-beta4/bin/gumtree"
export BUGIDS_PATH="/users/linke/oss-fuzz-for-select/osv_projects.json"
export BUGINFO_PATH="/users/linke/oss-fuzz-for-select/osv_testcases_summary.json"
# Number of parallel jobs for multi-agent runs (reduce to avoid OOM)
# Each agent uses ~1.6GB RAM + Docker build uses ~4GB
export REACT_AGENT_JOBS=10
