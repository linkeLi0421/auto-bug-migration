# Plan: Add Codex Interactive Mode Option

## Context

Currently, the Codex CLI is always invoked in **exec mode**:
```
codex exec --dangerously-bypass-approvals-and-sandbox <prompt> --json
```
This is non-interactive, single-shot — prompt passed as CLI arg, agent runs to completion without a TUI.

The user wants an option to use Codex in **interactive mode** (`codex <prompt> ...`), which launches the TUI and behaves as if a human is at the terminal — enabling multi-turn interaction, session persistence, and potentially different agent behavior.

### Key differences between modes

| Aspect | `exec` (current) | `interactive` (new) |
|--------|------------------|---------------------|
| Command | `codex exec <prompt>` | `codex <prompt>` |
| TUI | No | Yes (needs TTY) |
| Output | JSONL via `--json` | TUI output (no `--json`) |
| Docker exec | `docker exec container bash -c "..."` | `docker exec -it container bash -c "..."` |
| Output capture | `subprocess.run(capture_output=True)` | `subprocess.call()` (streams to terminal) |
| Token tracking | Parsed from JSONL | Not available |

## Changes

### 1. Add `--codex-mode` CLI argument

Add to all four entry points with choices `exec` (default) and `interactive`:

- **`script/bug_transplant.py`** — `build_parser()` (~line 1053)
- **`script/bug_transplant_batch.py`** — argparse section (~line 592), propagate to child process (~line 388)
- **`script/bug_transplant_merge.py`** — argparse section (~line 2840)
- **`script/bug_transplant_merge_offline.py`** — argparse section (~line 1033)

### 2. Modify `CODEX_CONFIG` in `bug_transplant.py` (~line 58)

Add a second `run_cmd` template for interactive mode:

```python
CODEX_CONFIG = {
    ...
    "run_cmd": "codex exec --dangerously-bypass-approvals-and-sandbox {prompt}",
    "run_cmd_interactive": "codex --dangerously-bypass-approvals-and-sandbox {prompt}",
    ...
}
```

### 3. Update command builders to respect mode

Three functions need updating:

- **`build_codex_command()`** (`bug_transplant.py:82`) — add `mode` param, select `run_cmd` or `run_cmd_interactive`, skip `--json` in interactive mode
- **`_build_agent_command()`** (`bug_transplant.py:967`) — read `args.codex_mode`, same logic
- **`_build_agent_cmd()`** (`bug_transplant_merge_offline.py:179`) — add `codex_mode` param, same logic

### 4. Add `_exec_interactive()` in `bug_transplant.py`

New function alongside `_exec_capture()` (~line 998) for TTY-based execution:

```python
def _exec_interactive(container_name: str, command: str, timeout: int = 3600) -> int:
    """docker exec -it, streaming output to terminal. Returns exit code."""
    cmd = ["docker", "exec", "-it", container_name, "bash", "-c", command]
    try:
        return subprocess.call(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error("Command timed out after %ds", timeout)
        return 124
```

### 5. Update `run_agent_in_container()` (`bug_transplant.py:555`)

At the agent invocation (~line 690-700):

- Check `args.codex_mode`
- If `interactive`: use `_exec_interactive()`, skip token tracking, save a note that output was streamed to terminal
- If `exec` (default): current behavior unchanged

### 6. Update merge script agent invocations

In `bug_transplant_merge.py` and `bug_transplant_merge_offline.py`, the agent is invoked via `_exec_capture()` inside Docker. For interactive mode:
- Use `_exec_interactive()` (or equivalent `docker exec -it`)
- Skip `--json` flag and token tracking when interactive

### 7. Graceful token tracking skip

Wherever `_usage_tracker.log_usage()` is called, guard with mode check:
```python
if codex_mode != "interactive" and _usage_tracker:
    _usage_tracker.log_usage(...)
```

## Files to modify

1. `script/bug_transplant.py` — CODEX_CONFIG, build_codex_command, _build_agent_command, _exec_interactive (new), run_agent_in_container, build_parser
2. `script/bug_transplant_batch.py` — argparse, child process propagation
3. `script/bug_transplant_merge.py` — argparse, agent invocation functions
4. `script/bug_transplant_merge_offline.py` — _build_agent_cmd, argparse

## Trade-offs

- Interactive mode **won't capture output** to `claude_output.txt` (streams to terminal instead)
- Interactive mode **won't track token costs** (no JSONL output available)
- Default remains `exec` mode — fully backward compatible

## Verification

1. `--help` on all four scripts shows new `--codex-mode` flag
2. Dry run with `--codex-mode exec` (default) produces identical commands as before
3. `--codex-mode interactive` produces `codex --dangerously-bypass-approvals-and-sandbox <prompt>` (no `exec`, no `--json`)
4. Interactive mode runs with TTY allocation (`docker exec -it`)
