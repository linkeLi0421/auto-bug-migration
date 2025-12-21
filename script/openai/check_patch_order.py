import argparse
import os
import sys
from collections import Counter
from typing import Optional

_client = None


def _get_openai_client():
    global _client
    if _client is None:
        try:
            from openai import OpenAI
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(f"OpenAI python package is required: {exc}") from exc
        _client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    return _client


def _normalize_patch_text(patch_text: str) -> str:
    lines = []
    for line in patch_text.splitlines():
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith(("+", "-", " ")):
            lines.append(line[1:])
        else:
            lines.append(line)
    return "\n".join(lines).strip()

def _enforce_reorder_only(original: str, candidate: str) -> str:
    """
    Ensure `candidate` is a pure reordering of `original` (line-for-line).
    If the model adds/removes/edits lines, fall back to `original` unchanged.
    """
    original_lines = original.splitlines()
    candidate_lines = candidate.splitlines()

    remaining = Counter(original_lines)
    filtered: list[str] = []
    for line in candidate_lines:
        if remaining[line] > 0:
            filtered.append(line)
            remaining[line] -= 1

    if len(filtered) != len(original_lines):
        return original
    if any(count != 0 for count in remaining.values()):
        return original
    return "\n".join(filtered).strip()

def fix_patch_order(patch_text: str, model: str = "gpt-5-mini", allow_insertions: bool = False) -> str:
    """
    Use an LLM to fix ordering/dependency issues in a C patch snippet.
    Input can be raw code or a diff hunk; diff prefixes are ignored.
    Output is the corrected code snippet only (no explanations).
    """
    normalized = _normalize_patch_text(patch_text)
    if not normalized:
        return ""

    constraints = """Constraints:
- ONLY reorder existing lines; do NOT add, remove, or edit any lines.
- If reordering alone cannot fix it, return the snippet EXACTLY unchanged."""
    if allow_insertions:
        constraints = """Constraints:
- Prefer reordering existing lines.
- If reordering alone cannot fix it, you may add the minimal necessary forward declaration(s) ONLY.
- If the snippet already satisfies these rules, return it EXACTLY unchanged."""

    prompt = f"""You are reviewing a C code snippet (possibly extracted from a patch hunk).
Your task is to FIX ordering and dependency issues by reordering lines.

Focus ONLY on definition order and dependency usage inside the snippet.
Do not change identifiers, types, literals, or logic.
Do not introduce or remove any lines of code.

Rules:
- Macros must be defined before they are used.
- Typedefs, enums, structs, and types must be declared before use (unless a forward decl exists).
- Function prototypes/definitions should appear before any usage in the snippet if no prior declaration exists.
- Global variables with initializers must not depend on symbols defined later in the snippet.

{constraints}
- Output ONLY the final corrected code snippet. No code fences. No explanations. No extra text.

Snippet:
{normalized}
"""

    try:
        client = _get_openai_client()
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a precise C reviewer. Output only the final corrected code snippet."},
                {"role": "user", "content": prompt},
            ],
        )
        candidate = (response.choices[0].message.content or "").strip()
        if allow_insertions:
            return candidate
        return _enforce_reorder_only(normalized, candidate)
    except Exception as exc:
        return f"Error calling OpenAI API: {exc}"


def _read_input_text(path: Optional[str]) -> str:
    if path:
        with open(path, "r") as handle:
            return handle.read()
    return sys.stdin.read()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fix C patch snippet ordering/dependencies.")
    parser.add_argument("path", nargs="?", help="Optional path to a file containing a diff hunk or code.")
    parser.add_argument("--model", default="gpt-5-mini", help="OpenAI model name.")
    parser.add_argument(
        "--allow-insertions",
        action="store_true",
        help="Allow minimal forward declarations if needed (may add lines).",
    )
    args = parser.parse_args()

    input_text = _read_input_text(args.path)
    if not input_text.strip():
        print("Error: no input provided.", file=sys.stderr)
        sys.exit(1)
    print(fix_patch_order(input_text, model=args.model, allow_insertions=args.allow_insertions))
