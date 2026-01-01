from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple


def parse_build_errors(error_log: str) -> Dict[str, Any]:
    """Parse compiler/build errors into a JSON-serializable summary.

    This is a structured variant of `handle_build_error(...)` from `revert_patch_test.py`,
    extracted so agents can consume build failures without importing the full pipeline.
    """
    text = error_log or ""
    lines = text.splitlines()

    def _as_location(file_path: str, line: str, col: str) -> str:
        return f"{file_path}:{line}:{col}"

    undeclared_identifiers: List[Dict[str, Any]] = []
    undeclared_functions: List[Dict[str, Any]] = []
    missing_struct_members: List[Dict[str, Any]] = []
    function_call_issues: List[Dict[str, Any]] = []
    incomplete_types: List[Dict[str, Any]] = []

    # --- Undeclared identifiers ---
    pattern = r"(/src.+?):(\d+):(\d+):.*use of undeclared identifier '(\w+)'"
    for filepath, line, column, identifier in re.findall(pattern, text):
        undeclared_identifiers.append(
            {
                "name": identifier,
                "file": filepath,
                "line": int(line),
                "column": int(column),
                "location": _as_location(filepath, line, column),
                "kind": "undeclared_identifier",
            }
        )

    # --- Undeclared functions ---
    pattern = r"(/src.+?):(\d+):(\d+):.*undeclared function '(\w+)'"
    for filepath, line, column, identifier in re.findall(pattern, text):
        undeclared_functions.append(
            {
                "name": identifier,
                "file": filepath,
                "line": int(line),
                "column": int(column),
                "location": _as_location(filepath, line, column),
                "kind": "undeclared_function",
            }
        )

    # --- Conflicting types (treat like undeclared function) ---
    pattern = r"(/src.+?):(\d+):(\d+):.*conflicting types for '(\w+)'"
    for filepath, line, column, identifier in re.findall(pattern, text):
        undeclared_functions.append(
            {
                "name": identifier,
                "file": filepath,
                "line": int(line),
                "column": int(column),
                "location": _as_location(filepath, line, column),
                "kind": "conflicting_types",
            }
        )

    # --- Missing struct members (capture a short context block) ---
    pattern = r"(/src.+?):(\d+):(\d+):.*no member named '(\w+)' in '([^']+)'"
    for idx, line in enumerate(lines):
        match = re.search(pattern, line)
        if not match:
            continue
        filepath, line_num, column, member, struct_name = match.groups()
        context_lines = lines[idx : idx + 3]
        missing_struct_members.append(
            {
                "member": member,
                "struct": struct_name,
                "file": filepath,
                "line": int(line_num),
                "column": int(column),
                "location": _as_location(filepath, line_num, column),
                "message": "\n".join(context_lines).strip(),
            }
        )

    # --- Too few / many arguments to function call ---
    next_error = {"note:", "warning:", "error:"}
    line_num_pattern = r"^\s*(\d+)\s*\|\s*(.*)"
    pattern = r"(/src.+?):(\d+):(\d+):.*too (?:few|many) arguments to function call.*"
    for i, error_line in enumerate(lines):
        match = re.search(pattern, error_line)
        if not match:
            continue
        filepath, line_num, col_num = match.groups()
        line_num_set: set[int] = {int(line_num)}
        fun_call_code = ""

        context_block = [error_line]
        for j in range(i + 1, len(lines)):
            if any(sign in lines[j] for sign in next_error):
                break
            context_block.append(lines[j])

            # skip caret/tilde continuation lines
            if re.match(r"^\s*\|\s*\^", lines[j]) or re.match(r"^\s*\|\s*~", lines[j]):
                continue

            line_num_match = re.search(line_num_pattern, lines[j])
            if not line_num_match:
                continue
            lnum, code = line_num_match.groups()
            if abs(int(lnum) - int(line_num)) > 5:
                continue
            line_num_set.add(int(lnum))
            fun_call_code += code.strip() + " "

        function_call_issues.append(
            {
                "kind": "too_few_or_many_arguments_fun_call",
                "file": filepath,
                "line_range": [min(line_num_set), max(line_num_set)],
                "column": int(col_num),
                "call_code": fun_call_code.strip(),
                "message": "\n".join(context_block).strip(),
            }
        )

    # --- Type mismatch in function calls ---
    pattern_type_mismatch = (
        r"(/src.+?):(\d+):(\d+):.*passing '([^']+)'.*to parameter of incompatible type '([^']+)'.*"
    )
    for i, error_line in enumerate(lines):
        match = re.search(pattern_type_mismatch, error_line)
        if not match:
            continue
        filepath, line_num, col_num, from_type, to_type = match.groups()
        line_num_set: set[int] = {int(line_num)}
        fun_call_code = ""

        context_block = [error_line]
        for j in range(i + 1, len(lines)):
            if any(sign in lines[j] for sign in next_error):
                break
            context_block.append(lines[j])

            if re.match(r"^\s*\|\s*\^", lines[j]) or re.match(r"^\s*\|\s*~", lines[j]):
                continue
            line_num_match = re.search(line_num_pattern, lines[j])
            if not line_num_match:
                continue
            lnum, code = line_num_match.groups()
            if abs(int(lnum) - int(line_num)) > 5:
                continue
            line_num_set.add(int(lnum))
            fun_call_code += code.strip() + " "

        function_call_issues.append(
            {
                "kind": "type_mismatch_function_call",
                "file": filepath,
                "line_range": [min(line_num_set), max(line_num_set)],
                "column": int(col_num),
                "from_type": from_type,
                "to_type": to_type,
                "call_code": fun_call_code.strip(),
                "message": "\n".join(context_block).strip(),
            }
        )

    # --- Unknown type names ---
    pattern = r"(/src.+?):(\d+):(\d+):.*unknown type name '([^']+)'"
    for filepath, line, column, type_name in re.findall(pattern, text):
        undeclared_identifiers.append(
            {
                "name": type_name,
                "file": filepath,
                "line": int(line),
                "column": int(column),
                "location": _as_location(filepath, line, column),
                "kind": "unknown_type_name",
            }
        )

    # --- Incomplete type definitions (+ forward-decl note) ---
    pattern = r"(/src.+?):(\d+):(\d+):.*incomplete definition of type '([^']+)'"
    for i, error_line in enumerate(lines):
        match = re.search(pattern, error_line)
        if not match:
            continue
        error_filepath, error_line_num, error_column, type_name = match.groups()
        error_location = _as_location(error_filepath, error_line_num, error_column)

        forward_decl_location: Optional[str] = None
        forward_decl_type: Optional[str] = None
        note_pattern = r"(/src.+?):(\d+):(\d+):.*note:.*forward declaration of '([^']+)'"

        for j in range(i + 1, len(lines)):
            current_line = lines[j]
            if any(sign in current_line for sign in {"warning:", "error:"}):
                break
            note_match = re.search(note_pattern, current_line)
            if not note_match:
                continue
            note_filepath, note_line, note_column, note_type = note_match.groups()
            clean_type_name = type_name.replace("struct ", "")
            if note_type == clean_type_name or note_type == type_name:
                forward_decl_location = _as_location(note_filepath, note_line, note_column)
                forward_decl_type = note_type
                break

        incomplete_types.append(
            {
                "type": type_name,
                "error_location": error_location,
                "forward_decl_location": forward_decl_location,
                "forward_decl_type": forward_decl_type,
            }
        )

    # Deterministic ordering
    def _sort_key(obj: Dict[str, Any]) -> Tuple[Any, ...]:
        return (obj.get("file", ""), obj.get("line", 0), obj.get("column", 0), obj.get("name", ""))

    undeclared_identifiers.sort(key=_sort_key)
    undeclared_functions.sort(key=_sort_key)
    missing_struct_members.sort(key=lambda o: (o.get("file", ""), o.get("line", 0), o.get("member", "")))
    function_call_issues.sort(key=lambda o: (o.get("file", ""), (o.get("line_range") or [0, 0])[0], o.get("kind", "")))
    incomplete_types.sort(key=lambda o: (o.get("error_location", ""), o.get("type", "")))

    return {
        "undeclared_identifiers": undeclared_identifiers,
        "undeclared_functions": undeclared_functions,
        "missing_struct_members": missing_struct_members,
        "function_call_issues": function_call_issues,
        "incomplete_types": incomplete_types,
    }

