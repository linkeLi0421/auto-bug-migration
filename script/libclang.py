from __future__ import annotations

import os
import json
from clang.cindex import Index, CursorKind, Config, Diagnostic
from clang.cindex import TranslationUnit
import subprocess

Config.set_library_file('/usr/lib/llvm-18/lib/libclang.so')  # adjust for your system
index = Index.create()


def print_diagnostics(tu, path):
    """Print any parsing errors/warnings from the translation unit"""
    if not tu or not tu.diagnostics:
        return
    print(f"  Diagnostics for {path}:")
    for diag in tu.diagnostics:
        print(f"    [{diag.severity}] {diag.spelling} at {diag.location.file}:{diag.location.line}")


def _extent_dict(cur, include_paths):
    if not cur or not cur.extent or not cur.extent.start or not cur.extent.end:
        return None
    def _disp(p):
        p = str(p)
        if not p:
            return ""
        real = os.path.realpath(p)
        if real.startswith("/src"):
            return real.split("/", 3)[-1]
        if any(ip in p for ip in include_paths):
            for include_path in include_paths:
                if p in include_path:
                    return f"#include <{p[len(include_path)+1:]}>"
        return real
    s = cur.extent.start
    e = cur.extent.end
    return {
        "start": {"file": _disp(s.file), "line": s.line, "column": s.column},
        "end":   {"file": _disp(e.file), "line": e.line, "column": e.column},
    }


def extract_include_paths() -> list[str]:
    # Run the Clang command and capture stderr
    result = subprocess.run(
        ['clang', '-E', '-x', 'c', '-', '-v'],
        input='',  # empty input to simulate /dev/null
        capture_output=True,
        text=True
    )

    clang_output = result.stderr  # `-v` output goes to stderr
    include_paths = []
    inside_include_block = False

    for line in clang_output.splitlines():
        if "#include <...> search starts here:" in line:
            inside_include_block = True
            continue
        if inside_include_block:
            if line.strip() == "End of search list.":
                break
            include_paths.append(line.strip())

    return include_paths


def get_defs(directory, src_file, args):
    path = os.path.join(directory, src_file)
    include_paths = extract_include_paths()
    
    if not os.path.exists(path):
        print(f"File does not exist: {path}")
        return {}
    
    # For header files, use a special strategy
    is_header = src_file.endswith('.h') or src_file.endswith('.hpp')
    
    # Try multiple parsing strategies with different fallback options
    parse_args = args[:-1] + ["-resource-dir=/usr/local/lib/clang/18"]
    
    # Add -fsyntax-only for header files
    if is_header and "-fsyntax-only" not in parse_args:
        parse_args = parse_args + ["-fsyntax-only"]
    
    tu = None
    try:
        tu = index.parse(path, args=parse_args, options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        if tu and tu.cursor:
            print_diagnostics(tu, path)
    except Exception as e:
        print(f"Warning: First parse attempt failed for {path}: {e}")
        print(f"  Args: {parse_args}")
        # Fallback: try without resource-dir
        try:
            tu = index.parse(path, args=args[:-1], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            if tu and tu.cursor:
                print_diagnostics(tu, path)
        except Exception as e2:
            print(f"Warning: Second parse attempt failed for {path}: {e2}")
            print(f"  Args: {args[:-1]}")
            # Final fallback: try with minimal options (no args)
            try:
                tu = index.parse(path, args=[], options=0)
                if tu and tu.cursor:
                    print(f"  Success with minimal options for {path}")
                    print_diagnostics(tu, path)
            except Exception as e3:
                print(f"Error: Could not parse {path} with any strategy: {e3}")
                return {}
    
    defs_by_usr = {}
    
    if tu and tu.cursor:
        for cursor in tu.cursor.walk_preorder():
            if cursor.kind == CursorKind.FUNCTION_DECL and cursor.is_definition():
                usr = cursor.get_usr()
                if usr:
                    defs_by_usr[usr] = cursor
    return defs_by_usr


def analyze_file(directory, src_file, args, defs_by_usr, file_to_project=None):
    path = os.path.join(directory, src_file)
    include_paths = extract_include_paths()
    args = [f"-I{os.path.abspath(os.path.join(directory, arg[2:]))}" if arg.startswith("-I") and not os.path.isabs(arg[2:]) else arg for arg in args]
    if not os.path.exists(path):
        print(f"File does not exist: {path}")
        return set()
    
    # For header files, use a special strategy
    is_header = src_file.endswith('.h') or src_file.endswith('.hpp')
    
    # Try multiple parsing strategies with different fallback options
    parse_args = args[:-1] + ["-resource-dir=/usr/local/lib/clang/18"]
    
    # Add -fsyntax-only for header files
    if is_header and "-fsyntax-only" not in parse_args:
        parse_args = parse_args + ["-fsyntax-only"]
    
    tu = None
    try:
        tu = index.parse(path, args=parse_args, options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
        if tu and tu.cursor:
            print_diagnostics(tu, path)
    except Exception as e:
        print(f"Warning: First parse attempt failed for {path}: {e}")
        # Fallback: try without resource-dir
        try:
            tu = index.parse(path, args=args[:-1], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
            if tu and tu.cursor:
                print_diagnostics(tu, path)
        except Exception as e2:
            print(f"Warning: Second parse attempt failed for {path}: {e2}")
            # Final fallback: try with minimal options
            try:
                tu = index.parse(path, args=[], options=0)
                if tu and tu.cursor:
                    print(f"  Success with minimal options for {path}")
                    print_diagnostics(tu, path)
            except Exception as e3:
                print(f"Error: Could not parse {path} with any strategy: {e3}")
                return set()
    
    dir_path, file_name = os.path.split(path)
    # Handle files outside /src/ (e.g., oss-fuzz harness files like /src/matio_fuzzer.cc)
    # by mapping them into the appropriate project subdirectory
    if dir_path == '/src' or dir_path.startswith('/src/'):
        rel_path = dir_path[5:]  # Remove '/src' or '/src/' prefix
        if not rel_path:
            # File is directly in /src/, check if we have a pre-computed mapping
            if file_to_project and path in file_to_project:
                dir_path = os.path.join('/data/', file_to_project[path])
            else:
                dir_path = os.path.join('/data/', 'src')  # fallback to 'src' subdirectory
        else:
            # Get first directory component and strip -src suffix if present
            # e.g., 'php-src' -> 'php' so files go to /data/php/ not /data/php-src/
            first_dir = rel_path.split('/')[0]
            if first_dir.endswith('-src'):
                first_dir = first_dir[:-4]  # Remove '-src' suffix
            dir_path = os.path.join('/data/', first_dir)
    else:
        dir_path = os.path.join('/data/', dir_path[5:] if dir_path.startswith('/src') else dir_path.lstrip('/'))  # ensure output is in /data/
    out_path_set = set()
    
    if not tu or not tu.cursor:
        print(f"Warning: No cursor available for {path}")
        return set()
    
    for cursor in tu.cursor.walk_preorder():
        file_path = os.path.normpath(str(cursor.location.file) if cursor.location.file else "")
        file = os.path.realpath(file_path)
        if file.startswith('/src'):
            file = file.split('/', 3)[-1]
        elif any(path in str(cursor.extent.start.file) for path in include_paths):
            file = '#include <' + file + '>'
        if cursor.kind not in {CursorKind.FUNCTION_DECL,
                               CursorKind.STRUCT_DECL,
                               CursorKind.UNION_DECL,
                               CursorKind.ENUM_DECL,
                               CursorKind.ENUM_CONSTANT_DECL,
                               CursorKind.DECL_REF_EXPR,
                               CursorKind.MACRO_DEFINITION,
                               CursorKind.TYPEDEF_DECL,
                               CursorKind.TYPE_REF,
                               }:
            continue
        info = {
            "kind": cursor.kind.name,
            "spelling": cursor.spelling,
            "location": {
            "file": file,
            "line": cursor.location.line,
            "column": cursor.location.column,
            },
        }
        if cursor.kind == CursorKind.FUNCTION_DECL:
            # Build a precise function signature
            is_def = bool(cursor.is_definition())
            info["is_definition"] = is_def
            # Record storage/inline metadata so downstream tools can preserve
            # header-safe linkage (e.g. wasm3 op implementations use `static inline`).
            try:
                sc = cursor.storage_class
                info["storage_class"] = sc.name if hasattr(sc, "name") else str(sc)
            except Exception:
                pass
            try:
                info["is_inline"] = bool(cursor.is_function_inlined())
            except Exception:
                pass
            try:
                lk = cursor.linkage
                info["linkage"] = lk.name if hasattr(lk, "name") else str(lk)
            except Exception:
                pass

            if is_def:
                info['kind'] = 'FUNCTION_DEFI'
            else:
                def_cursor = defs_by_usr.get(cursor.get_usr())
                if def_cursor and def_cursor.location:
                    def_file_path = os.path.normpath(str(def_cursor.location.file) if def_cursor.location.file else "")
                    def_file = os.path.realpath(def_file_path)
                    if def_file.startswith('/src'):
                        def_file = def_file.split('/', 3)[-1]
                    info["location"] = {
                        "file": def_file,
                        "line": def_cursor.location.line,
                        "column": def_cursor.location.column,
                    }
            arg_list = []
            for arg in cursor.get_arguments():
                arg_list.append(f"{arg.type.spelling} {arg.spelling}")
            signature = f"{cursor.result_type.spelling} {cursor.spelling}({', '.join(arg_list)})"
            info["signature"] = signature
        elif cursor.kind == CursorKind.DECL_REF_EXPR:
            target = cursor.referenced
            if target is not None:
                if target.kind == CursorKind.FUNCTION_DECL:
                    info['kind'] = 'CALL_EXPR'
                    num_args = len(list(target.get_arguments()))
                    info["num_arguments"] = num_args
                    info["callee"] = {
                        "name": target.spelling,
                        "type": target.type.spelling if hasattr(target, "type") else "",
                        "result_type": target.result_type.spelling if hasattr(target, "result_type") else "",
                    }
                    callee_args = []
                    for arg in target.get_arguments():
                        callee_args.append(f"{arg.type.spelling} {arg.spelling}")
                    info["callee"]["signature"] = f"{target.result_type.spelling} {target.spelling}({', '.join(callee_args)})"
                decl = target.get_definition() if target else None
                if not decl and target:
                    decl = target  # use the declaration if no definition found
                info["type_ref"] = {
                    "target_kind": target.kind.name if target else "",
                    "target_name": target.spelling if target else "",
                    "usr": (target.get_usr() if target else ""),
                    "canonical_type": (target.type.get_canonical().spelling if target and target.type else ""),
                    "decl_location": None,
                    "typedef_extent": _extent_dict(decl, include_paths),   # <-- full typedef range (includes name + semicolon)
                }
        elif cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            info['enum_value'] = cursor.enum_value
        elif cursor.kind == CursorKind.TYPEDEF_DECL:
            info['typedef'] = cursor.underlying_typedef_type.spelling
        elif cursor.kind == CursorKind.TYPE_REF:
            target = cursor.referenced  # e.g., TYPEDEF_DECL for proc_state_t
            decl = target.get_definition() if target else None
            if not decl and target:
                decl = target  # use the declaration if no definition found
            info["type_ref"] = {
                "target_kind": target.kind.name if target else "",
                "target_name": target.spelling if target else "",
                "usr": (target.get_usr() if target else ""),
                "canonical_type": (target.type.get_canonical().spelling if target and target.type else ""),
                "decl_location": None,
                "typedef_extent": _extent_dict(decl, include_paths),   # <-- full typedef range (includes name + semicolon)
            }

            # Try to resolve the underlying declaration (struct/union/enum) and record its full range too
            underlying_decl = None
            try:
                # Works for typedefs: proc_state_t -> enum (possibly anonymous)
                underlying_type = target.underlying_typedef_type if target else None
                if underlying_type is not None:
                    underlying_decl = underlying_type.get_declaration()
            except Exception:
                underlying_decl = None

            if underlying_decl:
                underlying_def = underlying_decl.get_definition() or underlying_decl
                info["type_ref"]["underlying"] = {
                    "kind": underlying_def.kind.name,
                    "name": underlying_decl.spelling or underlying_def.spelling,
                    "decl_location": {
                        "file": _extent_dict(underlying_def, include_paths)["start"]["file"] if _extent_dict(underlying_def, include_paths) else "",
                        "line": underlying_def.location.line if underlying_def.location else 0,
                        "column": underlying_def.location.column if underlying_def.location else 0,
                    },
                    "extent": _extent_dict(underlying_def, include_paths),  # <-- range of enum { … } block
                }
            else:
                # Fallback: keep at least the decl location of the typedef
                if decl and decl.location and decl.location.file:
                    info["type_ref"]["decl_location"] = {
                        "file": _extent_dict(decl, include_paths)["start"]["file"] if _extent_dict(decl, include_paths) else "",
                        "line": decl.location.line,
                        "column": decl.location.column,
                    }
        
        # record extent for declarations/definitions
        if cursor.extent and cursor.extent.start and cursor.extent.end:
            file = os.path.realpath(str(cursor.extent.start.file))
            if file.startswith('/src'):
                file = file.split('/', 3)[-1]
            elif any(path in str(cursor.extent.start.file) for path in include_paths):
                # header file from system include paths
                file = '#include <' + file + '>'
            info["extent"] = {
                "start": {
                    "file": file,
                    "line": cursor.extent.start.line,
                    "column": cursor.extent.start.column,
                },
                "end": {
                    "file": file,
                    "line": cursor.extent.end.line,
                    "column": cursor.extent.end.column,
                },
            }

        if file_path and file_path.startswith('/src'):
            # Sometimes, macro do not come from a file. So when the file_path is empty, we just keep the info
            # in where it use.
            file_relative_path = file_path.split('/', 2)[-1]
            file_name = file_relative_path.split('/')[-1] + "_analysis.json"
            # Get the directory parts and strip -src suffix from first component if present
            # e.g., 'php-src/Zend' -> 'php/Zend' so files go to /data/php/ not /data/php-src/
            dir_parts = file_relative_path.split('/')[:-1]
            if dir_parts and dir_parts[0].endswith('-src'):
                dir_parts[0] = dir_parts[0][:-4]  # Remove '-src' suffix
            folder = os.path.join('/data/', '/'.join(dir_parts))
            out_path = os.path.realpath(os.path.join(folder, file_name))
            if not os.path.exists(folder):
                os.makedirs(folder)
            with open(out_path, "a") as out:
                json.dump(info, out, indent=2)
                out.write(",\n")
            out_path_set.add(out_path)
        
        src_path = os.path.realpath(path)
        file_path = os.path.realpath(file_path)
        src_relative_path = src_path.split('/', 3)[-1] if src_path.startswith('src/') else src_path
        src_file_name = src_relative_path.split('/')[-1] + "_analysis.json"
        if file_path != src_path:
            # perhaps file_path is a .h file
            out_path = os.path.join(dir_path, src_file_name)
            out_path = os.path.realpath(out_path)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
            with open(out_path, "a") as out:
                json.dump(info, out, indent=2)
                out.write(",\n")
            out_path_set.add(os.path.realpath(out_path))
        
    return out_path_set
    

def deduplicate_json_files(json_files):
    """
    Remove duplicate entries from JSON files based on kind, spelling, and location.
    """
    for json_file in json_files:
        print(f"Deduplicating {json_file}")
        
        # Read the JSON file
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError) as e:
            print(f"Error reading {json_file}: {e}")
            continue
        
        if not isinstance(data, list):
            print(f"Skipping {json_file}: not a list")
            continue
        
        # Create a set to track unique entries
        seen = set()
        unique_entries = []
        
        for entry in data:
            # Create a unique key based on kind, spelling, and location
            if not isinstance(entry, dict):
                continue
                
            kind = entry.get('kind', '')
            spelling = entry.get('spelling', '')
            location = entry.get('location', {})
            
            # Create a hashable key for the location
            location_key = (
                location.get('file', ''),
                location.get('line', 0),
                location.get('column', 0)
            )
            
            # Create the unique key
            unique_key = (kind, spelling, location_key)
            
            # Only add if we haven't seen this combination before
            if unique_key not in seen:
                seen.add(unique_key)
                unique_entries.append(entry)
            else:
                print(f"  Removing duplicate: {kind} {spelling} at {location_key}")
        
        # Write the deduplicated data back to the file
        if len(unique_entries) < len(data):
            print(f"  Removed {len(data) - len(unique_entries)} duplicates from {json_file}")
            with open(json_file, 'w') as f:
                json.dump(unique_entries, f, indent=2)
        else:
            print(f"  No duplicates found in {json_file}")


def load_compile_commands(path="compile_commands.json"):
    with open(path) as f:
        data = json.load(f)
    commands = {}
    for entry in data:
        directory = entry["directory"]
        file = entry["file"]
        args = entry.get("arguments") or entry["command"].split()
        abs_path = os.path.abspath(os.path.join(directory, file))
        commands[abs_path] = (directory, args)
    return commands


def get_project_dir_mappings(compile_db):
    """
    Pre-analyze compile commands to determine which files should map to which project directories.
    This handles cases like oss-fuzz harness files that are outside the project source directory.
    """
    # First pass: identify all project directories that will be created
    project_dirs = set()
    file_to_project = {}
    
    for src_file in compile_db:
        directory, args = compile_db[src_file]
        path = os.path.join(directory, src_file)
        dir_path, file_name = os.path.split(path)
        
        # Check if path is under /src/ (including exactly /src)
        if dir_path == '/src' or dir_path.startswith('/src/'):
            rel_path = dir_path[5:]  # Remove '/src' or '/src/' prefix
            if rel_path and '/' in rel_path:
                project_name = rel_path.split('/')[0]
                project_dirs.add(project_name)
                file_to_project[path] = project_name
    
    # Second pass: map files directly in /src/ to appropriate projects
    for src_file in compile_db:
        directory, args = compile_db[src_file]
        path = os.path.join(directory, src_file)
        dir_path, file_name = os.path.split(path)
        
        # Check if file is directly in /src/ (not in a subdirectory)
        if dir_path == '/src':
            # File is directly in /src/, try to find matching project
            matched_project = None
            for proj in project_dirs:
                if file_name.lower().startswith(proj.lower()):
                    matched_project = proj
                    break
                # Also check with underscore replacement
                file_base = file_name.lower().replace('_', '').replace('-', '')
                proj_normalized = proj.lower().replace('_', '').replace('-', '')
                if file_base.startswith(proj_normalized):
                    matched_project = proj
                    break
            if matched_project:
                file_to_project[path] = matched_project
    
    return file_to_project


def main():
    compile_db = load_compile_commands()
    
    # Pre-compute project mappings for files directly in /src/
    file_to_project = get_project_dir_mappings(compile_db)
    
    # Clean any leftover analysis files from previous runs to prevent
    # appending to already-wrapped JSON (which creates invalid ][{ sequences)
    import glob as _glob
    for old in _glob.glob('/data/**/*_analysis.json', recursive=True):
        os.remove(old)

    out_path_set = set()
    defs_by_usr = dict()
    for src_file in compile_db:
        directory, args = compile_db[src_file]
        
        # Redirect the output file to /null
        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 < len(args):
                args[idx + 1] = "/dev/null"
        defs_by_usr.update(get_defs(directory, src_file, args))

    for src_file in compile_db:
        directory, args = compile_db[src_file]
        # Redirect the output file to /null
        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 < len(args):
                args[idx + 1] = "/dev/null"
        out_path_set.update(analyze_file(directory, src_file, args, defs_by_usr, file_to_project))

    for out_path in out_path_set:
        with open(out_path, "r+") as f:
            data = f.read().rstrip(",\n")
            f.seek(0)
            f.truncate()
            f.write("[\n")
            f.write(data)
            f.write("\n]\n")

    deduplicate_json_files(out_path_set)


if __name__ == "__main__":
    main()
