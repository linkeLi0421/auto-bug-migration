import os
import json
from clang.cindex import Index, CursorKind, Config
from clang.cindex import TranslationUnit
import subprocess

Config.set_library_file('/usr/lib/llvm-18/lib/libclang.so')  # adjust for your system
index = Index.create()


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


def analyze_file(directory, src_file, args):
    path = os.path.join(directory, src_file)
    include_paths = extract_include_paths()
    
    if not os.path.exists(path):
        print(f"File does not exist: {path}")
        return set()
    tu = index.parse(path, args=args[:-1] + ["-resource-dir=/usr/local/lib/clang/18"], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    results = []
    dir_path, file_name = os.path.split(path)
    dir_path = os.path.join('/data/', dir_path[5:])  # ensure output is in /data/
    out_path_set = set()
    
    for cursor in tu.cursor.walk_preorder():
        file_path = os.path.normpath(str(cursor.location.file) if cursor.location.file else "")
        file = os.path.realpath(file_path)
        if file.startswith('/src'):
            file = file.split('/', 3)[-1]
        elif any(path in str(cursor.extent.start.file) for path in include_paths):
            file = '#include <' + file.split('/')[-1] + '>'
        if cursor.kind not in {CursorKind.FUNCTION_DECL,
                               CursorKind.STRUCT_DECL,
                               CursorKind.UNION_DECL,
                               CursorKind.ENUM_DECL,
                               CursorKind.ENUM_CONSTANT_DECL,
                               CursorKind.CALL_EXPR,
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
            if cursor.is_definition():
                info['kind'] = 'FUNCTION_DEFI'
            arg_list = []
            for arg in cursor.get_arguments():
                arg_list.append(f"{arg.type.spelling} {arg.spelling}")
            signature = f"{cursor.result_type.spelling} {cursor.spelling}({', '.join(arg_list)})"
            info["signature"] = signature
        elif cursor.kind == CursorKind.CALL_EXPR:
            # Extract call expression information
            num_args = len(list(cursor.get_arguments()))
            info["num_arguments"] = num_args
            
            # Get callee information if available
            callee = cursor.referenced
            if callee:
                info["callee"] = {
                    "name": callee.spelling,
                    "type": callee.type.spelling if hasattr(callee, "type") else "",
                    "result_type": callee.result_type.spelling if hasattr(callee, "result_type") else "",
                }
                
                # Try to build signature for the callee if it's a function declaration
                if callee.kind == CursorKind.FUNCTION_DECL:
                    callee_args = []
                    for arg in callee.get_arguments():
                        callee_args.append(f"{arg.type.spelling} {arg.spelling}")
                    info["callee"]["signature"] = f"{callee.result_type.spelling} {callee.spelling}({', '.join(callee_args)})"
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
        elif cursor.kind == CursorKind.ENUM_CONSTANT_DECL:
            info['enum_value'] = cursor.enum_value
        elif cursor.kind == CursorKind.TYPEDEF_DECL:
            info['typedef'] = cursor.underlying_typedef_type.spelling
        elif cursor.kind == CursorKind.TYPE_REF:
            target = cursor.referenced  # e.g., TYPEDEF_DECL for proc_state_t
            decl = target.get_definition() if target else None
            if not decl and target:
                decl = target  # use the declaration if no definition found

            def _extent_dict(cur):
                if not cur or not cur.extent or not cur.extent.start or not cur.extent.end:
                    return None
                def _disp(p):
                    if not p:
                        return ""
                    real = os.path.realpath(str(p))
                    if real.startswith("/src"):
                        return real.split("/", 3)[-1]
                    if any(ip in str(p) for ip in include_paths):
                        return "#include <" + os.path.basename(real) + ">"
                    return real
                s = cur.extent.start
                e = cur.extent.end
                return {
                    "start": {"file": _disp(s.file), "line": s.line, "column": s.column},
                    "end":   {"file": _disp(e.file), "line": e.line, "column": e.column},
                }

            info["type_ref"] = {
                "target_kind": target.kind.name if target else "",
                "target_name": target.spelling if target else "",
                "usr": (target.get_usr() if target else ""),
                "canonical_type": (target.type.get_canonical().spelling if target and target.type else ""),
                "decl_location": None,
                "typedef_extent": _extent_dict(decl),   # <-- full typedef range (includes name + semicolon)
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
                        "file": _extent_dict(underlying_def)["start"]["file"] if _extent_dict(underlying_def) else "",
                        "line": underlying_def.location.line if underlying_def.location else 0,
                        "column": underlying_def.location.column if underlying_def.location else 0,
                    },
                    "extent": _extent_dict(underlying_def),  # <-- range of enum { … } block
                }
            else:
                # Fallback: keep at least the decl location of the typedef
                if decl and decl.location and decl.location.file:
                    info["type_ref"]["decl_location"] = {
                        "file": _extent_dict(decl)["start"]["file"] if _extent_dict(decl) else "",
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
                file = '#include <' + file.split('/')[-1] + '>'
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
            folder = os.path.join('/data/', '/'.join(file_relative_path.split('/')[:-1]))
            out_path = os.path.realpath(os.path.join(folder, file_name))
            if not os.path.exists(folder):
                os.makedirs(folder)
            print(f"Processing {file_relative_path} at {cursor.location.line}:{cursor.location.column} - {cursor.kind.name} {cursor.spelling} {out_path}")
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
        commands[file] = (directory, args)
    return commands


def main():
    compile_db = load_compile_commands()
    out_path_set = set()
    for src_file in compile_db:
        directory, args = compile_db[src_file]
        
        # Redirect the output file to /null
        if "-o" in args:
            idx = args.index("-o")
            if idx + 1 < len(args):
                args[idx + 1] = "/dev/null"
        out_path_set.update(analyze_file(directory, src_file, args))
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
