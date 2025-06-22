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
    tu = index.parse(path, args=args[:-1], options=TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD)
    results = []
    dir_path, file_name = os.path.split(path)
    dir_path = os.path.join('/data/', dir_path[5:])  # ensure output is in /out/
    out_path_set = set()
    
    for cursor in tu.cursor.walk_preorder():
        file_path = str(cursor.location.file) if cursor.location.file else ""
        file = file_path
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
            
        # record extent for declarations/definitions
        if cursor.extent and cursor.extent.start and cursor.extent.end:
            file = str(cursor.extent.start.file)
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

        if file_path:
            # Sometimes, macro do not come from a file. So when the file_path is empty, we just keep the info
            # in where it use.
            file_relative_path = file_path.split('/', 3)[-1] if file_path.startswith('/src') else file_path
            file_relative_folder = os.path.dirname(file_relative_path)
            file_name = file_relative_path.split('/')[-1] + "_analysis.json"
            out_path = os.path.realpath(os.path.join(file_relative_folder, file_name))
            if not os.path.exists(file_relative_folder):
                os.makedirs(file_relative_folder)
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
                os.makedirs(dir_path)
            with open(out_path, "a") as out:
                json.dump(info, out, indent=2)
                out.write(",\n")
            out_path_set.add(os.path.realpath(out_path))
        
    return out_path_set
    

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

if __name__ == "__main__":
    main()
