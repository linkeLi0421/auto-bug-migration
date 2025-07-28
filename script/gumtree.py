import os
import subprocess
import sys
import re
from typing import List, Tuple, Optional
from bisect import bisect_right

gumtree_path = os.getenv('GUMTREE_PATH')

class DiffOperation:
    # For match, line1 and line2 are number in different files
    # For delete, line1 and line2 are the start and end lines in the original file
    def __init__(
        self,
        label: str,
        span1: Tuple[int, int],
        span2: Tuple[int, int],
        line1: int,
        line2: int
    ):
        self.label = label
        self.span1 = span1
        self.span2 = span2
        self.line1 = line1
        self.line2 = line2

    def __repr__(self):
        return (f"<{self.label}: ({self.span1} {self.span2}) ⇄ "
                f" (line {self.line1}~line {self.line2})>")


def build_offset_to_line_map(text: str) -> List[int]:
    """Return list of character offsets where each line starts."""
    offsets = [0]
    for line in text.splitlines(True):  # keep \n
        offsets.append(offsets[-1] + len(line))
    return offsets


def offset_to_line(offsets: List[int], index: int) -> int:
    """Return 1-based line number for a character index using binary search."""
    return bisect_right(offsets, index)


class GumTreeTextDiffParser:
    def __init__(self, raw_text: str, original_code1: str, original_code2: str):
        self.raw_text = raw_text
        self.offsets1 = build_offset_to_line_map(original_code1)
        self.offsets2 = build_offset_to_line_map(original_code2)
        self.matches: List[DiffOperation] = []
        self.deletes: List[DiffOperation] = []
        self._parse()

    def _parse(self):
        # Split sections by '===\n' or lines that contain only '==='
        sections = re.split(r'^===\s*$', self.raw_text.strip(), flags=re.MULTILINE)

        for section in sections:
            lines = [line.strip() for line in section.strip().splitlines() if line.strip()]
            if not lines:
                continue
            if lines[0] == "match":
                if len(lines) != 4:
                    continue
                m1 = self._parse_line(lines[2])
                m2 = self._parse_line(lines[3])
                if not m1 or not m2:
                    continue
                label1, start1, end1 = m1
                label2, start2, end2 = m2
                start1, end1, start2, end2 = int(start1), int(end1), int(start2), int(end2)
                if label1 != label2:
                    continue
                line1 = offset_to_line(self.offsets1, start1)
                line2 = offset_to_line(self.offsets2, start2)
                self.matches.append(
                    DiffOperation(label1, (start1, end1), (start2, end2), line1, line2)
                )
            elif lines[0] == "delete-node" or lines[0] == "delete-tree":
                for line in lines[2:]:
                    m = self._parse_line(line)
                    label, start, end = m
                    try:
                        start = int(start)
                        end = int(end)
                        break
                    except:
                        continue
                line_start = offset_to_line(self.offsets1, start)
                line_end = offset_to_line(self.offsets1, end)
                self.deletes.append(
                    DiffOperation(label, (start, end), (-1, -1), line_start, line_end)
                )

    def _parse_line(self, line: str) -> Optional[Tuple[str, int, int]]:
        # Example line: "identifier: j [28021,28022]"
        label = line.split('[')[0].strip()
        start = line.split('[')[-1].split(',')[0]
        end = line.split(',')[-1].split(']')[0]
        return label, start, end

    def get_matches(self) -> List[DiffOperation]:
        return self.matches
    
    def get_deletes(self) -> List[DiffOperation]:
        return self.deletes


def get_corresponding_lines(target_repo_path, file_path1, commit1, file_path2, commit2, blocks):
    file_path1 = os.path.join(target_repo_path, file_path1)
    file_path2 = os.path.join(target_repo_path, file_path2)
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit1], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(file_path1, 'r') as f1:
        file_content1 = f1.read()
    subprocess.run(["git", "checkout", '-f', commit2], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(file_path2, 'r') as f2:
        file_content2 = f2.read()
    
    # *.c because GumTree's parser is based on the file extension
    with open('/tmp/gumtree_tmp1.c', 'w') as f1:
        f1.write(file_content1)
    with open('/tmp/gumtree_tmp2.c', 'w') as f2:
        f2.write(file_content2)
    cmd = [f'{gumtree_path}', 'textdiff', f'/tmp/gumtree_tmp1.c', f'/tmp/gumtree_tmp2.c']
    result = subprocess.run(cmd, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        return []
    diff_output = result.stdout
    parser = GumTreeTextDiffParser(result.stdout, original_code1=file_content1, original_code2=file_content2)
    corresponding_lines = set()
    line_set = set()
    for bb in blocks:
        s = range(bb.start_line, bb.end_line + 1)
        line_set.update(set(s))
    for op in parser.get_matches():
        if op.line1 in line_set and op.label != 'NULL: NULL' and op.label != 'null':
            if op.line2 == 847:
                print(f"Found corresponding line: {op.line1} -> {op.line2} for label {op.label}")
            corresponding_lines.add(op.line2)
    return list(corresponding_lines)


def get_delete_lines(target_repo_path, file_path1, commit1, file_path2, commit2, bb1_start_line, bb1_end_line):
    file_path1 = os.path.join(target_repo_path, file_path1)
    file_path2 = os.path.join(target_repo_path, file_path2)
    os.chdir(target_repo_path)
    subprocess.run(["git", "clean", "-fdx"], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["git", "checkout", '-f', commit1], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(file_path1, 'r') as f1:
        file_content1 = f1.read()
    subprocess.run(["git", "checkout", '-f', commit2], encoding='utf-8', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(file_path2, 'r') as f2:
        file_content2 = f2.read()
    
    # *.c because GumTree's parser is based on the file extension
    with open('/tmp/gumtree_tmp1.c', 'w') as f1:
        f1.write(file_content1)
    with open('/tmp/gumtree_tmp2.c', 'w') as f2:
        f2.write(file_content2)
    cmd = [f'{gumtree_path}', 'textdiff', f'/tmp/gumtree_tmp1.c', f'/tmp/gumtree_tmp2.c']
    result = subprocess.run(cmd, encoding='utf-8', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        return []
    diff_output = result.stdout
    parser = GumTreeTextDiffParser(result.stdout, original_code1=file_content1, original_code2=file_content2)
    delete_lines = []
    for op in parser.get_deletes():
        if op.line2 >= bb1_start_line and op.line1 <= bb1_end_line:
            delete_lines.append((op.line1, op.line2))
    return delete_lines


if __name__ == "__main__":
    print("Usage: python gumtree.py <target_repo_path> <file_path1> <commit1> <file_path2> <commit2>")

    target_repo_path = sys.argv[1]
    file_path1 = sys.argv[2]
    commit1 = sys.argv[3]
    file_path2 = sys.argv[4]
    commit2 = sys.argv[5]

    corresponding_lines = get_corresponding_lines(target_repo_path, file_path1, commit1, file_path2, commit2, [])
    print(corresponding_lines)