import os
import subprocess
import sys
import re
from typing import List, Tuple, Optional
from bisect import bisect_right

gumtree_path = os.getenv('GUMTREE_PATH')

class DiffOperation:
    def __init__(
        self,
        label: str,
        span1: Tuple[int, int],
        span2: Tuple[int, int],
        line1: int,
        line2: int
    ):
        self.op_type = "match"
        self.label = label
        self.span1 = span1
        self.span2 = span2
        self.line1 = line1  # line number in original file 1
        self.line2 = line2  # line number in original file 2

    def __repr__(self):
        return (f"<match {self.label}: {self.span1} (line {self.line1}) ⇄ "
                f"{self.span2} (line {self.line2})>")


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
        self._parse()

    def _parse(self):
        # Split sections by '===\n' or lines that contain only '==='
        sections = re.split(r'^===\s*$', self.raw_text.strip(), flags=re.MULTILINE)

        for section in sections:
            lines = [line.strip() for line in section.strip().splitlines() if line.strip()]
            if not lines or lines[0] != "match":
                continue
            if len(lines) != 4:
                continue
            m1 = self._parse_line(lines[2])
            m2 = self._parse_line(lines[3])
            if not m1 or not m2:
                continue
            label1, start1, end1 = m1
            label2, start2, end2 = m2
            if label1 != label2:
                continue
            line1 = offset_to_line(self.offsets1, start1)
            line2 = offset_to_line(self.offsets2, start2)
            self.matches.append(
                DiffOperation(label1, (start1, end1), (start2, end2), line1, line2)
            )

    def _parse_line(self, line: str) -> Optional[Tuple[str, int, int]]:
        # Example line: "identifier: j [28021,28022]"
        match = re.match(r'^(.*?):\s*.*?\[(\d+),\s*(\d+)\]$', line)
        if not match:
            return None
        label, start, end = match.groups()
        return label.strip(), int(start), int(end)

    def get_matches(self) -> List[DiffOperation]:
        return self.matches


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
        if op.line1 in line_set:
            corresponding_lines.add(op.line2)
    return list(corresponding_lines)


if __name__ == "__main__":
    print("Usage: python gumtree.py <target_repo_path> <file_path1> <commit1> <file_path2> <commit2>")

    target_repo_path = sys.argv[1]
    file_path1 = sys.argv[2]
    commit1 = sys.argv[3]
    file_path2 = sys.argv[4]
    commit2 = sys.argv[5]

    corresponding_lines = get_corresponding_lines(target_repo_path, file_path1, commit1, file_path2, commit2, [])
    print(corresponding_lines)