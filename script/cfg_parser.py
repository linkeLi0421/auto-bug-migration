import re
from collections import defaultdict
from typing import List, Dict, Optional


class CFGBlock:
    def __init__(self, block_id: int, is_entry=False, is_exit=False):
        self.block_id = block_id
        self.is_entry = is_entry
        self.is_exit = is_exit
        self.statements = []
        self.preds = []
        self.succs = []
        self.start_line: Optional[int] = None
        self.end_line: Optional[int] = None

    def __repr__(self):
        return f"B{self.block_id} ({self.start_line}-{self.end_line})"


class SourceCFG:
    def __init__(self, function_signature: str):
        self.function_signature = function_signature
        self.file_path: Optional[str] = None
        self.signature_line: Optional[int] = None
        self.blocks: Dict[int, CFGBlock] = {}

    def add_block(self, block: CFGBlock):
        self.blocks[block.block_id] = block

    def get_block(self, block_id: int) -> Optional[CFGBlock]:
        return self.blocks.get(block_id)

    def __repr__(self):
        return (f"<CFG for {self.function_signature} "
                f"defined at {self.file_path}:{self.signature_line} "
                f"with {len(self.blocks)} blocks>")

    def print_summary(self):
        print(f"Function: {self.function_signature}")
        if self.file_path:
            print(f"  File: {self.file_path}:{self.signature_line}")
        for block_id in sorted(self.blocks):
            blk = self.blocks[block_id]
            print(f"  Block {blk.block_id} | Lines: {blk.start_line}-{blk.end_line} | "
                  f"Preds: {blk.preds} | Succs: {blk.succs}")


def parse_cfg_text(cfg_text: str) -> List[SourceCFG]:
    lines = cfg_text.strip().splitlines()
    cfgs = []
    current_cfg = None
    current_block = None

    block_header_re = re.compile(r'\[B(\d+)(?: \((ENTRY|EXIT)\))?\]')
    preds_re = re.compile(r'Preds \((\d+)\): (.+)')
    succs_re = re.compile(r'Succs \((\d+)\): (.+)')
    from_line_re = re.compile(r'from line (\d+) to line (\d+)')
    func_sig_re = re.compile(r'^Function signature: (.+)$')
    file_line_re = re.compile(r'^Defined in file: (.+) at line (\d+)$')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        func_match = func_sig_re.match(line)
        if func_match:
            if current_cfg:
                cfgs.append(current_cfg)
            current_cfg = SourceCFG(func_match.group(1))
            continue

        file_match = file_line_re.match(line)
        if file_match and current_cfg:
            current_cfg.file_path = file_match.group(1)
            current_cfg.signature_line = int(file_match.group(2))
            continue

        block_match = block_header_re.match(line)
        if block_match:
            block_id = int(block_match.group(1))
            entry_exit = block_match.group(2)
            is_entry = entry_exit == "ENTRY"
            is_exit = entry_exit == "EXIT"

            current_block = CFGBlock(block_id, is_entry, is_exit)
            if current_cfg:
                current_cfg.add_block(current_block)
            continue

        if current_block:
            if line.startswith(tuple(str(i) for i in range(10))):
                current_block.statements.append(line)

            pred_match = preds_re.match(line)
            if pred_match:
                tokens = pred_match.group(2).split()
                current_block.preds = []
                for token in tokens:
                    # Assuming the first character is some prefix (like 'B' for block)
                    if len(token) > 1:
                        numeric_part = token[1:]
                        if numeric_part.isdigit():
                            current_block.preds.append(int(numeric_part))
                continue

            succ_match = succs_re.match(line)
            if succ_match:
                tokens = succ_match.group(2).split()
                current_block.succs = []
                for token in tokens:
                    # Assuming the first character is some prefix (like 'B' for block)
                    if len(token) > 1:
                        numeric_part = token[1:]
                        if numeric_part.isdigit():
                            current_block.succs.append(int(numeric_part))
                continue

            range_match = from_line_re.match(line)
            if range_match:
                current_block.start_line = int(range_match.group(1))
                current_block.end_line = int(range_match.group(2))
                continue

    if current_cfg:
        cfgs.append(current_cfg)

    return cfgs


def find_block_by_line(cfgs, file_name, line_number_list):
    cfg1 = None
    blocks = []
    for cfg in cfgs:
        if not (cfg.file_path == file_name):
            continue
        for block in cfg.blocks.values():
            if block.start_line is not None and block.end_line is not None:
                for line_number in line_number_list:
                    if block.start_line <= line_number <= block.end_line:
                        if not cfg1:
                            cfg1 = cfg
                        blocks.append(block)
    return cfg1, blocks


if __name__ == "__main__":
    text = """
    Function signature: int LLVMFuzzerTestOneInput(const uint8_t * data, int size)
    Defined in file: fuzz_decompress_chunk.c at line 10

    [B0 (EXIT)]
    Preds (4): B1 B4 B6 B8


    [B1]
    1: blosc_destroy()
    2: 0
    3: return [B1.2];
    Preds (2): B2 B3
    Succs (1): B0

    from line 38 to line 39

    [B2]
    1: free(output)
    Preds (1): B3
    Succs (1): B1

    from line 35 to line 35

    [B3]
    1: <recovery-expr>()
    T: if [B3.1]
    Preds (1): B5
    Succs (2): B2 B1

    from line 33 to line 33

    [B4]
    1: blosc_destroy()
    2: 0
    3: return [B4.2];
    Preds (1): B5
    Succs (1): B0

    from line 28 to line 29

    [B5]
    1: <recovery-expr>()
    T: if [B5.1]
    Preds (1): B7
    Succs (2): B4 B3

    from line 26 to line 26

    [B6]
    1: blosc_destroy()
    2: 0
    3: return [B6.2];
    Preds (1): B7
    Succs (1): B0

    from line 23 to line 24

    [B7]
    1: blosc_init()
    2: blosc_set_nthreads(1)
    3: <recovery-expr>()
    T: if [B7.3]
    Preds (1): B9
    Succs (2): B6 B5

    from line 18 to line 22

    [B8]
    1: 0
    2: return [B8.1];
    Preds (1): B9
    Succs (1): B0

    from line 15 to line 15

    [B9]
    1: void *output;
    2: <recovery-expr>() < BLOSC_MIN_HEADER_LENGTH
    T: if [B9.2]
    Preds (1): B10
    Succs (2): B8 B7

    from line 12 to line 14

    [B10 (ENTRY)]
    Succs (1): B9

    """

    cfgs = parse_cfg_text(text)
    for cfg in cfgs:
        cfg.print_summary()
    _, blocks = find_block_by_line(cfgs, "fuzz_decompress_chunk.c", [23])
