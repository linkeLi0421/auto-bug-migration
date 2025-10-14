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
        self.defs = set()  # Variables defined in this block
        self.uses = set()  # Variables used in this block
        self.data_dependencies = defaultdict(set)  # variable -> set of block_ids (defs this block depends on)

    def __repr__(self):
        return f"B{self.block_id} ({self.start_line}-{self.end_line}) defs:{list(self.defs)} uses:{list(self.uses)}"


class SourceCFG:
    def __init__(self, function_signature: str):
        self.function_signature = function_signature
        self.file_path: Optional[str] = None
        self.signature_line: Optional[int] = None
        self.blocks: Dict[int, CFGBlock] = {}
        self.variable_defs = defaultdict(set)  # variable -> set of block_ids where defined
        self.variable_uses = defaultdict(set)  # variable -> set of block_ids where used

    def add_block(self, block: CFGBlock):
        self.blocks[block.block_id] = block

    def get_block(self, block_id: int) -> Optional[CFGBlock]:
        return self.blocks.get(block_id)

    def __repr__(self):
        return (f"<CFG for {self.function_signature} "
                f"defined at {self.file_path}:{self.signature_line} "
                f"with {len(self.blocks)} blocks>")


    def get_line_range(self) -> tuple[int, int]:
        """Get the start and end line numbers for this CFG.
        
        Returns:
            tuple[int, int]: (start_line, end_line) representing the range
                           of lines covered by all blocks in this CFG
        """
        if not self.blocks:
            return (0, 0)
        
        all_lines = []
        for block in self.blocks.values():
            if block.start_line is not None and block.end_line is not None:
                all_lines.extend([block.start_line, block.end_line])
        
        if not all_lines:
            return (0, 0)
            
        return (min(all_lines), max(all_lines))


    def print_summary(self):
        print(f"Function: {self.function_signature}")
        if self.file_path:
            print(f"  File: {self.file_path}:{self.signature_line}")
        start_line, end_line = self.get_line_range()
        print(f"  Line range: {start_line}-{end_line}")
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
    defuse_chain_re = re.compile(r'Def-Use Chain:')
    defuse_entry_re = re.compile(r'\s*(USE|DEF)\s+(\S+).*?(\d+)\s*\(([^)]+)\)')
    in_defuse_chain = False

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
            in_defuse_chain = False
            continue

        if current_block:
            if line.startswith(tuple(str(i) for i in range(10))):
                current_block.statements.append(line)

            pred_match = preds_re.match(line)
            if pred_match:
                tokens = pred_match.group(2).split()
                current_block.preds = []
                for token in tokens:
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

            if defuse_chain_re.match(line):
                in_defuse_chain = True
                continue

            if in_defuse_chain:
                m = defuse_entry_re.match(line)
                if m:
                    kind, var, line_num, event_type = m.groups()
                    if event_type in ("assignment", "variable_use"):
                        current_block.uses.add(var)
                        if current_cfg:
                            current_cfg.variable_uses[var].add(current_block.block_id)
                    if event_type == "variable_declaration":
                        current_block.defs.add(var)
                        if current_cfg:
                            current_cfg.variable_defs[var].add(current_block.block_id)
                else:
                    in_defuse_chain = False

    if current_cfg:
        cfgs.append(current_cfg)

    return cfgs


def find_block_by_line(cfgs, file_name, line_number_list):
    cfg1 = None
    blocks = []
    for cfg in cfgs:
        if not cfg.file_path:
            # A temp fix
            continue
        if not (cfg.file_path == file_name or cfg.file_path.endswith(file_name)):
            continue
        for block in cfg.blocks.values():
            if block.start_line is not None and block.end_line is not None:
                for line_number in line_number_list:
                    if block.start_line <= line_number <= block.end_line:
                        if not cfg1:
                            cfg1 = cfg
                        blocks.append(block)
    return cfg1, blocks


def compute_data_dependencies(cfg: SourceCFG):
    # For each variable, for each use, find all defs in other blocks in the same function
    for var in cfg.variable_defs:
        def_blocks = cfg.variable_defs[var]
        use_blocks = cfg.variable_uses.get(var, set())
        for use_block_id in use_blocks:
            for def_block_id in def_blocks:
                if use_block_id != def_block_id:
                    block = cfg.get_block(use_block_id)
                    if block:
                        block.data_dependencies[var].add(def_block_id)


if __name__ == "__main__":
    text = """
    Function signature: int blosc2_register_io_cb(const blosc2_io_cb * io)
    Defined in file: blosc2.c at line 4633
    [B0]
    Preds (4): B1 B2 B9 B17
    from line 21960 to line 1

    [B1]
    Preds (1): B8
    Succs (1): B0
    Def-Use Chain:
        USE io used at line 4645 (variable_use)
    from line 4645 to line 4645

    [B2]
    Preds (2): B5 B3
    Succs (1): B0
    from line 4642 to line 4642

    [B3]
    Preds (1): B4
    Succs (1): B2
    from line 4641 to line 4641

    [B4]
    Preds (1): B6
    Succs (1): B3
    Def-Use Chain:
        USE stderr used at line 4641 (variable_use)
    from line 4641 to line 4641

    [B5]
    Preds (1): B6
    Succs (1): B2
    from line 4641 to line 4641

    [B6]
    Preds (2): B7 B8
    Succs (2): B5 B4
    Def-Use Chain:
        DEF __e at line 4641 (variable_declaration)
        USE __e used at line 4641 (variable_use)
    from line 4641 to line 4641

    [B7]
    Succs (1): B6
    from line 4641 to line 4641

    [B8]
    Preds (1): B15
    Succs (2): B6 B1
    Def-Use Chain:
        USE io used at line 4640 (variable_use)
    from line 4640 to line 4640

    [B9]
    Preds (2): B12 B10
    Succs (1): B0
    from line 4637 to line 4637

    [B10]
    Preds (1): B11
    Succs (1): B9
    from line 4636 to line 4636

    [B11]
    Preds (1): B13
    Succs (1): B10
    Def-Use Chain:
        USE stderr used at line 4636 (variable_use)
    from line 4636 to line 4636

    [B12]
    Preds (1): B13
    Succs (1): B9
    from line 4636 to line 4636

    [B13]
    Preds (2): B14 B15
    Succs (2): B12 B11
    Def-Use Chain:
        DEF __e at line 4636 (variable_declaration)
        USE __e used at line 4636 (variable_use)
    from line 4636 to line 4636

    [B14]
    Succs (1): B13
    from line 4636 to line 4636

    [B15]
    Preds (1): B16
    Succs (2): B13 B8
    Def-Use Chain:
        USE g_nio used at line 4635 (variable_use)
    from line 4635 to line 4635

    [B16]
    Preds (1): B23
    Succs (1): B15
    from line 4634 to line 4634

    [B17]
    Preds (2): B20 B18
    Succs (1): B0
    from line 4634 to line 4634

    [B18]
    Preds (1): B19
    Succs (1): B17
    from line 4634 to line 4634

    [B19]
    Preds (1): B21
    Succs (1): B18
    Def-Use Chain:
        USE stderr used at line 4634 (variable_use)
    from line 4634 to line 4634

    [B20]
    Preds (1): B21
    Succs (1): B17
    from line 4634 to line 4634

    [B21]
    Preds (2): B22 B23
    Succs (2): B20 B19
    Def-Use Chain:
        DEF __e at line 4634 (variable_declaration)
        USE __e used at line 4634 (variable_use)
    from line 4634 to line 4634

    [B22]
    Succs (1): B21
    from line 4634 to line 4634

    [B23]
    Preds (2): B24 B25
    Succs (2): B21 B16
    from line 4634 to line 4634

    [B24]
    Succs (1): B23
    from line 4634 to line 4634

    [B25]
    Succs (1): B23
    from line 4634 to line 4634
    """

    cfgs = parse_cfg_text(text)
    for cfg in cfgs:
        compute_data_dependencies(cfg)
        cfg.print_summary()
    _, blocks = find_block_by_line(cfgs, "fuzz_decompress_chunk.c", [23])
