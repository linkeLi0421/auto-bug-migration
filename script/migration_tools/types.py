from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional, Set


@dataclass(frozen=True)
class FunctionLocation:
    """Location of a function/type region in source code."""

    file_path: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        if self.start_line > self.end_line:
            raise ValueError(f"start_line ({self.start_line}) must be <= end_line ({self.end_line})")


@dataclass
class PatchInfo:
    """A single unified-diff patch plus metadata used by the migration pipeline."""

    file_path_old: str
    file_path_new: str
    patch_text: str
    file_type: str

    old_start_line: int
    old_end_line: int
    new_start_line: int
    new_end_line: int

    patch_type: Set[str] = field(default_factory=set)

    old_signature: Optional[str] = None
    new_signature: Optional[str] = None
    old_function_start_line: Optional[int] = None
    old_function_end_line: Optional[int] = None
    new_function_start_line: Optional[int] = None
    new_function_end_line: Optional[int] = None

    dependent_func: Set[str] = field(default_factory=set)
    hiden_func_dict: Dict[str, int] = field(default_factory=dict)
    recreated_function_locations: Dict[str, FunctionLocation] = field(default_factory=dict)

    def has_type(self, patch_type: str) -> bool:
        return patch_type in self.patch_type

    @property
    def is_function_modification(self) -> bool:
        return bool(self.old_signature or self.new_signature)

    def _get_function_name_from_sig(self, signature: Optional[str]) -> Optional[str]:
        if not signature:
            return None
        try:
            return signature.split("(")[0].split()[-1]
        except IndexError:
            return None

    @property
    def old_function_name(self) -> Optional[str]:
        return self._get_function_name_from_sig(self.old_signature)

    @property
    def new_function_name(self) -> Optional[str]:
        return self._get_function_name_from_sig(self.new_signature)

    @property
    def is_file_deletion(self) -> bool:
        return self.file_path_new == "/dev/null"

    @property
    def is_file_addition(self) -> bool:
        return self.file_path_old == "/dev/null"

    def __str__(self) -> str:
        patch_types = ", ".join(sorted(self.patch_type)) if self.patch_type else "none"
        dependent_funcs = ", ".join(sorted(self.dependent_func)) if self.dependent_func else "none"
        preview_lines = [line.strip() for line in self.patch_text.strip().splitlines() if line.strip()]
        if preview_lines:
            preview = preview_lines[0]
            if len(preview_lines) > 1:
                preview += " ..."
            if len(preview) > 80:
                preview = f"{preview[:77]}..."
        else:
            preview = "<empty>"
        v_old = str(Path(str(self.file_path_old)).as_posix())
        v_new = str(Path(str(self.file_path_new)).as_posix())
        return (
            "PatchInfo("
            f"{v_old} -> {v_new}, "
            f"type={self.file_type}, "
            f"old_lines={self.old_start_line}-{self.old_end_line}, "
            f"new_lines={self.new_start_line}-{self.new_end_line}, "
            f"patch_types={patch_types}, "
            f"dependent_funcs={dependent_funcs}, "
            f"old_sig={self.old_signature}, "
            f"new_sig={self.new_signature}, "
            f"preview='{preview}'"
            ")"
        )

