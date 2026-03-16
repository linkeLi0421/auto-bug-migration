"""Per-project build quirks and configuration.

Some projects have build-system idiosyncrasies that affect how function names
appear in libclang AST output vs. source code.  This module provides a simple
registry so the pipeline can adapt without project-specific conditionals
scattered throughout the codebase.
"""

# Per-project configuration.  Keys are project names (as passed to --target).
PROJECT_CONFIG = {
    "unicorn": {
        # Unicorn/QEMU compiles the same source files once per target
        # architecture, using preprocessor macros to append arch suffixes
        # (e.g. #define disas_arm_insn disas_arm_insn_arm in qemu/arm.h).
        # The libclang AST sees the post-preprocessed names but source code
        # uses the bare names.
        "strip_function_suffixes": [
            "_arm", "_armeb", "_aarch64", "_aarch64eb",
            "_x86_64", "_i386",
            "_m68k",
            "_mips", "_mipsel", "_mips64", "_mips64el",
            "_ppc", "_ppc64",
            "_sparc", "_sparc64",
            "_riscv32", "_riscv64",
            "_s390x",
        ],
    },
}


def get_project_config(target):
    """Return the configuration dict for *target*, or empty dict if unknown."""
    return PROJECT_CONFIG.get(target, {})


def strip_function_suffix(name, target):
    """Strip build-system suffixes from a function name for *target* project.

    For projects without a config entry this is a no-op (returns *name* unchanged).
    """
    if not name:
        return name
    suffixes = get_project_config(target).get("strip_function_suffixes", [])
    for suffix in suffixes:
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name
