# OSS-Fuzz for Select

This repository contains scripts and examples used to explore automated fuzzing workflows.  It is focused on building and testing fuzzing harnesses for specific open-source projects.

## Repository structure
- `Function_instrument/` – simple instrumentation example with a `Makefile` and `trace.c`.
- `script/` – assorted Python utilities for building targets, running fuzzers and analysing bug data.
- `cfg-clang/` and `oss-fuzz/` – configuration and data directories used by the scripts.

## Requirements
- Python 3.8+
- Clang/LLVM toolchain
- git

## Usage
Most functionality lives in the `script` directory.  For example, to build a fuzzing target and run tests:

```bash
python script/buildAndtest.py --help
python script/run_fuzz_test.py --help
```

## Contributing
Pull requests and bug reports are welcome.  Please ensure that all scripts pass basic syntax checks before submitting changes.

