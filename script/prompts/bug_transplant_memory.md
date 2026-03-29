# Bug Transplant -- Shared Knowledge

This file describes the **target commit** code only. All bugs transplant
into the same target, so knowledge about the target is reusable.

Do NOT write information about specific buggy commits or old-vs-new comparisons
here -- those differ per bug. Only write what is true about the target commit.

## Project: {project}
## Target commit: {target_commit}
## Fuzzer: {fuzzer_name}

## Target Code Structure
<!-- How the parser/decoder works at the target commit: header layout, key structs,
     field offsets, data formats the target code expects -->

## Validation Checks in Target
<!-- Validation checks in the target code that may reject malformed inputs.
     Include function name, file, line, what they check, and what happens on failure -->

## Input Format at Target
<!-- What input format the target commit's parser expects: magic numbers, field sizes,
     byte order, required fields, trailer format -->

## Build Notes
<!-- Build quirks, workarounds, compile flags specific to this project -->
