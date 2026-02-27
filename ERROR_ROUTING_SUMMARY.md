# React Agent Error Routing Summary

This file summarizes how `script/react_agent/agent_langgraph.py` currently routes diagnostics to tools.

Scope:
- Patch-scope flow (`--error-scope patch`) with patch bundle tools.
- Source of truth is current code + prompt files under `script/react_agent/prompts/`.

## 1) High-Level Routing Order

When the model returns a tool decision, routing/guardrails are applied in this order:

1. Location normalization for mapping tools.
- `get_error_patch_context` and `get_link_error_patch_context` are forced to active parsed error location.

2. Struct-field query rewrite.
- If model does `search_definition` on a member name (`nsdb`, `ctxt->nsdb`), it is rewritten to parent struct lookup.

3. Override safety/repair guardrails (for `make_error_patch_override`).
- Single-slice scope only.
- Preserve signature.
- Preserve function name.
- Ensure complete function body when base is function-scoped.
- Do not mass-drop `__revert_*` symbols.
- Do not introduce new `__revert_*` symbols.

4. Forced error-specific routing guardrails.
- `__revert_*` missing definition -> `make_extra_patch_override(..., prefer_definition=true)`.
- missing prototype warning -> `make_extra_patch_override`.
- undeclared symbol/type route guardrail.
- incomplete type guardrail.
- macro define guardrail.

5. Patch prerequisite tool ordering.
- Mapping/context tools are forced before patching tools.

6. `_extra_*` hunk block.
- If active patch_key is `_extra_*`, block direct `make_extra_patch_override` and force `read_artifact` then rewrite with `make_error_patch_override`.

7. Read-before-override enforcement.
- If attempting `make_error_patch_override` without a fresh `read_artifact`, force `read_artifact` first.

## 2) Error-Type Routing Matrix

## A) Undeclared Symbol/Type/Function (`_UNDECLARED_SYMBOL_RE`)

Trigger regex includes:
- `use of undeclared identifier 'X'`
- `call to undeclared function 'X'`
- `implicit declaration of function 'X'`
- `unknown type name 'X'`
- `undeclared function 'X'`

Routing:
- `__revert_*` symbol:
  - Route to `make_extra_patch_override(symbol_name=__revert_...)`.
- Non-`__revert_*` + `use of undeclared identifier` or `unknown type name`:
  - Route to `make_extra_patch_override(symbol_name=X)`.
- Non-`__revert_*` + undeclared function call:
  - Do NOT force `make_extra`; expected route is caller rewrite (`make_error_patch_override`) to remove/adapt call.

Batch-before-build behavior:
- After a patch is generated and before OSS-Fuzz build, remaining grouped undeclared symbols are auto-fixed via `make_extra_patch_override`.
- In grouped mode, non-`__revert_*` undeclared function-call errors are excluded from this batch.

Default toggle:
- `REACT_AGENT_ENABLE_UNDECLARED_SYMBOL_GUARDRAIL` is enabled by default.
- If unset -> enabled.
- Set `0/false/no/off` to disable.

## B) Incomplete Type (`_INCOMPLETE_TYPE_RE`)

Examples:
- `incomplete definition of type '...'`
- `invalid application of 'sizeof' to an incomplete type '...'`
- `dereferencing pointer to incomplete type`

Routing:
- Force `make_extra_patch_override(symbol_name=<type candidate>)`.
- Prevent function-rewrite workaround for this class.
- Up to 2 attempts per symbol candidate.

Candidate extraction behavior:
- For `struct _Foo`, candidates include `Foo` then `_Foo`.
- For `enum Tag`, candidate `Tag`.

## C) Missing Prototype Warning (`_MISSING_PROTOTYPE_RE`)

Example:
- `no previous prototype for function '__revert_*'`

Routing:
- Force `make_extra_patch_override(symbol_name=<function>)`.
- Prototype/declaration mode (no prefer_definition).

## D) Unresolved `__revert_*` Definition

Triggers:
- `function '__revert_*' has internal linkage but is not defined`
- `undefined reference to '__revert_*'`

Routing:
- Force `make_extra_patch_override(symbol_name=__revert_..., prefer_definition=true)`.
- This is the full-definition insertion path (not just prototype).

## E) Visibility Warning (`_VISIBILITY_DECL_RE`)

Example:
- `declaration of 'struct/union/enum X' will not be visible outside of this function`

Routing:
- In pre-build grouped-error phase, add forward declaration via `make_extra_patch_override(symbol_name="struct X" | "enum X" | "union X")`.

## F) Macro Errors / Missing Macro Definitions

Routing mechanisms:
1. Macro preflight:
- If active error is undeclared-style + snippet contains `expanded from macro` + missing macro tokens are known:
  - Force `make_extra_patch_override(symbol_name=<macro token>)`.

2. Override macro define guardrail:
- If model tries to add `#define` in `make_error_patch_override.new_func_code` for a token missing in slice:
  - Rewrite to `make_extra_patch_override(symbol_name=<token>)`.

Policy intent:
- Put macro definitions in `_extra_*`, not invented inline in function body.

## G) Struct Member Errors (`_MISSING_MEMBER_RE`)

Example:
- `no member named 'field' in 'struct X'`

Routing:
- Force prerequisite sequence before finalization:
  1. `get_error_patch_context`
  2. `search_definition("struct X", version="v1")`
  3. `search_definition("struct X", version="v2")`
- If model does member-only symbol lookup, rewrite to struct lookup.
- Adapt caller/function body based on v1/v2 struct diff via patch rewrite tools.

## H) Function Signature / Call-Argument Mismatch

Examples:
- `too few arguments to function call`
- `too many arguments to function call`

Tool routing rule:
- If `editable_hunk` is non-empty -> use `revise_patch_hunk`.
- If `editable_hunk` is empty -> use `make_error_patch_override`.

Applies to both `__revert_*` callees (lookup in v1 after stripping prefix) and non-`__revert_*` callees (lookup in v2).

## I) Linker Context Mapping

If compiler file:line is unavailable but linker context exists:
- Use `_first_link_error_location`.
- Route mapping through `get_link_error_patch_context`.
- Patch rewrite via `make_link_error_patch_override` as needed.

## 3) `_extra_*` Special Rule

If active patch_key starts with `_extra_`:
- Direct `make_extra_patch_override` is blocked in normal decision flow.
- Agent forces `read_artifact` and then rewrites current `_extra_*` content with `make_error_patch_override`.

Reason:
- Prevent repeatedly extending the same `_extra_*` hunk and causing cascades.

Precedence caveat:
- Some earlier force-guardrails can return a forced `make_extra_patch_override` before `_extra_*` blocking logic runs.
- So the intended `_extra_*` rule is strong, but not absolute in every path.

## 4) Mandatory Test Routing

After any successful patch-generation tool (`make_error_patch_override`, `make_extra_patch_override`, `revise_patch_hunk`):
- Agent must run `ossfuzz_apply_patch_and_test` before final success/stop.

Also before build:
- Agent may inject additional grouped undeclared/visibility fixes via `make_extra_patch_override` first.

## 5) Safety Guardrails for `make_error_patch_override`

These are not error classes, but they gate routing success:
- Must rewrite only mapped active slice.
- Must not include unified-diff headers in `new_func_code`.
- Must preserve function signature and name.
- Must produce complete body when base slice is function-scoped.
- Must not broadly remove existing `__revert_*` symbols.
- Must not introduce new `__revert_*` symbols.

## 6) Prompts Aligned to Routing

Primary prompt files that define policy for these routes:
- `system_patch_scope.txt`
- `system_mapped_slice_rewrite.txt`
- `system_undeclared_symbol.txt`
- `system_incomplete_type.txt`
- `system_missing_prototypes.txt`
- `system_macro.txt`
- `system_struct_members.txt`
- `system_visibility.txt`
- `system_linker_error.txt`
- `system_conflicting_types.txt`
- `system_func_sig_change.txt`
