[x] Deterministic “extra patch” tool for undeclared symbols (port from `revert_patch_test.py`)
  - [x] Expand build-log parsing to include selected `warning:` diagnostics (at least: “call to undeclared function …”) so react_agent can act on them.
  - [x] Add tool `make_extra_patch_override(...)`:
    - [x] Infer `_extra_<file>` patch_key from the build error’s `file_path` (e.g. `dict.c` → `_extra_dict.c`).
    - [x] For `__revert_*` function names: extract a prototype from an existing `__revert_*` definition in the patch bundle when possible (KB won’t contain generated names).
    - [x] Fallback: use KB/JSON (via `KbIndex` + `search_definition`-style extents) to locate a definition/decl/macro/typedef and synthesize a safe insertion block (prototype / `#define` / `typedef`).
    - [x] Insert the generated block into the extra patch hunk and recompute hunk header lengths; return a full override diff (never truncated).
  - [x] Integrate into patch-scope flow:
    - [x] Register tool in `tools/registry.py` + `tools/runner.py` and ensure patch tools use the effective `state.patch_path`.
    - [x] In `agent_langgraph.py`, treat this tool as “patch generated” (same lifecycle as `make_error_patch_override`) and persist an updated effective bundle.
    - [x] Keep `active_patch_key` pinned (do not drift) even when the tool targets an `_extra_*` patch_key.
    - [x] Update the system prompt to recommend this tool for undeclared symbols instead of inventing/inlining declarations in function bodies.
  - [x] Add regression tests:
    - [x] `build_log.iter_compiler_errors` includes the targeted warnings.
    - [x] `make_extra_patch_override` can insert a forward declaration into an `_extra_*` hunk from a minimal pickle bundle.

[x] Fix `make_extra_patch_override` selecting statement-level “definitions” (e.g. `DECL_REF_EXPR`)
  - [x] Reproduce `xmlRngMutex` KB lookup: V1 JSON contains `DECL_REF_EXPR` with `type_ref.typedef_extent` pointing at `static xmlMutex xmlRngMutex;`.
  - [x] Prefer declaration extents (e.g. `type_ref.typedef_extent` → pseudo `VAR_DECL`) and reject expression-only matches so we never insert a statement like `xmlInitMutex(&xmlRngMutex);` at file scope.
  - [x] Add regression test for the `DECL_REF_EXPR` + `type_ref.typedef_extent` case.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Fix `kb_search_symbols` kind-filter mismatch for file-scope vars only present as `DECL_REF_EXPR`
  - [x] Confirm root cause: libclang JSON lacks `VAR_DECL` nodes for some file-scope vars; references show `type_ref.target_kind=VAR_DECL` + `type_ref.typedef_extent` with the real declaration line.
  - [x] Update `AgentTools.kb_search_symbols` to expand nodes via `KbIndex.related_definition_candidates(...)` *before* applying `kinds=` filtering, so `kinds=['VAR_DECL']` can still return pseudo `VAR_DECL` extents.
  - [x] Extend regression test: `kb_search_symbols(['xmlRngMutex'], kinds=['VAR_DECL'])` returns `exists=true` and includes `static xmlMutex xmlRngMutex;` from the derived extent.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Prefer `_extra_*` declarations over “delete the symbol” function rewrites
  - [x] Add guardrail: if current diagnostic is an undeclared symbol/type/macro and KB shows it exists in V1 (VAR_DECL / TYPEDEF_DECL / MACRO_DEFINITION / STRUCT_DECL / …), force `make_extra_patch_override` instead of allowing `make_error_patch_override` to remove references (preserve semantics).
  - [x] Ensure guardrail runs only after patch prereqs (`get_error_patch_context`) and only once per symbol per run to avoid loops.
  - [x] Add regression test that a model proposing a function rewrite for an undeclared global is rewritten to `make_extra_patch_override` when prior `kb_search_symbols` indicates `exists=true`.
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Refactor system prompt into modular fragments (reduce default prompt size)
  - [x] Create `script/react_agent/prompts/` with small, focused prompt fragments (base / tools / patch-scope / merged-tail / macro / struct-members).
  - [x] Add prompt builder module to load + cache fragments and assemble a conditional system prompt based on `AgentState` (avoid including patch-scope/macro/merged guidance when irrelevant).
  - [x] Update `agent_langgraph.py` to use the new prompt builder (keep behavior/guardrails unchanged).
  - [x] Add a regression test that verifies prompt composition (e.g. `error_scope=first` prompt omits patch-scope section; `error_scope=patch` includes it).
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Fix `make_extra_patch_override` for undeclared `__revert_*` calls (tmp3.log steps 20–27)
  - [x] Reproduce: ensure the bundle contains both a call-site and a definition for `__revert_*` and observe the current bad prototype extraction (e.g. `if (...) ;`).
  - [x] Make prototype extraction robust:
    - [x] Only treat file-scope lines as prototype/definition candidates (skip indented body statements and preprocessor directives).
    - [x] Validate extracted prototypes (must contain the symbol name, no `=`/control-stmt keywords, ends with `;`).
    - [x] If bundle-extraction is invalid, fall back to KB-derived signature (underlying symbol) and rename to `__revert_*`.
  - [x] Add regression test covering the call-site-before-definition case (pre-fix fails; post-fix extracts correct prototype).
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Struct-member workflow: stop using `kb_search_symbols` for fields
  - [x] Update `system_struct_members` prompt to rely on `search_definition(struct)` + field-list inspection, not `kb_search_symbols`.
  - [x] Flip `_struct_member_search_guardrail_for_search_definition`: rewrite `search_definition(ctxt->field)` → `search_definition(struct ...)` instead of `kb_search_symbols`.
  - [x] Make `kb_search_symbols.kinds` tolerant to LLM-style aliases (`VARIABLE/OBJECT/TYPE/...`) so non-struct cases don't fail due to invalid kind strings.
  - [x] Update regression tests and run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] Remove `kb_search_symbols` tool entirely (use `search_definition` + deterministic patch tools instead)
  - [x] Remove `kb_search_symbols` from the tool registry and runner (so it is not exposed/usable as a tool).
  - [x] Add a compatibility rewrite: if the model still outputs `tool=kb_search_symbols`, rewrite to `search_definition` (first symbol) instead of crashing.
  - [x] Replace macro-lookup guardrails that depended on `kb_search_symbols`:
    - [x] Remove the kb_search_symbols-driven `macro_lookup` state machine.
    - [x] For macro-expansion errors: prefer `make_extra_patch_override(symbol_name=<TOKEN>)` rather than inventing `#define`.
  - [x] Simplify undeclared-symbol guardrail: for “undeclared identifier/function/type name …”, force `make_extra_patch_override` once per symbol before allowing `make_error_patch_override`.
  - [x] Update prompt fragments + docs to stop mentioning `kb_search_symbols` (`system_macro.txt`, `README.md`, `AGENTS.md`).
  - [x] Update regression tests and run `bash script/react_agent/test_langgraph_agent.sh`.
  - [x] Post reminder to `#report`.

[x] multi_agent: include all required override diffs in `summary.json`
  - [x] Parse `agent_stdout.json.steps` to collect override diff artifacts from `make_error_patch_override` and `make_extra_patch_override` (do not rely on only `next_step`).
  - [x] When a hunk run ends on `make_extra_patch_override`, still include the hunk’s latest `make_error_patch_override` diff (e.g. `.../209443265285/make_error_patch_override_patch_text_dict.c.5.diff`).
  - [x] Pick one “latest” override diff per patch_key (mtime + numeric suffix) and sort by `PatchInfo.new_start_line(desc)` for bottom-up application.
  - [x] Add regression test in `script/react_agent/test_multi_agent.sh`.
  - [x] Run `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.

[x] make_extra_patch_override: avoid inserting opaque-by-value globals (e.g. `xmlMutex`)
  - [x] Detect when the chosen `VAR_DECL` defines an object of an opaque typedef in V2 (common pattern: `typedef struct TAG T;` where `struct TAG` is only defined in a `.c` file).
  - [x] Rewrite inserted code to a pointer form (prefer `TPtr` typedef when it exists, else `T *`) to avoid errors like “tentative definition has type 'T' that is never completed”.
  - [x] If the symbol is already present in the `_extra_*` hunk but uses an unsafe by-value opaque type, rewrite that existing line and emit a new override diff (do not no-op).
  - [x] Add regression tests for:
    - [x] initial insertion rewrite (v1 var decl → v2 pointer decl)
    - [x] “already present” rewrite (upgrade existing unsafe decl)
  - [x] Run `bash script/react_agent/test_langgraph_agent.sh` and `bash script/react_agent/test_multi_agent.sh`.
  - [x] Post reminder to `#report`.
