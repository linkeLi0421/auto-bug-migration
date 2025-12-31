# Tasks — react_agent (OpenAI + LangGraph)

## Objective

Build an LLM-driven agent that uses:

- OpenAI API for reasoning (model configurable)
- LangGraph for the agent loop / tool orchestration
- The existing tooling layer in `script/react_agent/agent_tools.py`

The agent should be able to read a build log, inspect evidence using tools, and produce a deterministic, machine-readable result (no patch application by default).

## Tasks

### Build-log parsing

- [x] Keep build-log parsing utilities in `script/react_agent/build_log.py`:
  - `load_build_log(path_or_stdin)`
  - `find_first_fatal(build_log)`

### Tooling layer (AgentTools)

- [x] Provide tools in `script/react_agent/agent_tools.py`:
  - `inspect_symbol(symbol_name)`
  - `read_file_context(file_path, line_number, context=5, version="v2")`
  - `search_definition_in_v1(symbol_name)`

### Dependencies & configuration

- [x] Decide the integration approach:
  - [x] Option A: direct OpenAI API calls + LangGraph (no LangChain dependency)
  - [ ] Option B: `langchain-openai` + LangGraph (ChatOpenAI wrapper)
- [x] Add dependency management (`requirements.txt` or `pyproject.toml`) for:
  - `langgraph`
  - OpenAI client (`openai` or `langchain-openai` + `langchain-core`)
- [x] Add a config layer (env vars + CLI flags):
  - `OPENAI_API_KEY`
  - `OPENAI_MODEL` (default)
  - Optional: `OPENAI_BASE_URL`, `OPENAI_ORG`, `OPENAI_PROJECT`
  - Paths for `--v1-json-dir`, `--v2-json-dir`, `--v1-src`, `--v2-src`

### Tool surface (for the graph)

- [x] Define the tool contract for the LLM (names + JSON args + return types):
  - `inspect_symbol({symbol_name})`
  - `read_file_context({file_path, line_number, context, version})`
  - `search_definition_in_v1({symbol_name})`
- [x] Implement a small wrapper layer (e.g. `tools_wrapper.py`) that:
  - Validates args types (best-effort)
  - Normalizes tool outputs into JSON-serializable values
  - Never raises uncaught exceptions (returns an error string/object instead)

### LangGraph agent

- [x] Add `agent_langgraph.py` (or `agent_graph.py`) that builds a LangGraph workflow:
  - Start: load build log and extract first error + snippet (reuse the existing parser)
  - LLM node: decide next action (tool call) using a strict JSON schema
  - Tool node: execute exactly one tool call and capture observation
  - Loop: feed observation back to LLM until it returns a final decision
- [x] Enforce safety / determinism:
  - Max tool steps (e.g. 3–5)
  - JSON-only model outputs (reject/retry if invalid)
  - No filesystem writes beyond logs (no patching) unless explicitly enabled

### Prompts & output schema

- [x] Define a system prompt that:
  - Explains the available tools and when to use them
  - Requires the model to output either:
    - `{"type":"tool","tool":"...","args":{...},"thought":"..."}` or
    - `{"type":"final","summary":"...","next_step":"...","thought":"..."}`
- [x] Make the final output stable and easy to parse (single JSON object on stdout).

### Tests

- [x] Add a test script (e.g. `test_langgraph_agent.sh`) that:
  - Runs the graph on the fixtures with the stub model
  - Asserts that:
    - output is valid JSON
    - tool calls are within the allowed set
    - the loop respects max steps

## Success Criteria

- [x] `agent_langgraph.py` runs end-to-end with the stub model (no network) and produces valid JSON.
- [ ] With a real OpenAI API key, the agent can complete at least one multi-step investigation on `tmp1` (network-enabled run) without crashing.
