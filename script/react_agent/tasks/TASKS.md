## Current Plan (unarchived)

- [ ] Stop forcing `read_file_context(context=80)` in macro-lookup guardrail (`script/react_agent/agent_langgraph.py`); keep forcing only `kb_search_symbols` (v2 → v1).
- [ ] Update the system prompt (`script/react_agent/agent_langgraph.py`) to remove “context=80” and instruct the model to choose an appropriate context window (large enough to include full `#if/#endif` blocks when needed).
- [ ] Update `script/react_agent/test_langgraph_agent.sh` to remove assumptions about `context=80` and add a small unit test ensuring the runtime doesn’t inject a fixed context value.
