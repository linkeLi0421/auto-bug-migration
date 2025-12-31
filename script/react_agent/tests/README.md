# react_agent tests

Manual smoke tests for `script/react_agent/agent_tools.py`.

- `script/react_agent/tests/tool_cli.py`: CLI wrapper used to exercise the tooling.
- `script/react_agent/README.md`: Overview and usage of the core library.

## CLI usage

Show help:
```bash
python3 script/react_agent/tests/tool_cli.py -h
```

Inspect a symbol (prints V1 + V2 code based on the node’s `extent`):
```bash
python3 script/react_agent/tests/tool_cli.py <symbol-or-usr> \
  --v1-json-dir /path/to/v1/json \
  --v2-json-dir /path/to/v2/json \
  --v1-src /path/to/v1/source/checkout \
  --v2-src /path/to/v2/source/checkout
```

List all matching nodes without printing code:
```bash
python3 script/react_agent/tests/tool_cli.py <symbol-or-usr> \
  --v1-json-dir /path/to/v1/json \
  --v2-json-dir /path/to/v2/json \
  --list --limit 50
```

## How to interpret results

- The CLI picks a “best” AST node for the given spelling/USR (definitions are preferred when present).
- If you pass an identifier like `ctxt`, you will often match a *reference* (`DECL_REF_EXPR`) rather than a declaration/definition; the printed code may be only a single line. In that case, inspect the owning function/type instead (e.g. `xmlSAX2ErrMemory`).
- Empty `Code:` usually means the node was found in JSON, but the corresponding source file could not be resolved/read. Ensure `--v1-src` and `--v2-src` point at real local checkouts whose layout matches the JSON `location.file` / `extent.*.file` values.

## Example run (test log)

This is a smoke-test log for `script/react_agent/tests/tool_cli.py`.

### Environment

- Timestamp: `2025-12-31T00:25:57+00:00`
- Python: `Python 3.12.3` (from `/home/user/pyenv/venv/bin/python3`)
- V1 JSON dir: `/home/user/oss-fuzz-build/data/libxml2-e11519`
- V2 JSON dir: `/home/user/oss-fuzz-build/data/libxml2-f0fd1b`
- V1 src root: `/home/user/tasks-git/libxml2/`
- V2 src root: `/home/user/tasks-git1/libxml2/`

### 1) Help text

Command:
```bash
/home/user/pyenv/venv/bin/python3 script/react_agent/tests/tool_cli.py -h
```

Output:
```text
usage: tool_cli.py [-h] --v1-json-dir V1_JSON_DIR --v2-json-dir V2_JSON_DIR
              [--v1-src V1_SRC] [--v2-src V2_SRC] [--list] [--limit LIMIT]
              symbol

Smoke-test CLI for react_agent tooling.

positional arguments:
  symbol                Symbol name or USR to inspect

options:
  -h, --help            show this help message and exit
  --v1-json-dir V1_JSON_DIR
                        Root directory containing V1 *_analysis.json files
  --v2-json-dir V2_JSON_DIR
                        Root directory containing V2 *_analysis.json files
  --v1-src V1_SRC       Local filesystem root for V1 source code
  --v2-src V2_SRC       Local filesystem root for V2 source code
  --list                List matching AST nodes (file:line:col kind) instead
                        of showing code
  --limit LIMIT         Max rows to print with --list
```

### 2) Inspect `ctxt` (identifier reference)

Command:
```bash
/home/user/pyenv/venv/bin/python3 script/react_agent/tests/tool_cli.py ctxt \
  --v1-json-dir /home/user/oss-fuzz-build/data/libxml2-e11519 \
  --v2-json-dir /home/user/oss-fuzz-build/data/libxml2-f0fd1b \
  --v1-src /home/user/tasks-git/libxml2/ \
  --v2-src /home/user/tasks-git1/libxml2/
```

Output:
```text
=== Version 1 ===
File: SAX2.c
Code:
    xmlErrMemory(ctxt, msg);

=== Version 2 ===
Status: Changed
File: SAX2.c
Code:
    if (ctxt != NULL) {
```

### 3) List AST nodes for `ctxt` (`--list`)

Command:
```bash
/home/user/pyenv/venv/bin/python3 script/react_agent/tests/tool_cli.py ctxt \
  --v1-json-dir /home/user/oss-fuzz-build/data/libxml2-e11519 \
  --v2-json-dir /home/user/oss-fuzz-build/data/libxml2-f0fd1b \
  --list --limit 10
```

Output:
```text
=== v1 nodes ===
HTMLparser.c:63:10 DECL_REF_EXPR
HTMLparser.c:63:28 DECL_REF_EXPR
HTMLparser.c:64:10 DECL_REF_EXPR
HTMLparser.c:66:9 DECL_REF_EXPR
HTMLparser.c:67:9 DECL_REF_EXPR
HTMLparser.c:68:9 DECL_REF_EXPR
HTMLparser.c:69:9 DECL_REF_EXPR
HTMLparser.c:72:43 DECL_REF_EXPR
HTMLparser.c:77:43 DECL_REF_EXPR
HTMLparser.c:96:10 DECL_REF_EXPR

=== v2 nodes ===
HTMLparser.c:79:10 DECL_REF_EXPR
HTMLparser.c:79:28 DECL_REF_EXPR
HTMLparser.c:80:10 DECL_REF_EXPR
HTMLparser.c:82:9 DECL_REF_EXPR
HTMLparser.c:83:9 DECL_REF_EXPR
HTMLparser.c:84:9 DECL_REF_EXPR
HTMLparser.c:85:9 DECL_REF_EXPR
HTMLparser.c:88:43 DECL_REF_EXPR
HTMLparser.c:93:43 DECL_REF_EXPR
HTMLparser.c:112:10 DECL_REF_EXPR
```

### 4) Inspect a function definition: `xmlSAX2ErrMemory`

Command:
```bash
/home/user/pyenv/venv/bin/python3 script/react_agent/tests/tool_cli.py xmlSAX2ErrMemory \
  --v1-json-dir /home/user/oss-fuzz-build/data/libxml2-e11519 \
  --v2-json-dir /home/user/oss-fuzz-build/data/libxml2-f0fd1b \
  --v1-src /home/user/tasks-git/libxml2/ \
  --v2-src /home/user/tasks-git1/libxml2/
```

Output:
```text
=== Version 1 ===
File: SAX2.c
Code:
static void LIBXML_ATTR_FORMAT(2,0)
xmlSAX2ErrMemory(xmlParserCtxtPtr ctxt, const char *msg) {
    xmlErrMemory(ctxt, msg);
}

=== Version 2 ===
Status: Changed
File: SAX2.c
Code:
static void LIBXML_ATTR_FORMAT(2,0)
xmlSAX2ErrMemory(xmlParserCtxtPtr ctxt, const char *msg) {
    xmlStructuredErrorFunc schannel = NULL;
    const char *str1 = "out of memory\n";

    if (ctxt != NULL) {
	ctxt->errNo = XML_ERR_NO_MEMORY;
	if ((ctxt->sax != NULL) && (ctxt->sax->initialized == XML_SAX2_MAGIC))
	    schannel = ctxt->sax->serror;
	__xmlRaiseError(schannel,
			ctxt->vctxt.error, ctxt->vctxt.userData,
			ctxt, NULL, XML_FROM_PARSER, XML_ERR_NO_MEMORY,
			XML_ERR_ERROR, NULL, 0, (const char *) str1,
			NULL, NULL, 0, 0,
			msg, (const char *) str1, NULL);
	ctxt->errNo = XML_ERR_NO_MEMORY;
	ctxt->instate = XML_PARSER_EOF;
	ctxt->disableSAX = 1;
    } else {
	__xmlRaiseError(schannel,
			NULL, NULL,
			ctxt, NULL, XML_FROM_PARSER, XML_ERR_NO_MEMORY,
			XML_ERR_ERROR, NULL, 0, (const char *) str1,
			NULL, NULL, 0, 0,
			msg, (const char *) str1, NULL);
    }
}
```
