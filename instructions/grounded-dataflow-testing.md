# Grounded Dataflow Testing

How to validate the taint-engine's dataflow analysis against real-world codebases using Semgrep findings as inputs.

## Prerequisites

```bash
# taint-engine (inside venv)
source .venv/bin/activate
pip install -e ".[dev]"

# semgrep (outside venv — system install)
semgrep --version
```

## Step 1: Pick Target Repos

Clone 2-3 real-world repos (not intentionally-vulnerable ones). Pick repos that use web frameworks with user-controlled inputs:

- **Python**: Flask (`request.args`, `request.form`), Django (`request.GET`, `request.POST`)
- **JS/TS**: Express (`req.body`, `req.query`, `req.params`), Koa, Fastify

```bash
mkdir -p /tmp/taint-eval
cd /tmp/taint-eval
git clone --depth 1 https://github.com/<org>/<repo>.git <name>
```

## Step 2: Run Semgrep

Use language-specific rulesets. Semgrep must run outside the taint-engine venv.

```bash
# Python repos
cd /tmp/taint-eval/<name>
semgrep --config "p/python" --json . 2>/dev/null > /tmp/taint-eval/<name>-findings.json

# JS/TS repos
semgrep --config "p/javascript" --json . 2>/dev/null > /tmp/taint-eval/<name>-findings.json
```

Parse the output to find taint-relevant findings:

```bash
python3 -c "
import json
d = json.load(open('/tmp/taint-eval/<name>-findings.json'))
for r in d['results']:
    cid = r['check_id']
    if any(k in cid.lower() for k in [
        'sqli', 'sql-injection', 'xss', 'redirect', 'ssrf',
        'command-injection', 'path-traversal', 'eval', 'exec',
        'dangerously', 'innerHTML',
    ]):
        print(f\"{r['path']}:{r['start']['line']}  {cid}\")
"
```

## Step 3: Map Semgrep Rules to Taint-Engine Parameters

The taint-engine needs three parameters per finding:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `--check-id` | `<lang>.<category>` | `python.sqli`, `javascript.redirect` |
| `--cwe` | CWE identifier | `CWE-89`, `CWE-601` |
| `--label` | Taint label from rules JSON | `sql`, `redirect`, `html` |

### Mapping table

| Semgrep keyword | check-id (Python) | check-id (JS) | CWE | Label |
|---|---|---|---|---|
| `sqli`, `sql-injection` | `python.sqli` | `javascript.sqli` | `CWE-89` | `sql` |
| `xss`, `dangerously`, `innerHTML` | `python.xss` | `javascript.xss` | `CWE-79` | `html` |
| `redirect`, `open-redirect` | `python.redirect` | `javascript.redirect` | `CWE-601` | `redirect` |
| `command-injection`, `exec` | `python.shell` | `javascript.shell` | `CWE-78` | `shell` |
| `ssrf` | `python.ssrf` | `javascript.ssrf` | `CWE-918` | `ssrf` |
| `path-traversal` | `python.path` | `javascript.path` | `CWE-22` | `path` |
| `eval`, `code-injection` | `python.eval` | `javascript.eval` | `CWE-95` | `eval` |

Labels and sinks are defined in `taint_engine/rules/python.json` and `taint_engine/rules/javascript.json`.

## Step 4: Run Taint-Trace

```bash
source .venv/bin/activate

# Basic usage — engine auto-detects the function enclosing the sink line
taint-trace trace <file>:<sink_line> \
  --check-id <lang>.<category> \
  --cwe <CWE-NNN> \
  --label <taint_label> \
  --format text

# If the function is not auto-detected (anonymous functions, module-level exports),
# specify it explicitly
taint-trace trace <file>:<sink_line> \
  --symbol <function_name> \
  --check-id <lang>.<category> \
  --cwe <CWE-NNN> \
  --label <taint_label> \
  --format text

# JSON output for programmatic analysis
taint-trace trace <file>:<sink_line> \
  --check-id <lang>.<category> \
  --cwe <CWE-NNN> \
  --label <taint_label> \
  --format json
```

### List available symbols in a file

```bash
taint-trace symbols <file>
```

This helps find the correct `--symbol` value when auto-detection fails.

## Step 5: Verify Results

For each taint-trace result, read the actual source code and verify:

### 1. Dataflow correctness

- Does the reported source actually contain user-controlled input?
- Does each assignment step in the path correctly reflect the code's data flow?
- Are intermediate variables correctly linked?

### 2. Source/sink type correctness

- Does the `active_label` match the actual vulnerability type?
- Is the `final_state` correct (e.g., `raw` for unsanitized, `html-encoded` after `html.escape`)?
- Are sanitizers correctly identified and their effectiveness correctly assessed?

### 3. Expected outcomes

| Scenario | Expected result |
|---|---|
| User input flows to sink unsanitized | Flow found, source kind = `source` or `parameter` |
| User input flows through sanitizer to sink | Flow found, sanitizer listed, state reflects sanitization |
| Hardcoded value at sink (no user input) | `No taint flow found` |
| Taint killed by reassignment | `No taint flow found` |
| Function not found (anonymous/exported) | Error: `no function found at line N` |

### 4. Known limitations

- **Anonymous functions**: `exports.x = function() {}` — use `--symbol` or expect `no function found`
- **JSX object patterns**: `dangerouslySetInnerHTML={{ __html: var }}` — sink detected but variables not extracted
- **Sources not in rules**: `request.url`, `request.referrer` — add to `rules/python.json` if needed
- **Cross-file flows**: Use `--cross-file` flag (requires index: `taint-trace index <dir>`)

## Example Session

```bash
# Clone a repo
cd /tmp/taint-eval
git clone --depth 1 https://github.com/simple-login/app.git simplelogin

# Scan with semgrep
cd simplelogin
semgrep --config "p/python" --json . 2>/dev/null > ../simplelogin-findings.json

# Activate taint-engine
source /path/to/taint-engine/.venv/bin/activate

# Trace a redirect finding
taint-trace trace app/auth/views/login.py:32 \
  --symbol login \
  --check-id python.redirect \
  --cwe CWE-601 \
  --label redirect \
  --format text

# Expected output:
# Taint Flow: next_url = sanitize_next_url(request.args.get("next")) → redirect(next_url)
#
#   [source]       line 27:  next_url = sanitize_next_url(request.args.get("next"))
#   [sink]         line 32:  redirect(next_url)
#
#   Sink type: redirect
#   Sanitizers: none found
#   Cross-file hops: 0

# Verify: read the code — request.args.get("next") IS user input,
# sanitize_next_url is an unresolved call (not a known sanitizer),
# redirect() IS a sink. Flow is correct.

# Trace a hardcoded redirect (should report no flow)
taint-trace trace app/dashboard/views/setting.py:140 \
  --check-id python.redirect \
  --cwe CWE-601 \
  --label redirect \
  --format text

# Expected output:
# No taint flow found in app/dashboard/views/setting.py
```

## Batch Testing Script

For running many findings at once, use a loop:

```bash
# Extract taint-relevant findings and run taint-trace on each
python3 -c "
import json, subprocess, os

d = json.load(open('/tmp/taint-eval/<name>-findings.json'))

KEYWORD_MAP = {
    'sqli': ('python.sqli', 'CWE-89', 'sql'),
    'redirect': ('python.redirect', 'CWE-601', 'redirect'),
    'xss': ('python.xss', 'CWE-79', 'html'),
    'ssrf': ('python.ssrf', 'CWE-918', 'ssrf'),
    'eval': ('python.eval', 'CWE-95', 'eval'),
}

for r in d['results']:
    cid = r['check_id'].lower()
    for kw, (check_id, cwe, label) in KEYWORD_MAP.items():
        if kw in cid:
            filepath = os.path.join('/tmp/taint-eval/<name>', r['path'])
            line = r['start']['line']
            print(f'--- {r[\"path\"]}:{line} ({cid}) ---')
            subprocess.run([
                'taint-trace', 'trace', f'{filepath}:{line}',
                '--check-id', check_id,
                '--cwe', cwe,
                '--label', label,
                '--format', 'text',
            ])
            print()
            break
"
```
