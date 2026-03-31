# Taint Labels & Desanitizers — Design Spec

## Problem

The engine treats all sanitizers as universal — `html.escape` is counted as effective
against SQL injection, SSRF, or any other vulnerability type. In addition, if a
value is sanitized and then later decoded/unquoted, the engine still reports it as
sanitized. Both lead to incorrect results:

**Scenario A — wrong sanitizer for context:**
```python
safe = html.escape(user_input)
cursor.execute("SELECT " + safe)   # html.escape doesn't prevent SQLi
```
Engine reports: "sanitized by html.escape" → **false negative**.

**Scenario B — sanitization undone:**
```python
safe = html.escape(user_input)     # "&lt;script&gt;"
decoded = base64.b64decode(safe)   # back to "<script>"
el.innerHTML = decoded             # XSS
```
Engine reports: "sanitized by html.escape" → **false negative**.

## Solution

Introduce **taint labels** — named categories like `html`, `sql`, `shell`, `ssrf`.
Every sanitizer declares which labels it removes. A new **desanitizers** rule section
declares functions that restore labels (undo sanitization). The engine infers the
active label from the sink expression by matching it against a labeled sinks map.

## Rule Schema Changes

### Current format (backward compatible)

```json
{
  "sources": ["request.args", "request.form"],
  "sinks": {
    "call": ["eval", "cursor.execute"],
    "property": ["innerHTML"]
  },
  "sanitizers": [
    { "name": "html.escape", "neutralizes": ["CWE-79"] }
  ]
}
```

### New format

```json
{
  "sources": {
    "request.args":      ["html", "sql", "shell", "ssrf", "redirect"],
    "request.form":      ["html", "sql", "shell", "ssrf"],
    "request.get_json":  ["html", "sql", "shell", "ssrf"],
    "request.data":      ["html", "sql", "shell", "ssrf"],
    "os.environ":        ["path", "shell"],
    "sys.argv":          ["path", "shell", "eval"],
    "input()":           ["html", "sql", "shell", "ssrf", "path", "eval"],
    "request.GET":       ["html", "sql", "shell", "ssrf", "redirect"],
    "request.POST":      ["html", "sql", "shell", "ssrf"]
  },

  "sinks": {
    "html":     ["innerHTML", "document.write", "response.write"],
    "sql":      ["cursor.execute", "db.execute", "conn.execute"],
    "shell":    ["os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "os.popen"],
    "ssrf":     ["requests.get", "requests.post", "requests.put", "urllib.request.urlopen"],
    "redirect": ["redirect", "HttpResponseRedirect"],
    "path":     ["open", "os.path.join"],
    "eval":     ["eval", "exec", "compile"]
  },

  "sanitizers": [
    { "name": "html.escape",       "removes": ["html"] },
    { "name": "markupsafe.escape",  "removes": ["html"] },
    { "name": "bleach.clean",       "removes": ["html"] },
    { "name": "cgi.escape",         "removes": ["html"] },
    { "name": "escape",             "removes": ["html"] },
    { "name": "strip_tags",         "removes": ["html"] },
    { "name": "shlex.quote",        "removes": ["shell"] },
    { "name": "os.path.basename",   "removes": ["path"] },
    { "name": "os.path.normpath",   "removes": ["path"] },
    { "name": "parameterize",       "removes": ["sql"] },
    { "name": "sanitize_sql",       "removes": ["sql"] },
    { "name": "int",                "removes": ["sql", "html", "ssrf"] },
    { "name": "float",              "removes": ["sql", "html", "ssrf"] }
  ],

  "desanitizers": [
    { "name": "base64.b64decode",       "restores": ["html", "sql", "shell"] },
    { "name": "base64.b64encode",       "restores": [] },
    { "name": "urllib.parse.unquote",   "restores": ["html"] },
    { "name": "urllib.parse.unquote_plus", "restores": ["html"] },
    { "name": "codecs.decode",          "restores": ["html", "sql"] },
    { "name": "json.loads",             "restores": ["html", "sql"] },
    { "name": ".decode",                "restores": ["html"] }
  ],

  "guards": ["re.match", "re.fullmatch", "isinstance", "hasattr", "urlsplit"]
}
```

### Backward compatibility rules

The loader must handle both old and new formats:

| Old format | Interpretation |
|---|---|
| `"sources"` is a `list[str]` | Each source emits all labels (equivalent to `["*"]`) |
| `"sinks"` has `"call"` / `"property"` keys | Flatten into label-less sinks; label detection returns `None` |
| Sanitizer has `"neutralizes"` but no `"removes"` | `"neutralizes"` is kept for metadata; sanitizer treated as removing all labels (universal) |
| No `"desanitizers"` key | No desanitizer checking — existing behavior |

## Label Detection

When the engine finds the sink expression at the target line, it determines the
**active label** by matching the callee or property against the labeled `sinks` map.

### Algorithm

```
function detect_label(sink_expression, rules, ext):
    lang_rules = rules.for_extension(ext)
    if lang_rules is None or lang_rules.labeled_sinks is None:
        return None

    callee = extract_callee_from_expression(sink_expression)

    for label, sink_names in lang_rules.labeled_sinks.items():
        for sink_name in sink_names:
            if sink_name in callee:
                return label

    return None  # no match → all sanitizers count
```

This runs inside `trace_taint_flow()` after `_find_vars_at_line()` identifies the
sink variables. The first `(sink_var, sink_expr)` that yields a label wins.

### CLI override

`taint-trace trace file.py:42 --label sql` sets the active label explicitly,
bypassing auto-detection. Useful when the sink function is not in the rules map.

## Engine Changes

### 1. `LanguageRules` — new fields

```python
@dataclass(frozen=True)
class LanguageRules:
    language: str
    sources: frozenset[str]                          # flat set (backward compat)
    labeled_sources: dict[str, list[str]] | None     # NEW: source → labels
    call_sinks: frozenset[str]                       # kept for Pass 1 (any-call matching)
    property_sinks: frozenset[str]                   # kept for Pass 3
    labeled_sinks: dict[str, list[str]] | None       # NEW: label → sink names
    sanitizers: MappingProxyType[str, list[str]]      # existing
    sanitizer_labels: dict[str, list[str]] | None    # NEW: sanitizer name → removes labels
    desanitizers: dict[str, list[str]] | None        # NEW: function name → restores labels
    guards: frozenset[str]
```

### 2. `SanitizerInfo` — new fields

```python
@dataclass
class SanitizerInfo:
    name: str
    line: int
    cwe_categories: list[str]    # kept for backward compat
    removes: list[str]           # NEW: taint labels this sanitizer removes
    conditional: bool
    verified: bool
    effective: bool = True       # NEW: False if wrong label or invalidated by desanitizer
    invalidated_by: str | None = None  # NEW: desanitizer name that voided this
```

The `removes` field defaults to `["*"]` (universal) when the old rule format is used.

### 3. `trace_taint_flow()` — label-aware post-processing

After the backward trace completes and produces a `TaintFlow`, a new
`_apply_label_analysis()` step runs:

```
function _apply_label_analysis(flow, active_label, rules, ext):
    if active_label is None:
        return flow  # no label → existing behavior, all sanitizers effective

    lang_rules = rules.for_extension(ext)

    # Step 1: Check each sanitizer's effectiveness for the active label
    for san in flow.sanitizers:
        if "*" not in san.removes and active_label not in san.removes:
            san.effective = False  # wrong sanitizer for this sink type

    # Step 2: Check for desanitizers that void effective sanitizers
    if lang_rules.desanitizers:
        for san in flow.sanitizers:
            if not san.effective:
                continue
            # Look for desanitizer calls in the flow path AFTER the sanitizer
            for step in flow.path:
                if step.line <= san.line:
                    continue
                for desan_name, restores in lang_rules.desanitizers.items():
                    if desan_name in step.expression and active_label in restores:
                        san.effective = False
                        san.invalidated_by = desan_name

    # Step 3 (optional): Check if source emits the active label
    if lang_rules.labeled_sources:
        source_step = flow.source
        for source_name, labels in lang_rules.labeled_sources.items():
            if source_name in source_step.expression:
                if active_label not in labels:
                    flow.confidence_factors.append(
                        f"source '{source_name}' may not emit '{active_label}' taint"
                    )
                break

    return flow
```

### 4. Walker `_check_sanitizer()` — populate `removes`

When the walker records a sanitizer, it now also populates the `removes` field
from the rule's `sanitizer_labels` map. If the rule uses old format,
`removes = ["*"]`.

### 5. `_find_vars_at_line()` — return callee name

Currently returns `list[tuple[str, str]]` as `(variable_name, expression_text)`.
Add the callee name to the return value so `trace_taint_flow()` can detect the
label without re-parsing. Change to `list[tuple[str, str, str | None]]` where the
third element is the callee name (or `None` for non-call sinks).

## Output Changes

### JSON output

`SanitizerInfo.to_dict()` adds:

```json
{
  "name": "html.escape",
  "line": 15,
  "removes": ["html"],
  "effective": false,
  "invalidated_by": null,
  "cwe_categories": ["CWE-79"],
  "conditional": false,
  "verified": true
}
```

### Text output

When a sanitizer is ineffective:

```
  Sanitizers: html.escape (INEFFECTIVE — does not neutralize 'sql' taint)
```

When a sanitizer is invalidated by a desanitizer:

```
  Sanitizers: html.escape (INVALIDATED by base64.b64decode at line 20)
```

### TaintFlow — new field

```python
@dataclass
class TaintFlow:
    ...
    active_label: str | None = None   # NEW: the detected taint label for this flow
```

This is included in `to_dict()` output so consumers know which label was active.

## File Map

| File | Change |
|---|---|
| `taint_engine/rules/python.json` | New format: labeled sources, labeled sinks, removes on sanitizers, desanitizers section |
| `taint_engine/rules/javascript.json` | Same structural changes |
| `taint_engine/rules/go.json` | Same structural changes |
| `taint_engine/rules/java.json` | Same structural changes |
| `taint_engine/rules/php.json` | Same structural changes |
| `taint_engine/rules/__init__.py` | Load new fields, backward-compat loader, new `LanguageRules` fields |
| `taint_engine/models.py` | `SanitizerInfo`: add `removes`, `effective`, `invalidated_by`. `TaintFlow`: add `active_label` |
| `taint_engine/engine.py` | Label detection in `trace_taint_flow()`, `_apply_label_analysis()` post-processing, updated `_find_vars_at_line()` return |
| `taint_engine/walker.py` | `_check_sanitizer()` populates `removes` field |
| `taint_engine/cli/cmd_trace.py` | Accept `--label` CLI flag, pass to engine |
| `taint_engine/cli/formatters/text.py` | Show effective/ineffective/invalidated sanitizers |
| `taint_engine/cli/formatters/json_fmt.py` | Include new fields in JSON output |
| `taint_engine/cli/formatters/sarif.py` | Include label and effectiveness in SARIF relatedLocations |
| `tests/test_taint_engine.py` | Tests for label-aware sanitizer filtering |
| `tests/test_taint_walker.py` | Tests for `removes` field population |
| `tests/test_taint_rules.py` | Tests for new rule format loading + backward compat |
| `tests/test_taint_models.py` | Tests for new SanitizerInfo/TaintFlow serialization |

## Test Scenarios

### Label-aware sanitizer filtering

```python
# Scenario A: html.escape before SQL sink
def vuln_a(user_input):
    safe = html.escape(user_input)
    cursor.execute("SELECT " + safe)   # label = "sql", html.escape removes ["html"] → INEFFECTIVE
```
Expected: flow reported with `html.escape` marked `effective=False`.

### Desanitizer invalidation

```python
# Scenario B: sanitize then decode
def vuln_b(user_input):
    safe = html.escape(user_input)
    decoded = base64.b64decode(safe)
    return decoded                     # label = "html", html.escape was valid but b64decode restores ["html"] → INVALIDATED
```
Expected: flow reported with `html.escape` marked `effective=False, invalidated_by="base64.b64decode"`.

### Correct sanitization (no change)

```python
def safe_fn(user_input):
    safe = html.escape(user_input)
    response.write(safe)               # label = "html", html.escape removes ["html"] → EFFECTIVE
```
Expected: flow reported with `html.escape` marked `effective=True`.

### No label match (backward compat)

```python
def unknown_sink(user_input):
    custom_function(user_input)        # not in sinks map → label = None → all sanitizers count
```
Expected: existing behavior unchanged.

### CLI --label override

```
taint-trace trace app.py:42 --label sql
```
Forces `active_label = "sql"` regardless of what the sink expression matches.

## Non-Goals

- Full interprocedural taint coloring (Psalm-style label sets flowing through every node)
- CWE-to-label mapping — labels are derived from sink matching, not from external CWE input
- Automatic detection of desanitizer functions — the list is maintained manually in rules
- Changing the forward walker's branch-merge semantics (conditional reassignment is a separate issue)
