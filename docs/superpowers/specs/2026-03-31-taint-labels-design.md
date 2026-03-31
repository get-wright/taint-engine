# Taint Labels & Flow State — Design Spec

## Problem

The engine treats all sanitizers as universal — `html.escape` is counted as effective
against SQL injection, SSRF, or any other vulnerability type. In addition, if a
value is sanitized and then later decoded/transformed, the engine still reports it as
sanitized. Both lead to incorrect results:

**Scenario A — wrong sanitizer for context:**
```python
safe = html.escape(user_input)
cursor.execute("SELECT " + safe)   # html.escape doesn't prevent SQLi
```
Engine reports: "sanitized by html.escape" → **false negative**.

**Scenario B — sanitization invalidated by transformation:**
```python
safe = html.escape(user_input)     # data state: html-encoded
decoded = base64.b64decode(safe)   # data state: raw-bytes (encoding is meaningless now)
el.innerHTML = decoded             # HTML sink expects html-encoded, gets raw-bytes
```
Engine reports: "sanitized by html.escape" → **false negative**.

## Solution

Introduce **taint labels** and **flow state** — a model inspired by CodeQL's
`FlowState` where data carries a representation state through the trace.

Three concepts:

1. **Taint labels** — named vulnerability categories (`html`, `sql`, `shell`, `ssrf`).
   Sinks declare which label they belong to. Sanitizers declare which labels they
   address. A sanitizer only counts if its label matches the sink's label.

2. **Flow state** — data has a *representation state* (`raw`, `html-encoded`,
   `parameterized`, `base64`, `int`, etc.). Sanitizers set a specific state.
   Transformers change the state. Sinks declare which states they accept as safe.

3. **Transformers** — functions that change data representation without sanitizing.
   Unlike "desanitizers" (which model undoing a specific sanitizer), transformers
   are representation transitions. `base64.b64decode` doesn't "undo html.escape" —
   it transitions data to `raw-bytes` regardless of prior encoding. This is more
   general and more correct.

The engine infers the active label from the sink expression, then checks whether
the last state-setting operation in the trace path left data in a state the sink
accepts.

## Why Flow State Instead of Desanitizers

The "desanitizer" concept (Psalm's `@psalm-taint-unescape`) models sanitization
as something reversible. But `base64.b64decode` doesn't reverse `html.escape` —
it does something completely unrelated. The real question is: **what representation
is the data in when it reaches the sink?**

| Model | Approach | Weakness |
|---|---|---|
| Desanitizers | Explicit list of functions that "undo" sanitization | Assumes sanitization is reversible. Misses transformations that aren't direct inverses but change representation |
| Flow state | Every function that changes data representation is a state transition. Sinks declare what states they accept | Correct by construction — any transformation that changes representation naturally invalidates irrelevant prior sanitizations |

Example: `html.escape` → `json.dumps` → HTML sink.
- Desanitizer model: Is `json.dumps` a desanitizer for `html`? Unclear — it's not an inverse of `html.escape`.
- Flow state model: `html.escape` sets state to `html-encoded`. `json.dumps` transitions state to `json-string`. HTML sink accepts `html-encoded` but not `json-string`. → Flagged. Correct.

## Rule Schema

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
  "language": "python",
  "extensions": [".py"],

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
    "html": {
      "call":     ["document.write", "response.write"],
      "property": ["innerHTML", "outerHTML"],
      "accepts":  ["html-encoded", "int", "float", "stripped"]
    },
    "sql": {
      "call":     ["cursor.execute", "db.execute", "conn.execute"],
      "accepts":  ["parameterized", "int", "float"]
    },
    "shell": {
      "call":     ["os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "os.popen"],
      "accepts":  ["shell-quoted", "int", "float"]
    },
    "ssrf": {
      "call":     ["requests.get", "requests.post", "requests.put", "urllib.request.urlopen"],
      "accepts":  ["validated-url", "int"]
    },
    "redirect": {
      "call":     ["redirect", "HttpResponseRedirect"],
      "accepts":  ["validated-url", "relative-path"]
    },
    "path": {
      "call":     ["open", "os.path.join"],
      "accepts":  ["normalized-path", "basename-only"]
    },
    "eval": {
      "call":     ["eval", "exec", "compile"],
      "accepts":  []
    }
  },

  "sanitizers": [
    { "name": "html.escape",       "removes": ["html"], "sets_state": "html-encoded" },
    { "name": "markupsafe.escape",  "removes": ["html"], "sets_state": "html-encoded" },
    { "name": "bleach.clean",       "removes": ["html"], "sets_state": "html-encoded" },
    { "name": "cgi.escape",         "removes": ["html"], "sets_state": "html-encoded" },
    { "name": "strip_tags",         "removes": ["html"], "sets_state": "stripped" },
    { "name": "shlex.quote",        "removes": ["shell"], "sets_state": "shell-quoted" },
    { "name": "os.path.basename",   "removes": ["path"], "sets_state": "basename-only" },
    { "name": "os.path.normpath",   "removes": ["path"], "sets_state": "normalized-path" },
    { "name": "parameterize",       "removes": ["sql"], "sets_state": "parameterized" },
    { "name": "sanitize_sql",       "removes": ["sql"], "sets_state": "parameterized" },
    { "name": "int",                "removes": ["sql", "html", "ssrf", "shell"], "sets_state": "int" },
    { "name": "float",              "removes": ["sql", "html", "ssrf"], "sets_state": "float" }
  ],

  "transformers": [
    { "name": "base64.b64decode",          "sets_state": "raw-bytes" },
    { "name": "base64.b64encode",          "sets_state": "base64" },
    { "name": "urllib.parse.unquote",      "sets_state": "raw" },
    { "name": "urllib.parse.unquote_plus", "sets_state": "raw" },
    { "name": "urllib.parse.quote",        "sets_state": "url-encoded" },
    { "name": "codecs.decode",             "sets_state": "raw" },
    { "name": "codecs.encode",             "sets_state": "encoded" },
    { "name": "json.loads",                "sets_state": "parsed-object" },
    { "name": "json.dumps",               "sets_state": "json-string" }
  ],

  "guards": ["re.match", "re.fullmatch", "isinstance", "hasattr", "urlsplit"]
}
```

### Key design points

**`sanitizers` have both `removes` and `sets_state`:**
- `removes` answers: "which taint label does this sanitizer address?" (Scenario A)
- `sets_state` answers: "what representation is the data in after this call?" (Scenario B)

**`transformers` only have `sets_state`:**
- They don't remove any taint label. They just change representation.
- If a transformer runs after a sanitizer, it overwrites the state. The sanitizer's
  state is gone.

**`sinks` have `accepts`:**
- A list of states that are safe for this sink type.
- If the data's state at the sink is in `accepts`, the sanitization chain is effective.
- If `accepts` is empty (like `eval`), no state is ever safe — nothing can sanitize `eval`.
- If `accepts` is absent, no state checking — existing behavior.

### Backward compatibility

| Old format | Interpretation |
|---|---|
| `"sources"` is a `list[str]` | Used as-is (flat source set) |
| `"sources"` is a `dict[str, list]` (new format) | Keys are extracted as the flat source set; label values are stored but reserved for future use |
| `"sinks"` has flat `"call"` / `"property"` keys | Populate `call_sinks` / `property_sinks` as before; label detection returns `None`; no state checking |
| Sanitizer has `"neutralizes"` but no `"removes"` or `"sets_state"` | Treated as removing all labels, setting state `"sanitized"` (universal) |
| No `"transformers"` key | No state transitions — existing behavior |

## Label and State Detection

### Label detection

When the engine finds the sink at the target line, it matches the sink identifier
(callee name or property name) against the labeled `sinks` map to get the active label.

```
function detect_label(sink_identifier, rules, ext):
    lang_rules = rules.for_extension(ext)
    if lang_rules is None or lang_rules.labeled_sinks is None:
        return None

    for label, sink_def in lang_rules.labeled_sinks.items():
        all_names = sink_def.get("call", []) + sink_def.get("property", [])
        for sink_name in all_names:
            if sink_name in sink_identifier:
                return label

    return None  # no match → all sanitizers count, no state checking
```

The `sink_identifier` is extracted from `_find_vars_at_line()`:
- **Pass 1 (call arguments)**: `get_full_callee(call_node)`
- **Pass 2 (return statements)**: `None`
- **Pass 3 (property assignments)**: `get_member_property(left)`

Return type changes to `list[tuple[str, str, str | None]]` — third element is the
sink identifier.

### State checking

Once the label is known, look up `accepts` for that label. Then scan the trace path
(source → sink order) to find the **last state-setting operation** (sanitizer or
transformer). If that operation's `sets_state` is in `accepts`, the flow is sanitized.
If not, it's unsanitized.

```
function check_flow_state(flow, active_label, rules, ext):
    lang_rules = rules.for_extension(ext)
    sink_def = lang_rules.labeled_sinks.get(active_label)
    if sink_def is None:
        return  # no state checking

    accepted_states = sink_def.get("accepts")
    if accepted_states is None:
        return  # no state checking for this sink

    # Merge all state-setting operations into one sorted list.
    # Each entry: (line, discovery_order, sets_state, name)
    # discovery_order comes from the walker's DFS traversal, which processes
    # inner expressions before outer ones on the same line.
    state_ops = []
    for i, san in enumerate(flow.sanitizers):
        if san.sets_state:
            state_ops.append((san.line, san.discovery_order, san.sets_state, san.name))
    for i, tfm in enumerate(flow.transformers):
        state_ops.append((tfm.line, tfm.discovery_order, tfm.sets_state, tfm.name))
    state_ops.sort()  # by (line, discovery_order)

    # Walk in order to find the last state
    last_state = "raw"  # default: untransformed user input
    last_state_setter = None

    for line, order, sets_state, name in state_ops:
        # Only consider operations on lines within the trace path
        path_lines = {step.line for step in flow.path}
        if line in path_lines:
            last_state = sets_state
            last_state_setter = name

    flow.final_state = last_state

    # Mark sanitizers as effective/ineffective based on final state
    if last_state in accepted_states:
        # Final state is safe — sanitization chain worked
        pass
    else:
        # Final state is NOT safe
        for san in flow.sanitizers:
            if san.effective:
                if last_state_setter and last_state_setter != san.name:
                    san.effective = False
                    san.invalidated_by = f"{last_state_setter} (state: {last_state})"
```

Note: `discovery_order` is an integer assigned by the walker during DFS traversal.
The walker processes inner expressions before outer ones (e.g., in
`int(base64.b64decode(x))`, `b64decode` is visited before `int`). This ensures
correct ordering when a sanitizer and transformer appear on the same line.

### CLI override

`taint-trace trace file.py:42 --label sql` forces the active label, bypassing
auto-detection.

## Engine Changes

### 1. `LanguageRules` — new fields

```python
@dataclass(frozen=True)
class LanguageRules:
    language: str
    sources: frozenset[str]                           # flat set (backward compat + new format flattened)
    call_sinks: frozenset[str]                        # flattened for Pass 1
    property_sinks: frozenset[str]                    # flattened for Pass 3
    labeled_sinks: MappingProxyType[str, dict] | None  # label → {call, property, accepts}
    sanitizers: MappingProxyType[str, list[str]]       # existing (name → CWE list)
    sanitizer_labels: MappingProxyType[str, list[str]] | None  # sanitizer name → removes labels
    sanitizer_states: MappingProxyType[str, str] | None        # sanitizer name → sets_state
    transformers: MappingProxyType[str, str] | None            # transformer name → sets_state
    guards: frozenset[str]
```

The loader populates `call_sinks` and `property_sinks` by flattening all labeled
sink entries (union of all `call` and `property` lists across all labels). This
preserves backward compatibility — `_find_vars_at_line()` Pass 3 still calls
`rules.is_property_sink()` and gets correct results.

### 2. `SanitizerInfo` — new fields

```python
@dataclass
class SanitizerInfo:
    name: str
    line: int
    cwe_categories: list[str]                    # kept for backward compat
    conditional: bool
    verified: bool
    removes: list[str] = field(default_factory=lambda: ["*"])  # NEW: taint labels
    sets_state: str | None = "sanitized"         # NEW: data representation
    discovery_order: int = 0                     # NEW: walker DFS order (for same-line sorting)
    effective: bool = True                       # NEW: False if wrong label or state not accepted
    invalidated_by: str | None = None            # NEW: what overwrote state
```

Default values ensure backward compatibility — existing `SanitizerInfo(...)` calls
that don't pass `removes`/`sets_state` get universal behavior (`["*"]`, `"sanitized"`).

For new-format rules (those with `removes`/`sets_state`), `cwe_categories` is
populated with `["*"]` since label-based matching supersedes CWE-based filtering.
The field is retained for output format compatibility.

`from_dict()` handles missing keys:
```python
removes=d.get("removes", ["*"]),
sets_state=d.get("sets_state", "sanitized"),
discovery_order=d.get("discovery_order", 0),
effective=d.get("effective", True),
invalidated_by=d.get("invalidated_by"),
```

### 3. `TransformerInfo` — new dataclass

```python
@dataclass
class TransformerInfo:
    """A function call that changes data representation without sanitizing."""
    name: str
    line: int
    sets_state: str        # data representation after this call
    discovery_order: int = 0  # walker DFS order (for same-line sorting)
```

### 4. `TaintFlow` — new fields

```python
@dataclass
class TaintFlow:
    ...
    active_label: str | None = None             # detected taint label
    transformers: list[TransformerInfo] = field(default_factory=list)
    final_state: str | None = None              # data state at the sink
```

`from_dict()`:
```python
active_label=d.get("active_label"),
transformers=[TransformerInfo(**x) for x in d.get("transformers", [])],
final_state=d.get("final_state"),
```

### 5. `WalkState` — carry transformers

`WalkState` gets a new field: `transformers: list[TransformerInfo]`.

### 6. `trace_taint_flow()` — new `label` parameter and post-processing

```python
def trace_taint_flow(
    *,
    file_path: str,
    function_name: str,
    sink_line: int,
    check_id: str,
    cwe_list: list[str],
    rules: TaintRuleSet,
    parser: object,
    label: str | None = None,    # NEW: explicit label override
) -> Optional[TaintFlow]:
```

After the backward trace, post-processing runs two checks:

**Check 1 — Label matching** (Scenario A):
For each sanitizer, if `active_label not in sanitizer.removes` and `"*" not in
sanitizer.removes`, mark `effective = False`.

**Check 2 — State acceptance** (Scenario B):
Walk the path in source→sink order. Track the last `sets_state` from any sanitizer
or transformer. Compare to `accepts` list for the active label's sink definition.
If the final state is not in `accepts`, mark the responsible sanitizer as
`effective = False` with `invalidated_by` showing what changed the state.

Cross-file sub-traces inherit the parent's label.

### 7. Walker — detect transformers

A new `_check_transformer()` function, parallel to `_check_sanitizer()`, uses
AST-based callee matching (`get_callee_name` / `get_full_callee` + suffix indexing)
to detect transformer calls and record them in `state.transformers`.

Called from `_handle_assignment()` alongside `_check_sanitizer()`, for every call
on the RHS of an assignment.

### 8. `_find_vars_at_line()` — return sink identifier

Return type changes to `list[tuple[str, str, str | None]]`:
- **Pass 1 (call arguments)**: `get_full_callee(call_node)` — callee name
- **Pass 2 (return statements)**: `None`
- **Pass 3 (property assignments)**: `get_member_property(left)` — property name

### 9. `TaintRuleSet` — new query methods

```python
def check_transformer(self, ext: str, callee: str) -> TransformerInfo | None:
    """Check if a callee is a known transformer. Returns TransformerInfo or None."""

def get_accepted_states(self, ext: str, label: str) -> list[str] | None:
    """Get the accepted states for a sink label. Returns None if no state checking."""

def get_sanitizer_state(self, ext: str, callee: str) -> str | None:
    """Get the state a sanitizer sets. Returns None if not configured."""
```

Suffix indexing (bare name fallback) works the same as `check_sanitizer`.

## Output Changes

### JSON output

`SanitizerInfo.to_dict()`:
```json
{
  "name": "html.escape",
  "line": 15,
  "removes": ["html"],
  "sets_state": "html-encoded",
  "effective": false,
  "invalidated_by": "base64.b64decode (state: raw-bytes)",
  "cwe_categories": ["CWE-79"],
  "conditional": false,
  "verified": true
}
```

`TaintFlow.to_dict()` adds:
```json
{
  "active_label": "html",
  "final_state": "raw-bytes",
  "transformers": [
    { "name": "base64.b64decode", "line": 20, "sets_state": "raw-bytes" }
  ]
}
```

### Text output

When a sanitizer's label doesn't match:
```
  Sanitizers: html.escape (INEFFECTIVE — does not address 'sql' sinks)
```

When a transformer changed the state after sanitization:
```
  Sanitizers: html.escape (INEFFECTIVE — state changed to 'raw-bytes' by base64.b64decode at line 20)
  Flow state: raw → html-encoded → raw-bytes (sink expects: html-encoded)
```

When sanitization is effective:
```
  Sanitizers: html.escape (effective, state: html-encoded)
  Flow state: raw → html-encoded (sink accepts: html-encoded ✓)
```

## File Map

| File | Change |
|---|---|
| `taint_engine/rules/python.json` | New format: labeled sources, labeled sinks with `accepts`, sanitizers with `removes`/`sets_state`, transformers section |
| `taint_engine/rules/javascript.json` | Same structural changes |
| `taint_engine/rules/go.json` | Same structural changes |
| `taint_engine/rules/java.json` | Same structural changes |
| `taint_engine/rules/php.json` | Same structural changes |
| `taint_engine/rules/__init__.py` | Load new fields, backward-compat loader, new `LanguageRules` fields, new query methods |
| `taint_engine/models.py` | `SanitizerInfo`: add `removes`, `sets_state`, `effective`, `invalidated_by`; add `TransformerInfo`; `TaintFlow`: add `active_label`, `transformers`, `final_state` |
| `taint_engine/engine.py` | `trace_taint_flow()`: add `label` param, label detection, state-checking post-processing; `_find_vars_at_line()`: return `sink_identifier` |
| `taint_engine/walker.py` | `_check_sanitizer()` populates `removes`/`sets_state`; new `_check_transformer()`; `WalkState` gets `transformers` list |
| `taint_engine/cli/cmd_trace.py` | Accept `--label` CLI flag, pass to engine |
| `taint_engine/cli/formatters/text.py` | Show state chain, effective/ineffective sanitizers |
| `taint_engine/cli/formatters/json_fmt.py` | Include new fields |
| `taint_engine/cli/formatters/sarif.py` | Include label, state, transformers in SARIF |
| `tests/test_taint_engine.py` | Tests for label matching + state acceptance |
| `tests/test_taint_walker.py` | Tests for transformer detection, `sets_state` population |
| `tests/test_taint_rules.py` | Tests for new rule format + backward compat |
| `tests/test_taint_models.py` | Tests for new dataclass serialization |

## Test Scenarios

### Scenario A: Wrong sanitizer for context

```python
def vuln_a(user_input):
    safe = html.escape(user_input)
    cursor.execute("SELECT " + safe)
```
- Label: `sql` (from `cursor.execute`)
- `html.escape` removes `["html"]` → `"sql" not in ["html"]` → **INEFFECTIVE**
- Expected: flow flagged, sanitizer marked ineffective

### Scenario B: Transformation invalidates sanitization

```python
def vuln_b(user_input):
    safe = html.escape(user_input)
    decoded = base64.b64decode(safe)
    return decoded  # used in HTML context
```
- Label: `html`
- State chain: `raw` → `html-encoded` (html.escape) → `raw-bytes` (b64decode)
- Sink accepts: `["html-encoded", "int", "float", "stripped"]`
- Final state: `raw-bytes` → **NOT IN accepts** → **INEFFECTIVE**
- `invalidated_by`: `"base64.b64decode (state: raw-bytes)"`

### Scenario C: Correct sanitization preserved

```python
def safe_c(user_input):
    safe = html.escape(user_input)
    response.write(safe)
```
- Label: `html`
- State chain: `raw` → `html-encoded` (html.escape)
- Final state: `html-encoded` → **IN accepts** → **EFFECTIVE**

### Scenario D: Transformer after sanitizer but state still accepted

```python
def safe_d(user_input):
    n = int(user_input)
    query = str(n)
    cursor.execute("SELECT " + query)
```
- Label: `sql`
- State chain: `raw` → `int` (int()) → `raw` (str())
- Wait — `str()` sets state to `raw`, which is NOT in sql accepts `["parameterized", "int", "float"]`.
- But `int()` already removed all dangerous content. `str(int(x))` is safe.
- This reveals that `str()` should NOT be a transformer for numeric types, OR
  `int`/`float` states should be "sticky" (not overwritten by `str()`).
- **Resolution**: Don't list `str()` as a transformer. It's a representation-
  preserving operation for our purposes — it doesn't change the safety properties.
  Only list functions that change encoding/format in security-relevant ways.

### Scenario E: No label match (backward compat)

```python
def unknown_sink(user_input):
    custom_function(user_input)
```
- Sink not in map → label = `None` → no state checking → all sanitizers count
- Existing behavior preserved

### Scenario F: CLI --label override

```
taint-trace trace app.py:42 --label sql
```
Forces `active_label = "sql"` regardless of sink expression.

## Known Limitations

- **Sanitizers and transformers are function-scoped, not path-scoped.** The walker
  records all sanitizers/transformers in the function body, including on unrelated
  variables. State checking uses line numbers to order them along the path, but may
  include operations on different variables. Filtering to path-relevant operations
  is a future improvement.

- **Transformer list is manual.** Rules must explicitly list state-changing functions.
  The engine doesn't infer representation changes automatically.

- **State is a single value, not a set.** Each operation overwrites the previous
  state. This is sufficient for the backward trace post-processing model but less
  expressive than CodeQL's full flow-state-set approach.

- **Return-statement sinks skip label detection.** When `_find_vars_at_line()`
  matches a return statement (Pass 2), the sink identifier is `None`, bypassing
  label detection and state checking. Use `--label` CLI override for these cases.

- **`str()` and similar "neutral" calls.** Some functions (like `str()`) technically
  change representation but don't affect safety. These should NOT be listed as
  transformers. Only list functions that change encoding/format in security-relevant
  ways. When in doubt, omit it — an unlisted function preserves the previous state.

## Non-Goals

- Full forward flow-state tracking (CodeQL-style `StateConfigSig` with per-node state sets)
- CWE-to-label mapping — labels come from sink matching only
- Automatic transformer detection
- Branch-sensitive state tracking (conditional state changes)
