# Taint Labels & Flow State Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add taint labels, flow state tracking, and transformers to the engine, plus fix 16 pre-existing correctness issues in the walker and engine.

**Architecture:** The changes layer on top of the existing backward tracer. Models gain new fields (TransformerInfo, SanitizerInfo.removes/sets_state, TaintFlow.active_label/final_state). Rules switch to a labeled format with sink accepts/sanitizer removes/transformer sets_state. The walker detects transformers alongside sanitizers and fixes 16 correctness issues (try/except, with, augmented assignment, etc.). The engine adds label detection from sink expressions and state-checking post-processing. All changes are opt-in — when no label is detected, existing behavior is preserved.

**Tech Stack:** Python 3.11+, tree-sitter (existing), pytest 8+, SQLite (existing CLI)

**Spec:** `docs/superpowers/specs/2026-03-31-taint-labels-design.md`

---

## File Map

| File | Responsibility |
|---|---|
| `taint_engine/models.py` | Add `TransformerInfo`, update `SanitizerInfo`, update `TaintFlow` |
| `taint_engine/rules/__init__.py` | Rewrite loader for new format, new `LanguageRules` fields, new query methods |
| `taint_engine/rules/python.json` | Rewrite to labeled format |
| `taint_engine/rules/javascript.json` | Rewrite to labeled format |
| `taint_engine/rules/go.json` | Rewrite to labeled format |
| `taint_engine/rules/java.json` | Rewrite to labeled format |
| `taint_engine/rules/php.json` | Rewrite to labeled format |
| `taint_engine/walker.py` | Transformer detection, path-scoped sanitizers, 12 correctness fixes |
| `taint_engine/ast_helpers.py` | `collect_identifiers` improvements, dead code cleanup |
| `taint_engine/engine.py` | Label detection, state-checking, source match fix, `_find_vars_at_line` changes |
| `taint_engine/cli/cmd_trace.py` | `--label` CLI flag |
| `taint_engine/cli/formatters/text.py` | State chain display, effective/ineffective markers |
| `taint_engine/cli/formatters/json_fmt.py` | New fields in JSON output |
| `taint_engine/cli/formatters/sarif.py` | Label/state/transformers in SARIF |
| `tests/test_taint_models.py` | Serialization tests for new fields |
| `tests/test_taint_rules.py` | New format loading tests |
| `tests/test_taint_walker.py` | Walker fix tests + transformer detection |
| `tests/test_taint_engine.py` | Label matching, state acceptance, source match tests |
| `tests/test_cli.py` | `--label` flag integration test |

---

### Task 0: Update Data Models

Foundation — everything else depends on these types.

**Files:**
- Modify: `taint_engine/models.py`
- Modify: `tests/test_taint_models.py`

- [ ] **Step 1: Write failing tests for new model fields**

Add tests to `tests/test_taint_models.py` verifying:
- `TransformerInfo` dataclass creation and `to_dict()`/`from_dict()` roundtrip
- `SanitizerInfo` new fields: `removes`, `sets_state`, `discovery_order`, `effective`, `invalidated_by` — defaults work, `to_dict()` includes them, `from_dict()` handles missing keys
- `TaintFlow` new fields: `active_label`, `transformers`, `final_state` — `to_dict()` includes them, `from_dict()` handles missing keys

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/test_taint_models.py -v`

- [ ] **Step 3: Implement model changes**

In `taint_engine/models.py`:

1. Add `TransformerInfo` dataclass (after `SanitizerInfo`):
```python
@dataclass
class TransformerInfo:
    """A function call that changes data representation without sanitizing."""

    name: str
    line: int
    sets_state: str
    discovery_order: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "line": self.line,
            "sets_state": self.sets_state,
        }

    @classmethod
    def from_dict(cls, d: dict) -> TransformerInfo:
        return cls(
            name=d["name"],
            line=d["line"],
            sets_state=d["sets_state"],
            discovery_order=d.get("discovery_order", 0),
        )
```

2. Add fields to `SanitizerInfo` (after `verified`, using defaults):
```python
    removes: list[str] = field(default_factory=lambda: ["*"])
    sets_state: str | None = "sanitized"
    discovery_order: int = 0
    effective: bool = True
    invalidated_by: str | None = None
```

Update `SanitizerInfo.to_dict()` to include new fields. Update `from_dict()` to handle missing keys with defaults.

3. Add fields to `TaintFlow` (after `guards`, using defaults):
```python
    active_label: str | None = None
    transformers: list[TransformerInfo] = field(default_factory=list)
    final_state: str | None = None
```

Update `TaintFlow.to_dict()` and `from_dict()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/test_taint_models.py -v`

- [ ] **Step 5: Run full suite for regressions**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/ -v`
Expected: All existing tests still pass (new fields have defaults)

- [ ] **Step 6: Commit**

```bash
git add taint_engine/models.py tests/test_taint_models.py
git commit -m "feat: add TransformerInfo, extend SanitizerInfo and TaintFlow with label/state fields"
```

---

### Task 1: Rewrite Rule Loader and JSON Files

**Files:**
- Modify: `taint_engine/rules/__init__.py`
- Modify: `taint_engine/rules/python.json`
- Modify: `taint_engine/rules/javascript.json`
- Modify: `taint_engine/rules/go.json`
- Modify: `taint_engine/rules/java.json`
- Modify: `taint_engine/rules/php.json`
- Modify: `tests/test_taint_rules.py`

- [ ] **Step 1: Write failing tests for new rule format**

Add tests to `tests/test_taint_rules.py` verifying:
- New format loads correctly: labeled sources (dict), labeled sinks (dict with call/property/accepts), sanitizers with removes/sets_state, transformers
- `LanguageRules` has new fields: `labeled_sinks`, `sanitizer_labels`, `sanitizer_states`, `transformers`
- `call_sinks` and `property_sinks` are populated by flattening labeled sinks
- New query methods: `check_transformer()`, `get_accepted_states()`, `get_sanitizer_state()`
- Suffix indexing works for transformers (e.g., `b64decode` matches `base64.b64decode`)

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Rewrite all 5 rule JSON files to new format**

Each file follows the schema from the spec. The `python.json` content is provided verbatim in the spec (lines 70-147). For the other languages, adapt the same structure with language-appropriate sources/sinks/sanitizers/transformers. Keep existing entries, restructure into labeled format.

- [ ] **Step 4: Rewrite the loader in `rules/__init__.py`**

Key changes to `LanguageRules`:
- Add: `labeled_sinks: MappingProxyType[str, dict] | None`
- Add: `sanitizer_labels: MappingProxyType[str, list[str]] | None`
- Add: `sanitizer_states: MappingProxyType[str, str] | None`
- Add: `transformers: MappingProxyType[str, str] | None`

Update `_merge()` to:
- Handle `sources` as dict (extract keys for flat `sources` frozenset)
- Handle labeled `sinks` (flatten into `call_sinks`/`property_sinks`, store full structure as `labeled_sinks`)
- Handle `sanitizers` with `removes`/`sets_state` (build `sanitizer_labels` and `sanitizer_states` maps)
- Handle `transformers` section (build `transformers` map with suffix indexing)

Add new query methods to `TaintRuleSet`:
- `check_transformer(ext, callee) -> tuple[str, str] | None` — returns `(name, sets_state)` or None
- `get_accepted_states(ext, label) -> list[str] | None`
- `get_sanitizer_state(ext, callee) -> str | None`

Update `check_sanitizer()` to populate `removes` and `sets_state` on the returned `SanitizerInfo`.

- [ ] **Step 5: Run tests**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/test_taint_rules.py -v`

- [ ] **Step 6: Run full suite**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/ -v`
NOTE: Some existing tests may break due to rule format change — update them.

- [ ] **Step 7: Commit**

```bash
git add taint_engine/rules/ tests/test_taint_rules.py
git commit -m "feat: rewrite rules to labeled format with sinks/accepts, sanitizer removes/sets_state, transformers"
```

---

### Task 2: Walker Foundation — Fork Lists, Path-Scoped Sanitizers, Transformer Detection

Prerequisites for all other walker fixes. Fix 16 (shared mutable lists) must come first because Fix 5 (path-scoped sanitizers) depends on it, and transformer detection follows the same pattern.

**Files:**
- Modify: `taint_engine/walker.py`
- Modify: `tests/test_taint_walker.py`

- [ ] **Step 1: Write failing tests**

Add tests for:
- Sanitizer in one branch doesn't leak to the other branch's flow
- Transformer detection: `base64.b64decode(x)` on RHS records a TransformerInfo
- Transformer suffix matching: bare `b64decode` matches rule `base64.b64decode`
- `WalkState.transformers` list is populated
- `discovery_order` is assigned incrementally

- [ ] **Step 2: Run tests to verify they fail**

- [ ] **Step 3: Implement**

1. **Fix 16**: In `_handle_conditional`, shallow-copy `sanitizers`, `guards`, `unresolved` (and new `transformers`) when creating branch states. Merge them at join point.

2. **Fix 5**: Add `target_variable: str` field to `SanitizerInfo` (the LHS variable of the assignment containing the sanitizer). Record it in `_check_sanitizer`. (Filtering by path is done later in the engine post-processing.)

3. **Transformer detection**: Add `transformers: list[TransformerInfo]` to `WalkState`. Add `_check_transformer()` parallel to `_check_sanitizer()` — uses same AST callee matching + suffix indexing via `rules.check_transformer()`. Call it from `_handle_assignment()` for every call on the RHS. Assign `discovery_order` via a counter on `WalkState`.

4. Add `discovery_order` counter to `WalkState` and increment it in both `_check_sanitizer` and `_check_transformer`.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Run full suite**
- [ ] **Step 6: Commit**

```bash
git add taint_engine/walker.py tests/test_taint_walker.py
git commit -m "feat: fork lists in branches, path-scoped sanitizers, transformer detection"
```

---

### Task 3: Walker Fixes — try/except + with Statement

The two highest-impact walker fixes.

**Files:**
- Modify: `taint_engine/walker.py`
- Modify: `taint_engine/ts_parser/parser.py` (remove `try_statement` from `conditional_types`)
- Modify: `tests/test_taint_walker.py`

- [ ] **Step 1: Write failing tests**

Add inline code snippet tests:
- `try/except`: variable assigned in except handler has reaching definition; sink in except is reachable
- `try/except as e`: the `as` binding creates a definition
- `try/finally`: definitions in finally block are active after
- `with` statement: `as` binding creates a definition; body is walked

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement `_handle_try()`**

In `walker.py`, add `_handle_try(node, grammar, state)`:
- Walk the try body on a forked state
- Walk each `except_clause` child on a forked state (capture `as` binding from the exception name)
- Walk optional else clause on a forked state
- Walk finally clause on the parent state (always executes)
- Merge all branch states

In `_walk_stmts`, add case for `try_statement` → call `_handle_try`.
Remove `try_statement` from Python/JS `conditional_types` in `ts_parser/parser.py`.

- [ ] **Step 4: Implement `with_statement` handling**

In `_walk_stmts`, add case for `with_statement`:
- Extract the context expression and `as` binding (if present)
- Create a definition for the `as` variable with deps from the context expression
- Walk the body

- [ ] **Step 5: Run tests**
- [ ] **Step 6: Run full suite**
- [ ] **Step 7: Commit**

```bash
git add taint_engine/walker.py taint_engine/ts_parser/parser.py tests/test_taint_walker.py
git commit -m "fix: walk try/except handlers and with statement bodies"
```

---

### Task 4: Walker Fixes — Assignment Patterns

Augmented assignment, walrus operator, subscript assignment, *args/**kwargs.

**Files:**
- Modify: `taint_engine/walker.py`
- Modify: `taint_engine/engine.py` (`_extract_parameters` for *args)
- Modify: `tests/test_taint_walker.py`

- [ ] **Step 1: Write failing tests**

- Augmented assignment: `x = a; x += b; sink(x)` → deps include both `a` and `b`
- Walrus: `if (data := source()): sink(data)` → `data` has reaching definition
- Subscript: `d = {}; d["k"] = val; sink(d)` → `d` depends on `val`
- `*args`: `def f(*args): sink(args[0])` → `args` is a parameter

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement fixes**

1. **Fix 2 (augmented assignment)**: In `_handle_assignment`, if node type contains "augmented", add the LHS variable to `rhs_ids`.

2. **Fix 6 (walrus)**: In `_walk_stmts` or `_handle_expression_statement`, check for `named_expression` nodes. Extract `name` (LHS) and `value` (RHS) fields, create a definition.

3. **Fix 9 (subscript)**: In `_handle_assignment`, if the LHS is a `subscript` node, extract the base object identifier. Create a definition that merges deps (don't kill old defs of the base object).

4. **Fix 8 (*args/**kwargs)**: In `engine.py` `_extract_parameters`, handle `list_splat_pattern` and `dictionary_splat_pattern` by extracting the identifier child.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Run full suite**
- [ ] **Step 6: Commit**

```bash
git add taint_engine/walker.py taint_engine/engine.py tests/test_taint_walker.py
git commit -m "fix: augmented assignment, walrus operator, subscript assignment, *args/**kwargs"
```

---

### Task 5: Walker Fixes — Control Flow

switch/match, C-style for, branch termination.

**Files:**
- Modify: `taint_engine/walker.py`
- Modify: `taint_engine/ts_parser/parser.py` (add switch to conditional types or new field)
- Modify: `tests/test_taint_walker.py`

- [ ] **Step 1: Write failing tests**

- JS switch: variable assigned in case branches has reaching definition
- Python match (if tree-sitter supports it): similar
- C-style for: `for (let i = 0; ...)` → `i` has definition from initializer
- Branch termination: `if check: return; sink(x)` → only the fall-through path matters

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement**

1. **Fix 7 (switch/match)**: Add `_handle_switch` that walks each case/match arm on forked states, merges all.

2. **Fix 14 (C-style for)**: In `_handle_loop`, extract `initializer` and `increment` children for C-style for-loops. Walk the initializer before the loop body, walk the increment after each pass.

3. **Fix 11 (branch termination)**: In `_handle_conditional`, after walking a branch, check if it ends with `return_statement` or `raise_statement` (or `throw_statement` for JS). If so, mark the branch as terminating and don't include its final state in the merge. If both branches terminate, mark the parent as terminating.

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Run full suite**
- [ ] **Step 6: Commit**

```bash
git add taint_engine/walker.py taint_engine/ts_parser/parser.py tests/test_taint_walker.py
git commit -m "fix: switch/match handling, C-style for init, branch termination"
```

---

### Task 6: AST Helpers and Source Detection Fixes

**Files:**
- Modify: `taint_engine/ast_helpers.py`
- Modify: `taint_engine/engine.py`
- Modify: `taint_engine/rules/__init__.py` (remove dead `is_source` — Fix 13)
- Modify: `tests/test_taint_engine.py`
- Modify: `tests/test_taint_walker.py`

- [ ] **Step 1: Write failing tests**

- `collect_identifiers` skips callee names: `len(x)` → deps = `{x}` not `{len, x}`
- Source match false positive: expression text `"mentions request.args in a string"` is NOT a source
- `validate_input()` does NOT match source `input()`
- Keyword arg filtering: `requests.get(url, timeout=5)` → sink vars = `{url}` not `{url, timeout}`
- Sanitizer suffix: `custom_module.escape()` does NOT match `html.escape`

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement**

1. **Fix 10 (collect_identifiers)**: In `ast_helpers.py`, modify `collect_identifiers` to skip identifiers that are the `function` field child of a call node (the callee name). Walk the tree, and for each identifier check if its parent is a call and it's in the `function` field position.

2. **Fix 4 (source detection)**: In `engine.py` `_trace_back`, replace `if source in expr` with a more precise check. At minimum, use word-boundary matching: check that the source pattern appears as a whole token, not as a substring of a larger identifier or inside a string literal. Better: walk the definition's AST node (stored in `Definition.node`) to find structural matches.

3. **Fix 12 (keyword arg names)**: In `engine.py` `_find_vars_at_line` Pass 1, when walking argument children, skip identifiers where `arg_child.parent.type == "keyword_argument"` and `arg_child == arg_child.parent.child_by_field_name("name")`.

4. **Fix 13 (dead code)**: Remove `TaintRuleSet.is_source()` from `rules/__init__.py`.

5. **Fix 15 (sanitizer suffix)**: In `rules/__init__.py` `check_sanitizer()`, when doing suffix lookup, only match if the suffix is an exact key in the sanitizer map (not a suffix of another key). Additionally, require the callee to either be the exact rule name or have the rule name as a dotted suffix (i.e., `foo.escape` matches rule `escape`, but `myescape` does not).

- [ ] **Step 4: Run tests**
- [ ] **Step 5: Run full suite**
- [ ] **Step 6: Commit**

```bash
git add taint_engine/ast_helpers.py taint_engine/engine.py taint_engine/rules/__init__.py tests/
git commit -m "fix: source detection, collect_identifiers, keyword arg filtering, sanitizer suffix matching"
```

---

### Task 7: Engine — Label Detection and State Checking

The core labels/flow-state feature.

**Files:**
- Modify: `taint_engine/engine.py`
- Modify: `tests/test_taint_engine.py`

- [ ] **Step 1: Write failing tests**

Use inline code snippet tests with the test parser:
- **Scenario A**: `html.escape` before SQL sink → sanitizer marked `effective=False`
- **Scenario B**: `html.escape` then `base64.b64decode` before HTML sink → sanitizer marked `effective=False`, `invalidated_by` set
- **Scenario C**: `html.escape` before HTML sink → sanitizer marked `effective=True`
- **No label**: unknown sink → all sanitizers count (existing behavior)
- **Label detection**: `cursor.execute` → label `sql`; `requests.get` → label `ssrf`

- [ ] **Step 2: Run tests to verify they fail**
- [ ] **Step 3: Implement label detection**

In `engine.py`:

1. Update `_find_vars_at_line` return type to `list[tuple[str, str, str | None]]`. Extract sink identifier:
   - Pass 1: `get_full_callee(call_node)`
   - Pass 2: `None`
   - Pass 3: `get_member_property(left)`

2. Add `_detect_label(sink_identifier, rules, ext) -> str | None` that matches the identifier against `labeled_sinks`.

3. Add `label: str | None = None` parameter to `trace_taint_flow()`.

- [ ] **Step 4: Implement state-checking post-processing**

Add `_apply_label_analysis(flow, active_label, rules, ext)`:

1. **Check 1 — Label matching**: For each sanitizer, if `active_label not in removes` and `"*" not in removes`, set `effective = False`.

2. **Check 2 — State acceptance**: Merge sanitizers and transformers by `(line, discovery_order)`. Walk in order to find last `sets_state`. Compare to `accepts` list. Mark sanitizers ineffective if final state not accepted.

3. Set `flow.active_label` and `flow.final_state`.

Call `_apply_label_analysis` after building the `TaintFlow` in `trace_taint_flow()`.

- [ ] **Step 5: Run tests**
- [ ] **Step 6: Run full suite**
- [ ] **Step 7: Commit**

```bash
git add taint_engine/engine.py tests/test_taint_engine.py
git commit -m "feat: label detection from sink, state-checking post-processing"
```

---

### Task 8: CLI and Formatters

**Files:**
- Modify: `taint_engine/cli/cmd_trace.py`
- Modify: `taint_engine/cli/formatters/text.py`
- Modify: `taint_engine/cli/formatters/json_fmt.py`
- Modify: `taint_engine/cli/formatters/sarif.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_formatters.py`

- [ ] **Step 1: Add `--label` CLI flag**

In `cmd_trace.py`, add `--label` argument to the trace subparser. Pass it to `trace_taint_flow()` as the `label` parameter. Also pass it to `_augment_cross_file()` for cross-file inheritance.

- [ ] **Step 2: Update text formatter**

Show sanitizer effectiveness:
- `effective=True`: `html.escape (effective, state: html-encoded)`
- `effective=False` (wrong label): `html.escape (INEFFECTIVE — does not address 'sql' sinks)`
- `effective=False` (state changed): `html.escape (INEFFECTIVE — state changed to 'raw-bytes' by base64.b64decode)`

Show flow state chain when `active_label` is set:
```
  Flow state: raw → html-encoded → raw-bytes (sink expects: html-encoded)
```

- [ ] **Step 3: Update JSON formatter**

Include `active_label`, `final_state`, `transformers` in the output. Include new `SanitizerInfo` fields.

- [ ] **Step 4: Update SARIF formatter**

Include label and state info in SARIF `relatedLocations` or `properties`.

- [ ] **Step 5: Write tests**

- CLI: `taint-trace trace file.py:42 --label sql` works
- Text formatter: effective/ineffective sanitizer display
- JSON formatter: new fields present
- Formatter tests with `TransformerInfo` in the flow

- [ ] **Step 6: Run all tests**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/ -v`

- [ ] **Step 7: Commit**

```bash
git add taint_engine/cli/ tests/test_cli.py tests/test_formatters.py
git commit -m "feat: --label CLI flag, label/state display in all formatters"
```

---

### Task 9: Integration Tests and Final Verification

End-to-end tests using fixture files that exercise the full pipeline.

**Files:**
- Create: `tests/fixtures/taint_labels_sample.py`
- Modify: `tests/test_taint_engine.py`

- [ ] **Step 1: Create fixture file with label/state scenarios**

```python
# tests/fixtures/taint_labels_sample.py
# WARNING: line numbers are load-bearing — tests depend on exact positions.

import html
import base64

def wrong_sanitizer_for_context(user_input):
    safe = html.escape(user_input)
    cursor.execute("SELECT * FROM t WHERE name=" + safe)

def sanitization_invalidated(user_input):
    safe = html.escape(user_input)
    decoded = base64.b64decode(safe)
    response.write(decoded)

def correct_sanitization(user_input):
    safe = html.escape(user_input)
    response.write(safe)

def try_except_flow(user_input):
    try:
        result = process(user_input)
    except Exception as e:
        cursor.execute(user_input)

def with_statement_flow(user_path):
    with open(user_path) as fh:
        content = fh.read()
    cursor.execute(content)

def augmented_assignment_flow(a, b):
    x = a
    x += b
    cursor.execute(x)
```

- [ ] **Step 2: Write integration tests**

Test each fixture function through `trace_taint_flow()` with the real parser and rules. Verify:
- Label is correctly detected from sink expression
- Sanitizer effectiveness is correct
- `final_state` is correct
- try/except, with, augmented assignment flows work

- [ ] **Step 3: Run all tests**

Run: `cd /Users/n3m0/Code/taint-engine && python -m pytest tests/ -v`
Expected: All pass

- [ ] **Step 4: Run the binary against the smallweb repo**

Rebuild the binary and re-test against the real-world code:
```bash
cd /Users/n3m0/Code/taint-engine
pip install -e ".[cli,dev]"
taint-trace trace /Users/n3m0/Code/smallweb/app/sw.py:1070 --format json
```

Verify the SSRF flow now shows `html.escape` as INEFFECTIVE if present, and the label is correctly detected as `ssrf`.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/taint_labels_sample.py tests/test_taint_engine.py
git commit -m "test: integration tests for taint labels, flow state, and engine fixes"
```

---

### Task 10: Rebuild Binary

- [ ] **Step 1: Rebuild and smoke test**

```bash
cd /Users/n3m0/Code/taint-engine
pip install -e ".[cli,dev]"
pyinstaller --name taint-trace --onefile \
  --collect-all tree_sitter --collect-all tree_sitter_python \
  --collect-all tree_sitter_javascript --collect-all tree_sitter_typescript \
  --collect-all taint_engine \
  taint_trace_entry.py

./dist/taint-trace trace /Users/n3m0/Code/smallweb/app/sw.py:1070 --format json
./dist/taint-trace trace /Users/n3m0/Code/smallweb/app/sw.py:1070 --label ssrf --format json
```
