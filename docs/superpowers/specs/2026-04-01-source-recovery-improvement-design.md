# Design: Improve Universal Source Recovery

**Date:** 2026-04-01
**Approach:** Incremental Access-Path Enrichment (Approach A)
**Prompt:** `docs/superpowers/specs/2026-04-01-source-recovery-improvement-prompt.md`

## Problem

The taint engine tracks dataflow using plain string variable names. This causes
it to fail at recovering true sources when they involve property reads
(`req.body.email`), accessor calls (`request.args.get("next")`), destructured
aliases (`{ query } = req`), nested call results (`make_response(si.getvalue())`),
or structured extraction (`validated_data.pop("password")`).

The root cause is that `ActiveDefs.defs` is `dict[str, set[Definition]]`,
`Definition.deps` is `frozenset[str]`, and backward tracing in `_trace_back()`
follows plain variable names. The `AccessPath` dataclass exists but is
decorative — `selectors` is always `()`.

## Approach

Keep the current walker/engine architecture. Progressively widen the fact domain
from `str` to `AccessPath` without a big-bang rewrite. No backward compatibility
shim — all call sites migrate in one pass.

### Verified non-impact

The label/state pipeline (`_apply_label_analysis`, sanitizer/transformer
tracking, `_detect_label`) operates on callee names, sink identifiers, line
numbers, and rule-defined labels/states. None of these touch `ActiveDefs` keys
or `Definition.deps`. Zero changes needed there.

## Section 1: Data Structures

### Selector

New frozen dataclass in `models.py`:

```python
@dataclass(frozen=True)
class Selector:
    kind: str   # "field" | "subscript" | "call_result"
    name: str   # field name, subscript key, or callee name
```

### AccessPath (enhanced)

`AccessPath` already exists with `base: str` and `selectors: tuple`. Changes:

- `selectors` type becomes `tuple[Selector, ...]`
- New constructors: `from_identifier(name)`, `from_dotted(dotted_str)`
- New methods: `with_field(name)`, `with_subscript(key)`, `with_call_result(callee)`
- New property `name` — canonical string representation used as dict key:
  - `AccessPath("request", (Selector("field","args"), Selector("subscript","next")))` → `"request.args[\"next\"]"`
  - `AccessPath("si", (Selector("call_result","getvalue"),))` → `"si.getvalue()"`

### ActiveDefs key scheme

`ActiveDefs.defs` stays `dict[str, set[Definition]]` but keys become
`AccessPath.name` (the canonical string). This means `request.args["next"]` and
`request.args.get("next")` normalize to the same key after accessor
normalization.

### Definition.deps

Changes from `frozenset[str]` to `frozenset[AccessPath]`.

### FlowStep.variable

Stays `str`. Populated from `AccessPath.name` for richer output (e.g.
`"request.args[\"next\"]"` instead of just `"request"`).

## Section 2: Accessor Summaries

### Rule schema addition

New `"subscript_accessors"` flat list field in per-language JSON rule files.
Same pattern as the existing `"guards"` list.

```json
{
  "subscript_accessors": ["get", "pop", "getlist"]
}
```

Per language:
- **Python:** `["get", "pop", "getlist", "getattr"]`
- **JavaScript:** `["get", "getAll"]`
- **Go:** `["Get", "Values"]`
- **Java:** `["get", "getParameter", "getAttribute"]`
- **PHP:** `["get", "all", "input"]`

### Accessor normalization

When the walker encounters `receiver.accessor(string_literal)` and `accessor`
is in the language's `subscript_accessors` list, it normalizes to
`receiver["string_literal"]`. The resulting `AccessPath` uses a `subscript`
selector instead of a `call_result` selector.

### _resolve_expression_path()

New helper in `walker.py` that extracts a canonical `AccessPath` from an
expression AST node. Handles:

- Identifiers → `AccessPath.from_identifier(name)`
- Member access (`a.b`) → `AccessPath.from_dotted("a.b")`
- Recognized accessor calls → normalize to subscript
- Unrecognized calls → `call_result` selector on the receiver
- Subscript expressions (`a["b"]`) → `subscript` selector

### Destructuring alias preservation

For `const { query } = req`, the walker creates:
- `query` depends on `AccessPath("req", (Selector("field","query"),))`

For `const file = params.file`, the walker creates:
- `file` depends on `AccessPath("params.file")` which is
  `AccessPath("params", (Selector("field","file"),))`

### TaintRuleSet changes

`TaintRuleSet` and the rule loader in `rules/__init__.py` gain:
- `subscript_accessors(ext) -> list[str]` method
- Loading logic for the new JSON field (defaulting to `[]` if absent)

## Section 3: Expression-Aware Backward Tracing

### Signature change

`_trace_back()` receives `var: AccessPath` instead of `str`. The initial call
from `trace_taint_flow()` wraps sink vars using `AccessPath.from_dotted()`.

### Prefix matching in ActiveDefs

New method `ActiveDefs.reaching_path(path: AccessPath) -> tuple[set[Definition], tuple[Selector, ...]]`:

1. Try exact match on `path.name`
2. If no match, try progressively shorter prefixes: drop the last selector,
   recompute `name`, look up again
3. Return `(defs, remaining_selectors)` — the defs at the longest matching
   prefix, and the selectors that were not consumed

This replaces the ad-hoc `"." in var` fallback in the current `_trace_back()`.

### Selector accumulation across recursion

`_trace_back()` gains `accumulated_selectors: tuple[Selector, ...] = ()`.

Flow:
1. `reaching_path(var)` returns `(defs, remaining)`
2. Effective selectors for source matching: `remaining + accumulated_selectors`
3. When recursing into dep: `_trace_back(dep, ..., accumulated_selectors=remaining + accumulated_selectors)`

This solves multi-hop chains where selectors must carry across definition
boundaries. Example:

```
const { query } = req     // query deps: AccessPath("req", (field:query))
const toUrl = query.to     // toUrl deps: AccessPath("query.to")
res.redirect(toUrl)        // sink var: toUrl
```

Trace:
1. `trace_back(AccessPath("query.to"), accumulated=())`
2. Prefix match `query`, remaining=`(field:to)`
3. `query` deps → `AccessPath("req.query")`
4. Recurse: `trace_back(AccessPath("req.query"), accumulated=(field:to))`
5. Prefix match `req` (parameter), remaining=`(field:query)`
6. Effective = `(field:query, field:to)` → `req.query.to`
7. Source rule `req.query` is prefix → match

### Visited set

Uses `set[tuple[str, int]]` where the string is `AccessPath.name`. No object
identity issues.

### Unchanged

Recursive structure, `max_depth=50`, best-flow selection preference for
`source`/`parameter` kinds, label analysis — all unchanged.

## Section 4: Source Detection

### _match_source_by_path()

New function complementing `_is_source_in_node()`:

```python
def _match_source_by_path(
    source: str,
    resolved_base: str,
    effective_selectors: tuple[Selector, ...],
) -> bool
```

Logic:
1. Reconstruct effective path from resolved base + effective selectors
   (e.g., `request` + `(field:args, subscript:next)` → `request.args["next"]`)
2. Check if any rule source is a prefix of this effective path
3. For call sources (ending `()`), check for `call_result` selector at the
   appropriate position

### Integration into _trace_back()

When recursion bottoms out at a parameter or a definition with no further deps:
1. Compute effective selectors = `remaining + accumulated_selectors`
2. Try `_match_source_by_path()` against all rule sources
3. If match: return `FlowStep(kind="source", variable=effective_path_string)`
4. If no match: fall through to existing behavior (return parameter step or None)

When a definition has a node and expression:
1. First try `_is_source_in_node()` (unchanged — handles direct source text)
2. If that fails, try `_match_source_by_path()` with effective selectors
3. If either matches: return `FlowStep(kind="source")`

### _is_source_in_node() — unchanged

Continues to handle the common case where a definition's expression directly
contains a source pattern. The path-based matching is additive.

### Sink-side expression decomposition

`_find_vars_at_line()` return type becomes `list[tuple[AccessPath, str, str | None]]`.

New extraction cases in the call-argument walk:

- **Accessor calls as sink args:** `request.args.get('next')` inline in a sink
  call → normalize via `_resolve_expression_path()` to
  `AccessPath("request.args[\"next\"]")`
- **Call-result arguments:** `si.getvalue()` (not a recognized accessor) →
  `AccessPath("si", (Selector("call_result","getvalue"),))`
- **Compound expressions:** `x or y`, `x || y` → extract variables from both
  operands as separate entries. The existing best-flow selection loop handles
  picking the tainted one.

## Section 5: Testing

### Layer 1 — Unit tests

**Walker tests** (`test_taint_walker.py`): Inline code snippets verifying the
walker produces correct `AccessPath` objects with proper selectors in
`Definition.deps`.

| Test | Snippet | Assertion |
|------|---------|-----------|
| `test_walk_accessor_normalization` | `y = request.args.get("next")` | dep has `(field:args, subscript:next)` |
| `test_walk_subscript_accessor_pop` | `p = data.pop("key")` | dep has `subscript` selector for `"key"` |
| `test_walk_dotted_member_read` | `u = request.url` | dep has `(field:url)` |
| `test_walk_destructuring_js` | `const { query } = req` | dep is `AccessPath("req", (field:query,))` |
| `test_walk_call_result_dep` | `v = si.getvalue()` | dep has `call_result` selector |
| `test_walk_chained_member` | `e = req.body.email` | dep has `(field:body, field:email)` |

**Engine tests** (`test_taint_engine.py`): End-to-end source recovery via
`trace_taint_flow()` using new fixture files.

New fixtures:
- `tests/fixtures/taint_source_recovery.py` — accessor source, member read,
  alias chain, inline accessor sink, compound expression
- `tests/fixtures/taint_source_recovery.js` — destructured redirect,
  destructured file, inline call result, direct member sink

Assertions: `flow.source.kind == "source"`, source variable contains expected
canonical path, no `"hardcoded"` confidence factor.

### Layer 2 — Eval harness

`tests/test_eval_ground_truth.py` — parametrized over the 11 ground-truth
examples from the spec.

```python
GROUND_TRUTH = [
    {
        "id": "juice-shop-login",
        "file": "tmp/eval_repos/juice-shop-master/routes/login.ts",
        "function": "login",
        "sink_line": 34,
        "check_id": "typescript.sqli",
        "cwe_list": ["CWE-89"],
        "expected_source_contains": ["req.body"],
    },
    # ... 10 more entries
]

@pytest.mark.parametrize("case", GROUND_TRUTH, ids=lambda c: c["id"])
def test_ground_truth(case):
    flow = trace_taint_flow(...)
    assert flow is not None
    assert flow.source.kind in ("source", "parameter")
    for expected in case["expected_source_contains"]:
        assert expected in flow.source.variable or expected in flow.source.expression
```

Initially marked `xfail` — flipped to passing as implementation progresses.
Tests skip when eval repo files are absent.

### What is not tested

- Label/state analysis (unchanged, already covered)
- Sanitizer/transformer detection (unchanged, already covered)
- Performance benchmarks (not in scope)
- Cross-file resolution (out of scope for intraprocedural work)

## Files Modified

| File | Changes |
|------|---------|
| `taint_engine/models.py` | Add `Selector`, enhance `AccessPath` with selectors/constructors/methods |
| `taint_engine/walker.py` | Migrate `Definition.deps` to `frozenset[AccessPath]`, add `_resolve_expression_path()`, accessor normalization, destructuring alias preservation, `ActiveDefs.reaching_path()` |
| `taint_engine/engine.py` | `_trace_back()` takes `AccessPath` + `accumulated_selectors`, add `_match_source_by_path()`, update `_find_vars_at_line()` return type + sink expression decomposition |
| `taint_engine/ast_helpers.py` | Possible new helpers for expression path resolution |
| `taint_engine/rules/__init__.py` | Load `subscript_accessors` field, add accessor |
| `taint_engine/rules/python.json` | Add `"subscript_accessors"` list |
| `taint_engine/rules/javascript.json` | Add `"subscript_accessors"` list |
| `taint_engine/rules/go.json` | Add `"subscript_accessors"` list |
| `taint_engine/rules/java.json` | Add `"subscript_accessors"` list |
| `taint_engine/rules/php.json` | Add `"subscript_accessors"` list |
| `tests/test_taint_walker.py` | New walker-level tests for access path production |
| `tests/test_taint_engine.py` | New engine-level tests for source recovery |
| `tests/fixtures/taint_source_recovery.py` | New Python fixture |
| `tests/fixtures/taint_source_recovery.js` | New JS fixture |
| `tests/test_eval_ground_truth.py` | New eval harness |

## Implementation Sequence

1. `Selector` + enhanced `AccessPath` in `models.py`
2. `_resolve_expression_path()` + accessor normalization in `walker.py`
3. `Definition.deps` migration to `frozenset[AccessPath]`
4. `ActiveDefs.reaching_path()` with prefix matching
5. `_trace_back()` signature change + selector accumulation
6. `_match_source_by_path()` in `engine.py`
7. `_find_vars_at_line()` sink-side decomposition
8. Rule file updates (`subscript_accessors`)
9. Walker unit tests
10. Engine unit tests + fixtures
11. Eval harness

## Ground-Truth Coverage

| # | Example | Pattern | Handled by |
|---|---------|---------|------------|
| 1 | Juice Shop SQL login | `req.body.email` member read | Prefix matching on parameter |
| 2 | Juice Shop redirect | Destructuring + alias chain | Selector accumulation |
| 3 | Juice Shop fileServer | Destructuring + member read | Selector accumulation |
| 4 | NodeGoat redirect | Direct `req.query.url` in sink | Prefix matching on parameter |
| 5 | PyGoat eval POST | `request.POST.get('expression')` | Accessor normalization + prefix |
| 6 | PyGoat eval views | `request.POST.get('val')` | Accessor normalization + prefix |
| 7 | PyGoat raw SQL | POST accessor + string building | Accessor normalization + prefix |
| 8 | Flask-Base login | Inline accessor in sink arg | Sink-side decomposition |
| 9 | simple-login redirect | `request.url` member read | Prefix matching on parameter |
| 10 | simple-login call-result | `si.getvalue()` in sink arg | Sink-side call-result extraction |
| 11 | Django password | `validated_data.pop('password')` | Accessor normalization + prefix |
