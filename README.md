# taint-engine

Intraprocedural taint tracing engine built on tree-sitter ASTs. Traces data flow from sources to sinks within individual functions using reaching-definitions analysis.

**Zero runtime dependencies.** The engine operates on any AST nodes that satisfy a simple protocol — tree-sitter, custom parsers, or mocked nodes all work.

## What it does

Given a function, a sink line number, and a set of taint rules, the engine:

1. Walks the function body building **reaching definitions** for every variable
2. Identifies the **sink variables** at the target line
3. **Traces backward** through the definition chain to find the original source
4. Reports the full **taint path**, any **sanitizers** or **guards** encountered, and **unresolved calls** that couldn't be followed

```
request.args.get("url")          ← source
  → url.split("/")[3]            ← assignment
  → owner, repo = ...           ← tuple unpacking
  → requests.get(f"...{owner}") ← sink (19 steps total)
```

## Quick start

```bash
pip install -e ".[dev]"    # includes tree-sitter + grammars for testing
pytest                     # 93 tests
```

### Basic usage

```python
from taint_engine import trace_taint_flow, load_rules

rules = load_rules("path/to/taint_engine/rules")

flow = trace_taint_flow(
    file_path="app.py",
    function_name="handle_request",
    sink_line=42,
    check_id="python.sqli",
    cwe_list=["CWE-89"],
    rules=rules,
    parser=your_parser,
)

if flow:
    for step in flow.path:
        print(f"[{step.kind}] line {step.line}: {step.variable}")
    for san in flow.sanitizers:
        print(f"Sanitizer: {san.name}")
    for guard in flow.guards:
        print(f"Guard: {guard.name} at line {guard.line}")
```

### Implementing the Parser protocol

The engine needs a `parser` object with two methods:

```python
class Parser(Protocol):
    def parse_file(self, path: str) -> ASTNode: ...
    def get_grammar(self, extension: str) -> LanguageGrammar | None: ...
```

**`ASTNode`** — any object with `.type`, `.text`, `.children`, `.start_point`, `.end_point`, `.parent`, and `.child_by_field_name()`. Tree-sitter nodes satisfy this natively.

**`LanguageGrammar`** — an object with attributes describing the language's AST node types:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class PythonGrammar:
    func_types = ("function_definition",)
    call_types = ("call",)
    assignment_types = ("assignment", "augmented_assignment")
    parameter_types = ("parameters",)
    return_types = ("return_statement",)
    conditional_types = ("if_statement", "try_statement")
    member_access_types = ("attribute",)
    has_arrow_functions = False
```

A tree-sitter adapter is included in `tests/parser_helpers.py` as a reference implementation.

## Language support

Rules are JSON files in `taint_engine/rules/`:

| Language | Sources | Call sinks | Property sinks | Sanitizers | Guards |
|----------|---------|------------|----------------|------------|--------|
| Python | `request.args`, `os.environ`, `sys.argv`, ... | `eval`, `cursor.execute`, `subprocess.run`, ... | — | `html.escape`, `shlex.quote`, ... | `re.match`, `re.fullmatch`, ... |
| JavaScript | `req.query`, `req.body`, `document.location`, ... | `eval`, `res.send`, `exec`, ... | `innerHTML`, `outerHTML`, `href`, `src`, ... | `escapeHtml`, `DOMPurify.sanitize`, ... | `validator.isEmail`, ... |
| Go | `r.URL.Query`, `r.FormValue`, `os.Getenv`, ... | `db.Query`, `exec.Command`, `fmt.Fprintf`, ... | — | `html.EscapeString`, `url.QueryEscape`, ... | `regexp.MatchString`, ... |
| Java | `request.getParameter`, `System.getenv`, ... | `stmt.executeQuery`, `Runtime.exec`, ... | — | `StringEscapeUtils.escapeHtml4`, ... | `Pattern.matches`, ... |
| PHP | `$_GET`, `$_POST`, `$_REQUEST`, ... | `eval`, `mysqli_query`, `exec`, ... | — | `htmlspecialchars`, `mysqli_real_escape_string`, ... | `preg_match`, `filter_var`, ... |

### Adding rules

Create or edit a JSON file in `taint_engine/rules/`:

```json
{
  "language": "python",
  "extensions": [".py"],
  "sources": ["request.args", "os.environ"],
  "sinks": {
    "call": ["cursor.execute", "eval"],
    "property": []
  },
  "sanitizers": [
    {"name": "html.escape", "neutralizes": ["CWE-79"]}
  ],
  "guards": [
    {"name": "re.match", "validates": ["format"]}
  ]
}
```

## Architecture

```
trace_taint_flow()
  ├── parse file → find function node
  ├── extract parameters → seed reaching definitions
  ├── walker.walk_body()
  │     ├── assignments → Definition(variable, deps, expression)
  │     ├── branches → fork/merge ActiveDefs
  │     ├── loops → two-pass approximation + loop variable binding
  │     ├── sanitizer calls → SanitizerInfo
  │     └── guard conditions → GuardInfo
  ├── _find_vars_at_line() → sink variables
  └── _trace_back() → backward chain to source
        → TaintFlow(path, sanitizers, guards, unresolved_calls)
```

### Key modules

| Module | Purpose |
|--------|---------|
| `engine.py` | Top-level `trace_taint_flow()`, backward tracing, function/variable discovery |
| `walker.py` | Forward AST walk building reaching definitions with branch fork-merge |
| `models.py` | `TaintFlow`, `FlowStep`, `SanitizerInfo`, `GuardInfo`, `AccessPath` |
| `rules/` | JSON rule loader, `TaintRuleSet` with source/sink/sanitizer/guard queries |
| `ast_helpers.py` | Tree-sitter node utilities (walk, collect identifiers, extract callees) |
| `parser_protocol.py` | `Parser`, `LanguageGrammar`, `ASTNode` protocol definitions |
| `sanitizer_checker.py` | Legacy sanitizer lookup (delegates to rules) |
| `sink_source_inference.py` | CWE-based sink/source type inference when rules don't cover a finding |
| `cross_file.py` | Optional cross-file resolution via external definition search (e.g., gkg) |

### What the walker handles

- Simple assignments (`x = expr`)
- Tuple/pattern unpacking (`owner, repo = expr1, expr2`)
- JS destructuring (`const { name } = obj`, `const [a, b] = arr`)
- For-loop variable binding (`for entry in items:`, `for (const x of list)`)
- Branch fork-merge (`if/else` → two definition sets merged at join point)
- Loop two-pass approximation (loop-carried definitions)
- Augmented assignments (`x += expr`)
- Member access assignments (`obj.field = expr`)
- Sanitizer detection in RHS calls
- Guard detection in branch conditions

## Output

`trace_taint_flow()` returns a `TaintFlow` or `None`:

```python
@dataclass
class TaintFlow:
    path: list[FlowStep]           # source → ... → sink
    sanitizers: list[SanitizerInfo] # sanitizer calls found in scope
    unresolved_calls: list[str]    # calls that couldn't be followed
    cross_file_hops: list[CrossFileHop]
    confidence_factors: list[str]  # human-readable notes
    inferred: InferredSinkSource   # CWE-based sink/source inference
    guards: list[GuardInfo]        # validation guards in scope
```

Each `FlowStep` has a `kind`: `"source"`, `"parameter"`, `"assignment"`, `"sink"`.

## Limitations

- **Intraprocedural only.** Traces within a single function. Cross-function flows require the optional `cross_file.resolve_cross_file()` with an external definition search service.
- **No alias analysis.** `y = x; z = y` traces through, but `arr[i] = x; y = arr[j]` does not connect `x` to `y`.
- **No interprocedural return tracking.** `y = f(x)` follows `x` into unresolved calls but doesn't trace `f`'s return value.
- **Template files unsupported.** HTML/Jinja/Dockerfile don't have tree-sitter grammars with function scoping.
- **`try/except/finally` partial.** `try` blocks enter conditional handling but except clause bindings aren't fully tracked.

## License

MIT
