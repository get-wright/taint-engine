# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Intraprocedural taint-tracing engine built on tree-sitter ASTs. Traces data flow from sources to sinks within individual functions using reaching-definitions analysis with structured access paths. Zero runtime dependencies — tree-sitter is injected via a Protocol-based parser interface.

Includes a CLI (`taint-trace`) with three subcommands: `index`, `symbols`, `trace`. Distributable as a standalone binary via PyInstaller (`dist/taint-trace`).

## Build & Test

```bash
pip install -e ".[dev]"        # editable install with dev deps
pytest                          # all tests (~273)
pytest tests/test_taint_engine.py::test_straight_line_python  # single test
pytest -k "test_walk_branch_merge"                             # keyword match
pytest --ignore=tests/test_eval_ground_truth.py                # skip eval harness (needs external repos)
pyinstaller taint_trace_entry.py --onefile --name taint-trace  # build standalone binary
```

No linter, formatter, or type checker configured. No CI pipeline. No Makefile.

## Architecture

The engine pipeline: `trace_taint_flow()` → parse file → find function → `walker.walk_body()` (forward pass building reaching definitions) → `_find_vars_at_line()` (sink variables) → `_trace_back()` (backward chain to source) → `TaintFlow`.

The walker handles assignments, tuple/destructuring unpacking (with field-aware deps), for-loop binding, branch fork-merge (if/else → two definition sets merged at join), loop two-pass approximation, sanitizer detection, guard detection, and accessor normalization (`.get("key")` → subscript).

### Data model

- `Selector(kind, name)` — a single step: `"field"`, `"subscript"`, or `"call_result"`
- `AccessPath(base, selectors)` — structured variable path (e.g., `request.args["next"]`). Constructors: `from_identifier()`, `from_dotted()`, `parse()` (round-trips canonical names). Builder methods: `with_field()`, `with_subscript()`, `with_call_result()`
- `Definition.deps: frozenset[AccessPath]` — each definition tracks structured dependencies, not plain strings

### Key functions

- `_resolve_expression_path(node, grammar, rules, ext)` → `AccessPath | None` — resolves AST expressions to canonical paths. Handles member access, subscript accessors (`.get()`, `.pop()` etc.), call results, and direct subscripts
- `_resolve_deps(rhs_node, ...)` → `frozenset[AccessPath]` — resolves RHS to structured deps, splitting compound expressions
- `ActiveDefs.reaching_path(path)` → `(defs, remaining_selectors)` — prefix-based definition lookup with progressive selector fallback
- `_match_source_by_path(source, base, selectors)` — checks if a rule source matches via access path prefix
- `_trace_back(..., accumulated_selectors)` — backward trace with selector accumulation across definition chains

### Key design decisions

- `Parser` protocol (`parser_protocol.py`) decouples engine from any specific parser — consumers inject their own
- `__init__.py` uses `__getattr__` for lazy import of `trace_taint_flow` to break a circular dependency chain — don't eagerly import `engine` there
- JSON rule files (`rules/*.json`) per language define sources, sinks (by taint label), sanitizers, guards, and `subscript_accessors`
- `object` type annotations on some parameters are intentional (duck-typed protocol objects)
- `_resolve_expression_path` is imported cross-module (walker → engine) despite the underscore prefix — it's part of the internal API

**CLI layer** (`taint_engine/cli/`): `main.py` dispatches to `cmd_index.py`, `cmd_symbols.py`, `cmd_trace.py`. Formatters live in `cli/formatters/` (text, json, sarif). The `resolver/` package handles cross-file symbol resolution backed by a SQLite index.

## Code Style

- Black-style: 88-char lines, double quotes, trailing commas on multi-line
- Every source module starts with `from __future__ import annotations`
- Intra-package: relative imports. Tests: absolute imports
- Type hints on all public functions. `Protocol` classes for duck-typed interfaces
- `@dataclass(frozen=True)` for immutable value objects
- Module-level docstrings on every file; function docstrings on public functions
- Files under 500 lines (walker.py is an exception at ~1158 lines — access path resolution helpers could be extracted)

## Testing Conventions

- pytest 8+ with `asyncio_mode = "auto"`
- No conftest.py — shared setup in `tests/parser_helpers.py` as module-level constants
- Fixtures in `tests/fixtures/` — **line numbers are load-bearing**; editing fixtures requires updating test expectations
- Plain `assert` (no `pytest.raises` — uses try/except pattern)
- `unittest.mock.AsyncMock` for external clients
- `tests/test_eval_ground_truth.py` — parametrized eval harness over real-world repos in `tmp/eval_repos*/`; skips when repos absent

## Common Pitfalls

- Test fixture files have line-number-sensitive assertions — comments at fixture tops warn about this
- The walker uses two-pass loop approximation — loop-carried definitions may need manual verification
- `try/except/finally` handling is partial: `try` blocks enter conditional handling but except clause bindings aren't fully tracked
- Return `None` for non-fatal failures; raise `FileNotFoundError`/`ValueError` for configuration errors
- `AccessPath.from_dotted()` only handles dot-separated names — use `AccessPath.parse()` for canonical names with subscripts/call_results
- Anonymous function expressions (`exports.x = function() {}`) are not detected as functions — only named `function` declarations and Python `def` statements
- When no taint source traces to a sink, `trace_taint_flow()` returns `None` — no fake "hardcoded" flows

## Git

Conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`, etc. One logical change per commit.
