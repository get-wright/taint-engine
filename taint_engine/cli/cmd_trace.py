"""Implementation of the ``taint-trace trace`` subcommand."""

from __future__ import annotations

import os
import sys

from ..models import CrossFileHop, TaintFlow
from ..resolver.index_store import IndexStore
from ..resolver.js_resolver import JsResolver
from ..resolver.python_resolver import PythonResolver
from ..resolver.symbol_extractor import find_enclosing_function, find_symbols_at_line
from ..ts_parser import TreeSitterParser
from .formatters.json_fmt import format_json
from .formatters.sarif import format_sarif
from .formatters.text import format_text


def _parse_target(target: str) -> tuple[str, int]:
    """Parse 'file.py:42' into (file_path, line_number)."""
    if ":" not in target:
        raise ValueError(f"Invalid target format: {target!r} (expected file:line)")
    parts = target.rsplit(":", 1)
    try:
        line = int(parts[1])
    except ValueError:
        raise ValueError(f"Invalid line number: {parts[1]!r}")
    return parts[0], line


def _resolver_for_file(file_path: str, args):
    """Build the correct resolver for a source file."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".py":
        search_paths = (
            args.python_path.split(",")
            if args.python_path
            else [os.path.abspath(os.path.dirname(file_path))]
        )
        return PythonResolver(search_paths=search_paths)
    if ext in (".js", ".jsx", ".ts", ".tsx"):
        return JsResolver()
    return None


def _cross_file_action(flow: TaintFlow | None) -> str:
    if flow is None:
        return "unknown"
    if flow.sanitizers:
        return "sanitizes"
    if any(step.kind == "parameter" for step in flow.path):
        return "propagates"
    return "transforms"


def _augment_cross_file(
    flow: TaintFlow,
    *,
    source_file: str,
    resolver,
    index: IndexStore,
    parser,
    rules,
    check_id: str,
    cwe_list: list[str],
    args,
    label: str | None = None,
    depth: int = 0,
    visited: set[tuple[str, str]] | None = None,
) -> TaintFlow:
    """Follow unresolved calls through the local index and attach cross-file hops."""
    from .. import trace_taint_flow

    if visited is None:
        visited = set()
    if depth >= args.max_depth:
        return flow

    hops = list(flow.cross_file_hops)
    for callee in flow.unresolved_calls:
        resolved = resolver.resolve_import(source_file, callee, index)
        if resolved is None:
            continue

        visit_key = (resolved.file_path, resolved.name)
        if visit_key in visited:
            continue
        visited.add(visit_key)

        sub_flow = trace_taint_flow(
            file_path=resolved.file_path,
            function_name=resolved.name,
            sink_line=resolved.end_line + 1,
            check_id=check_id,
            cwe_list=cwe_list,
            rules=rules,
            parser=parser,
            label=label,
        )

        child_resolver = _resolver_for_file(resolved.file_path, args)
        if sub_flow is not None and child_resolver is not None:
            sub_flow = _augment_cross_file(
                sub_flow,
                source_file=resolved.file_path,
                resolver=child_resolver,
                index=index,
                parser=parser,
                rules=rules,
                check_id=check_id,
                cwe_list=cwe_list,
                args=args,
                label=label,
                depth=depth + 1,
                visited=visited,
            )

        hops.append(
            CrossFileHop(
                callee=callee,
                file=resolved.file_path,
                line=resolved.line,
                action=_cross_file_action(sub_flow),
                sub_flow=sub_flow,
            )
        )

    return TaintFlow(
        path=flow.path,
        sanitizers=flow.sanitizers,
        unresolved_calls=flow.unresolved_calls,
        cross_file_hops=hops,
        confidence_factors=flow.confidence_factors,
        inferred=flow.inferred,
        guards=flow.guards,
        active_label=flow.active_label,
        transformers=flow.transformers,
        final_state=flow.final_state,
    )


def run_trace(args) -> int:
    try:
        file_path, line = _parse_target(args.target)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not os.path.isfile(file_path):
        print(f"Error: file not found: {file_path}", file=sys.stderr)
        return 1

    ext = os.path.splitext(file_path)[1].lower()
    parser = TreeSitterParser()

    try:
        root = parser.parse_file(file_path)
        lang = parser.get_language(ext)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    line_0 = line - 1

    func_name = find_enclosing_function(root, lang, ext, line=line_0)
    if func_name is None:
        print(
            f"Error: no function found at line {line} in {file_path}",
            file=sys.stderr,
        )
        return 1

    if args.symbol:
        target_symbols = [args.symbol]
    else:
        syms_at_line = find_symbols_at_line(root, lang, ext, line=line_0)
        target_symbols = (
            [s.name for s in syms_at_line] if syms_at_line else [func_name]
        )

    from .. import load_rules

    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules")
    rules = load_rules(rules_dir)

    _LANG_CHECK_PREFIX = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
    }
    lang_prefix = _LANG_CHECK_PREFIX.get(ext, ext.lstrip("."))
    check_id = args.check_id or f"{lang_prefix}.taint"
    cwe_list = args.cwe.split(",") if args.cwe else []

    from .. import trace_taint_flow

    label = getattr(args, "label", None)

    flows: list[TaintFlow] = []
    for _sym in target_symbols:
        flow = trace_taint_flow(
            file_path=file_path,
            function_name=func_name,
            sink_line=line,
            check_id=check_id,
            cwe_list=cwe_list,
            rules=rules,
            parser=parser,
            label=label,
        )
        if flow is not None:
            flows.append(flow)
            break

    if args.cross_file and flows:
        store = IndexStore(args.db)
        try:
            resolver = _resolver_for_file(file_path, args)
            if resolver is not None:
                flows[0] = _augment_cross_file(
                    flows[0],
                    source_file=file_path,
                    resolver=resolver,
                    index=store,
                    parser=parser,
                    rules=rules,
                    check_id=check_id,
                    cwe_list=cwe_list,
                    args=args,
                    label=label,
                )
        finally:
            store.close()

    fmt = args.format
    if fmt == "text":
        if flows:
            print(format_text(flows[0], file_path=file_path))
        else:
            print(format_text(None, file_path=file_path))
    elif fmt == "json":
        if flows:
            print(format_json(flows[0], file_path=file_path))
        else:
            print(format_json(None, file_path=file_path))
    elif fmt == "sarif":
        print(format_sarif(flows, file_path=file_path))

    return 0
