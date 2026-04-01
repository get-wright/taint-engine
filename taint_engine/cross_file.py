"""Cross-file taint resolution via gkg definition lookup."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from .models import TaintFlow
from .engine import trace_taint_flow
from .rules import TaintRuleSet

logger = logging.getLogger(__name__)

_TIMEOUT_PER_RESOLUTION = 5.0
_TIMEOUT_TOTAL = 15.0


@dataclass
class CrossFileResult:
    """Result of cross-file callee resolution."""

    action: str  # "propagates" | "sanitizes" | "transforms" | "unknown"
    file: str = ""
    line: int = 0
    sub_flow: Optional[TaintFlow] = None


@dataclass
class _ResolutionCounter:
    """Mutable counter for tracking total gkg lookups."""

    value: int = 0
    max_total: int = 8


async def resolve_cross_file(
    callee_name: str,
    gkg_client,
    repo_path: str,
    rules: TaintRuleSet | None = None,
    parser: object | None = None,
    depth: int = 0,
    max_depth: int = 3,
    visited: Optional[set[str]] = None,
    resolution_counter=None,
) -> CrossFileResult:
    if visited is None:
        visited = set()
    if resolution_counter is None:
        resolution_counter = _ResolutionCounter()

    # Guards
    if callee_name in visited:
        return CrossFileResult(action="unknown")
    if depth >= max_depth:
        return CrossFileResult(action="unknown")
    if resolution_counter.value >= resolution_counter.max_total:
        return CrossFileResult(action="unknown")

    visited.add(callee_name)

    try:
        resolution_counter.value += 1
        results = await asyncio.wait_for(
            gkg_client.search_definitions(callee_name, project_path=repo_path),
            timeout=_TIMEOUT_PER_RESOLUTION,
        )

        if not results:
            return CrossFileResult(action="unknown")

        defn = results[0] if isinstance(results[0], dict) else {}
        file_path = defn.get("file", defn.get("file_path", ""))
        line = defn.get("line", 0)

        if not file_path:
            return CrossFileResult(action="unknown")

        # Use last line of function as sink_line (approximate — traces return statements)
        # The definition line is the function start; we need the end to find returns.
        end_line = defn.get("end_line", defn.get("line_end", 0))
        effective_sink = (
            end_line if end_line > line else line + 20
        )  # estimate if no end_line

        if rules is None or parser is None:
            sub_flow = None
        else:
            sub_flow = trace_taint_flow(
                file_path=file_path,
                function_name=callee_name,
                sink_line=effective_sink,
                check_id="",
                rules=rules,
                parser=parser,
            )

        action = "unknown"
        if sub_flow:
            if sub_flow.sanitizers:
                action = "sanitizes"
            elif sub_flow.path and any(s.kind == "parameter" for s in sub_flow.path):
                action = "propagates"
            else:
                action = "transforms"

        return CrossFileResult(
            action=action, file=file_path, line=line, sub_flow=sub_flow
        )

    except asyncio.TimeoutError:
        logger.warning("Cross-file resolution timed out for %s", callee_name)
        return CrossFileResult(action="unknown")
    except Exception as e:
        logger.warning("Cross-file resolution failed for %s: %s", callee_name, e)
        return CrossFileResult(action="unknown")
