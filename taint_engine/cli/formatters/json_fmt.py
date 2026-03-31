"""JSON formatter for taint flows."""

from __future__ import annotations

import json
from typing import Optional

from ...models import TaintFlow


def format_json(flow: Optional[TaintFlow], *, file_path: str) -> str:
    """Format a taint flow as JSON."""
    data = {
        "file": file_path,
        "flows": [flow.to_dict()] if flow else [],
    }
    return json.dumps(data, indent=2)
