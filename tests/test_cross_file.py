import pytest
from unittest.mock import AsyncMock

from taint_engine.cross_file import resolve_cross_file, CrossFileResult


@pytest.fixture
def mock_gkg():
    client = AsyncMock()
    return client


async def test_resolve_finds_definition_and_traces(mock_gkg, tmp_path):
    helper_file = tmp_path / "helper.py"
    helper_file.write_text("def sanitize(x):\n    return html_escape(x)\n")
    mock_gkg.search_definitions.return_value = [
        {"name": "sanitize", "file": str(helper_file), "line": 1}
    ]
    result = await resolve_cross_file(callee_name="sanitize", gkg_client=mock_gkg, repo_path=str(tmp_path))
    assert result is not None
    assert result.action in ("propagates", "sanitizes", "transforms", "unknown")


async def test_resolve_respects_max_depth(mock_gkg):
    mock_gkg.search_definitions.return_value = []
    result = await resolve_cross_file(callee_name="deep_fn", gkg_client=mock_gkg, repo_path="/tmp", depth=3, max_depth=3)
    assert result is not None
    assert result.action == "unknown"
    mock_gkg.search_definitions.assert_not_called()


async def test_resolve_prevents_cycles(mock_gkg):
    result = await resolve_cross_file(callee_name="recursive_fn", gkg_client=mock_gkg, repo_path="/tmp", visited={"recursive_fn"})
    assert result is not None
    assert result.action == "unknown"


async def test_resolve_respects_budget(mock_gkg):
    from taint_engine.cross_file import _ResolutionCounter
    counter = _ResolutionCounter(value=8, max_total=8)
    result = await resolve_cross_file(callee_name="fn", gkg_client=mock_gkg, repo_path="/tmp", resolution_counter=counter)
    assert result.action == "unknown"


async def test_resolve_returns_unknown_when_gkg_finds_nothing(mock_gkg):
    mock_gkg.search_definitions.return_value = []
    result = await resolve_cross_file(callee_name="nonexistent", gkg_client=mock_gkg, repo_path="/tmp")
    assert result.action == "unknown"
