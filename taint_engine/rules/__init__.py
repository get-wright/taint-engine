"""Rule loading, merging, and querying for taint analysis.

Rules are defined in JSON files (one per language). The loader merges
rules by file extension and provides a queryable TaintRuleSet.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from ..models import SanitizerInfo


@dataclass(frozen=True)
class LanguageRules:
    """Merged rules for a single language (group of extensions)."""

    language: str
    sources: frozenset[str]
    call_sinks: frozenset[str]
    property_sinks: frozenset[str]
    sanitizers: MappingProxyType[
        str, list[str]
    ]  # lowercase name -> CWE list (read-only)
    guards: frozenset[str]


@dataclass(frozen=True)
class TaintRuleSet:
    """Merged rules queryable by file extension."""

    _by_ext: dict[str, LanguageRules]

    def for_extension(self, ext: str) -> LanguageRules | None:
        return self._by_ext.get(ext)

    def is_source(self, ext: str, dotted_name: str) -> bool:
        rules = self._by_ext.get(ext)
        if not rules:
            return False
        return dotted_name in rules.sources

    def is_call_sink(self, ext: str, callee: str) -> bool:
        rules = self._by_ext.get(ext)
        if not rules:
            return False
        return callee in rules.call_sinks

    def is_property_sink(self, ext: str, property_name: str) -> bool:
        rules = self._by_ext.get(ext)
        if not rules:
            return False
        return property_name in rules.property_sinks

    def check_sanitizer(self, ext: str, callee: str) -> SanitizerInfo | None:
        rules = self._by_ext.get(ext)
        if not rules:
            return None
        key = callee.lower()
        if key in rules.sanitizers:
            return SanitizerInfo(
                name=callee,
                line=0,
                cwe_categories=rules.sanitizers[key],
                conditional=False,
                verified=False,
            )
        # Try bare suffix: "html.escape" -> "escape"
        if "." in key:
            suffix = key.rsplit(".", 1)[-1]
            if suffix in rules.sanitizers:
                return SanitizerInfo(
                    name=callee,
                    line=0,
                    cwe_categories=rules.sanitizers[suffix],
                    conditional=False,
                    verified=False,
                )
        return None

    def is_guard(self, ext: str, callee: str) -> bool:
        rules = self._by_ext.get(ext)
        if not rules:
            return False
        return callee in rules.guards


def load_rules(path: str) -> TaintRuleSet:
    """Load rules from a directory of JSON files or a single JSON file."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rule path not found: {path}")

    if p.is_dir():
        files = sorted(p.glob("*.json"))
        if not files:
            return TaintRuleSet(_by_ext={})
        raw_rules = []
        for f in files:
            raw_rules.append(_load_single(f))
    else:
        raw_rules = [_load_single(p)]

    return _merge(raw_rules)


def _load_single(path: Path) -> dict:
    """Load and validate a single JSON rule file."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}") from e

    if "language" not in data:
        raise ValueError(f"Missing required field 'language' in {path}")
    if "extensions" not in data:
        raise ValueError(f"Missing required field 'extensions' in {path}")

    return data


def _merge(raw_rules: list[dict]) -> TaintRuleSet:
    """Merge raw rule dicts into a TaintRuleSet, unioning by extension."""
    acc: dict[str, dict] = {}
    for rule in raw_rules:
        lang = rule["language"]
        for ext in rule["extensions"]:
            if ext not in acc:
                acc[ext] = {
                    "language": lang,
                    "sources": set(),
                    "call_sinks": set(),
                    "property_sinks": set(),
                    "sanitizers": {},
                    "guards": set(),
                }
            entry = acc[ext]
            entry["sources"].update(rule.get("sources", []))

            sinks = rule.get("sinks", {})
            entry["call_sinks"].update(sinks.get("call", []))
            entry["property_sinks"].update(sinks.get("property", []))

            for san in rule.get("sanitizers", []):
                name = san["name"]
                neutralizes = san.get("neutralizes") or ["*"]
                key = name.lower()
                if key not in entry["sanitizers"]:
                    entry["sanitizers"][key] = list(neutralizes)
                else:
                    for cwe in neutralizes:
                        if cwe not in entry["sanitizers"][key]:
                            entry["sanitizers"][key].append(cwe)
                # Also index bare suffix
                if "." in key:
                    suffix = key.rsplit(".", 1)[-1]
                    if suffix not in entry["sanitizers"]:
                        entry["sanitizers"][suffix] = list(neutralizes)

            entry["guards"].update(rule.get("guards", []))

    by_ext: dict[str, LanguageRules] = {}
    for ext, entry in acc.items():
        by_ext[ext] = LanguageRules(
            language=entry["language"],
            sources=frozenset(entry["sources"]),
            call_sinks=frozenset(entry["call_sinks"]),
            property_sinks=frozenset(entry["property_sinks"]),
            sanitizers=MappingProxyType(entry["sanitizers"]),
            guards=frozenset(entry["guards"]),
        )

    return TaintRuleSet(_by_ext=by_ext)
