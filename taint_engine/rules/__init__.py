"""Rule loading, merging, and querying for taint analysis.

Rules are defined in JSON files (one per language). The loader merges
rules by file extension and provides a queryable TaintRuleSet.

JSON format (v2 — labeled):
  sources:      dict[name, list[label]]
  sinks:        dict[label, {call?, property?, accepts?}]
  sanitizers:   list[{name, removes, sets_state}]
  transformers: list[{name, sets_state}]
  guards:       list[str]
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
    sanitizers: MappingProxyType[str, list[str]]
    guards: frozenset[str]
    labeled_sinks: MappingProxyType[str, dict] | None = None
    sanitizer_labels: MappingProxyType[str, list[str]] | None = None
    sanitizer_states: MappingProxyType[str, str] | None = None
    transformers: MappingProxyType[str, str] | None = None


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
        """Look up a sanitizer by name, populating removes/sets_state."""
        rules = self._by_ext.get(ext)
        if not rules:
            return None
        key = callee.lower()

        match = self._find_sanitizer_key(rules, key)
        if match is None:
            return None

        removes = list(rules.sanitizer_labels.get(match, ["*"])) if rules.sanitizer_labels else ["*"]
        sets_state = rules.sanitizer_states.get(match, "sanitized") if rules.sanitizer_states else "sanitized"

        return SanitizerInfo(
            name=callee,
            line=0,
            cwe_categories=rules.sanitizers[match],
            conditional=False,
            verified=False,
            removes=removes,
            sets_state=sets_state,
        )

    def get_sanitizer_state(self, ext: str, callee: str) -> str | None:
        """Return the sets_state value for a sanitizer, or None."""
        rules = self._by_ext.get(ext)
        if not rules or not rules.sanitizer_states:
            return None
        key = callee.lower()
        match = self._find_sanitizer_key(rules, key)
        if match is None:
            return None
        return rules.sanitizer_states.get(match)

    def get_accepted_states(self, ext: str, label: str) -> list[str] | None:
        """Return accepted states for a sink label, or None."""
        rules = self._by_ext.get(ext)
        if not rules or not rules.labeled_sinks:
            return None
        sink_def = rules.labeled_sinks.get(label)
        if sink_def is None:
            return None
        return sink_def.get("accepts")

    def check_transformer(
        self, ext: str, callee: str,
    ) -> tuple[str, str] | None:
        """Look up a transformer. Returns (canonical_name, sets_state) or None."""
        rules = self._by_ext.get(ext)
        if not rules or not rules.transformers:
            return None
        key = callee.lower()
        if key in rules.transformers:
            state = rules.transformers[key]
            if "." in key:
                return (callee, state)
            # Bare suffix hit — resolve canonical dotted name if one exists
            for full_name in rules.transformers:
                if "." in full_name and full_name.rsplit(".", 1)[-1] == key:
                    return (full_name, state)
            return (callee, state)
        if "." in key:
            suffix = key.rsplit(".", 1)[-1]
            if suffix in rules.transformers:
                return (callee, rules.transformers[suffix])
        return None

    def is_guard(self, ext: str, callee: str) -> bool:
        rules = self._by_ext.get(ext)
        if not rules:
            return False
        return callee in rules.guards

    @staticmethod
    def _find_sanitizer_key(
        rules: LanguageRules, key: str,
    ) -> str | None:
        """Find matching sanitizer key (exact or suffix) in rules.sanitizers."""
        if key in rules.sanitizers:
            return key
        if "." in key:
            suffix = key.rsplit(".", 1)[-1]
            if suffix in rules.sanitizers:
                return suffix
        return None


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
                    "labeled_sinks": {},
                    "sanitizer_labels": {},
                    "sanitizer_states": {},
                    "transformers": {},
                }
            entry = acc[ext]

            # Sources: dict[name, list[label]] — flatten keys into sources set
            sources = rule.get("sources", {})
            if isinstance(sources, dict):
                entry["sources"].update(sources.keys())
            else:
                entry["sources"].update(sources)

            # Sinks: labeled dict[label, {call?, property?, accepts?}]
            sinks = rule.get("sinks", {})
            if _is_labeled_sinks(sinks):
                for label, sink_def in sinks.items():
                    calls = sink_def.get("call", [])
                    props = sink_def.get("property", [])
                    entry["call_sinks"].update(calls)
                    entry["property_sinks"].update(props)
                    if label not in entry["labeled_sinks"]:
                        entry["labeled_sinks"][label] = {
                            "call": list(calls),
                            "property": list(props),
                            "accepts": list(sink_def.get("accepts", [])),
                        }
                    else:
                        existing = entry["labeled_sinks"][label]
                        for c in calls:
                            if c not in existing["call"]:
                                existing["call"].append(c)
                        for p in props:
                            if p not in existing["property"]:
                                existing["property"].append(p)
                        for a in sink_def.get("accepts", []):
                            if a not in existing["accepts"]:
                                existing["accepts"].append(a)
            else:
                entry["call_sinks"].update(sinks.get("call", []))
                entry["property_sinks"].update(sinks.get("property", []))

            # Sanitizers: list[{name, removes, sets_state}]
            for san in rule.get("sanitizers", []):
                name = san["name"]
                key = name.lower()
                removes = san.get("removes", ["*"])
                sets_state = san.get("sets_state", "sanitized")

                if key not in entry["sanitizers"]:
                    entry["sanitizers"][key] = ["*"]
                entry["sanitizer_labels"][key] = list(removes)
                entry["sanitizer_states"][key] = sets_state

                if "." in key:
                    suffix = key.rsplit(".", 1)[-1]
                    if suffix not in entry["sanitizers"]:
                        entry["sanitizers"][suffix] = ["*"]
                        entry["sanitizer_labels"][suffix] = list(removes)
                        entry["sanitizer_states"][suffix] = sets_state

            # Transformers: list[{name, sets_state}]
            for txf in rule.get("transformers", []):
                name = txf["name"]
                key = name.lower()
                state = txf["sets_state"]
                entry["transformers"][key] = state
                if "." in key:
                    suffix = key.rsplit(".", 1)[-1]
                    if suffix not in entry["transformers"]:
                        entry["transformers"][suffix] = state

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
            labeled_sinks=MappingProxyType(entry["labeled_sinks"]) or None,
            sanitizer_labels=MappingProxyType(entry["sanitizer_labels"]) or None,
            sanitizer_states=MappingProxyType(entry["sanitizer_states"]) or None,
            transformers=MappingProxyType(entry["transformers"]) or None,
        )

    return TaintRuleSet(_by_ext=by_ext)


def _is_labeled_sinks(sinks: dict) -> bool:
    """Detect labeled sink format vs legacy flat format.

    Labeled: each value is a dict with optional call/property/accepts.
    Legacy:  keys are 'call' and/or 'property' mapping to lists.
    """
    if not sinks:
        return False
    for v in sinks.values():
        if isinstance(v, dict):
            return True
        return False
    return False
