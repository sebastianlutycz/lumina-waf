#!/usr/bin/env python3
"""Internal inbound PL2 rule-coverage accounting.

This module does not establish a ModSecurity runtime reference. It measures the
coverage of pinned OWASP CRS FTW expectations and the exact IDs observed from
LuminaWAF over the same fixtures.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


BODY_DERIVED_COLLECTIONS = {
    "ARGS",
    "ARGS_NAMES",
    "JSON",
    "MULTIPART_PART_HEADERS",
    "MULTIPART_STRICT_ERROR",
    "MULTIPART_UNMATCHED_BOUNDARY",
    "REQBODY_PROCESSOR",
    "REQUEST_BODY",
    "REQUEST_BODY_LENGTH",
    "XML",
}


def _field(row: Any, name: str, default: Any = None) -> Any:
    if isinstance(row, dict):
        return row.get(name, default)
    return getattr(row, name, default)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(paths: Iterable[Path], root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted((Path(item) for item in paths), key=lambda item: item.as_posix()):
        relative = path.resolve().relative_to(root.resolve()).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def is_testable_detection_rule(row: Any) -> bool:
    return bool(
        _field(row, "direct_score_bearing", False)
        or _field(row, "chain_head_score_bearing", False)
    )


def percent(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return 100.0 * numerator / denominator


class CoverageTracker:
    def __init__(
        self,
        audit_rows: Iterable[Any],
        config_inactive_rule_ids: Iterable[int] = (),
    ) -> None:
        rows = list(audit_rows)
        self.source_rule_ids = {int(_field(row, "rule_id")) for row in rows}
        self.rules = {
            int(_field(row, "rule_id")): row
            for row in rows
            if is_testable_detection_rule(row)
        }
        self.config_inactive_rule_ids = {
            int(rule_id) for rule_id in config_inactive_rule_ids
        } & set(self.rules)
        self.reference_positive: dict[int, set[str]] = defaultdict(set)
        self.lumina_exact: dict[int, set[str]] = defaultdict(set)
        self.reference_negative: dict[int, set[str]] = defaultdict(set)
        self.lumina_negative_pass: dict[int, set[str]] = defaultdict(set)
        self.reference_media: dict[str, dict[int, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.lumina_media: dict[str, dict[int, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        self.supplemental_direct_expected: dict[int, set[str]] = defaultdict(set)
        self.supplemental_direct_exact: dict[int, set[str]] = defaultdict(set)
        self.non_testable_expected_ids: set[int] = set()
        self.multi_expectation_tests: set[str] = set()

    def observe_reference_positive(
        self, test_ref: str, expected_ids: Iterable[int], body_class: str
    ) -> None:
        expected = {int(value) for value in expected_ids}
        if len(expected) > 1:
            self.multi_expectation_tests.add(test_ref)
        for rule_id in expected:
            if rule_id not in self.rules:
                self.non_testable_expected_ids.add(rule_id)
                continue
            self.reference_positive[rule_id].add(test_ref)
            self.reference_media[body_class][rule_id].add(test_ref)

    def observe_lumina_exact(
        self, test_ref: str, matched_expected_ids: Iterable[int], body_class: str
    ) -> None:
        for rule_id in {int(value) for value in matched_expected_ids}:
            if rule_id not in self.rules:
                continue
            self.lumina_exact[rule_id].add(test_ref)
            self.lumina_media[body_class][rule_id].add(test_ref)

    def observe_negative(
        self, test_ref: str, excluded_ids: Iterable[int], passed_ids: Iterable[int]
    ) -> None:
        for rule_id in {int(value) for value in excluded_ids}:
            if rule_id in self.rules:
                self.reference_negative[rule_id].add(test_ref)
        for rule_id in {int(value) for value in passed_ids}:
            if rule_id in self.rules:
                self.lumina_negative_pass[rule_id].add(test_ref)

    def observe_supplemental_direct(
        self, test_ref: str, expected_rule_id: int, exact_match: bool
    ) -> None:
        rule_id = int(expected_rule_id)
        if rule_id not in self.rules:
            self.non_testable_expected_ids.add(rule_id)
            return
        self.supplemental_direct_expected[rule_id].add(test_ref)
        if exact_match:
            self.supplemental_direct_exact[rule_id].add(test_ref)

    def report(self, provenance: dict[str, Any]) -> dict[str, Any]:
        universe_ids = set(self.rules)
        active_ids = universe_ids - self.config_inactive_rule_ids
        reference_ids = set(self.reference_positive)
        lumina_ids = set(self.lumina_exact)
        negative_ids = set(self.reference_negative)
        dual_ids = reference_ids & negative_ids
        supplemental_ids = set(self.supplemental_direct_expected)
        supplemental_exact_ids = set(self.supplemental_direct_exact)
        combined_internal_ids = (lumina_ids & reference_ids) | supplemental_exact_ids
        body_capable_ids = {
            rule_id
            for rule_id, row in self.rules.items()
            if set(_field(row, "variables", []) or []) & BODY_DERIVED_COLLECTIONS
        }
        observed_body_reference_ids = set().union(
            *(
                set(rows)
                for media, rows in self.reference_media.items()
                if media != "none"
            ),
            set(),
        )
        observed_body_lumina_ids = set().union(
            *(
                set(rows)
                for media, rows in self.lumina_media.items()
                if media != "none"
            ),
            set(),
        )
        observed_body_reference_ids &= body_capable_ids
        observed_body_lumina_ids &= body_capable_ids

        media_rows: dict[str, Any] = {}
        for media in sorted(set(self.reference_media) | set(self.lumina_media)):
            if media == "none":
                continue
            media_reference = set(self.reference_media[media]) & body_capable_ids
            media_lumina = set(self.lumina_media[media]) & body_capable_ids
            media_rows[media] = {
                "reference_rule_count": len(media_reference),
                "lumina_exact_rule_count": len(media_lumina),
                "lumina_exact_percent_of_reference": percent(
                    len(media_lumina & media_reference), len(media_reference)
                ),
                "reference_rule_ids": sorted(media_reference),
                "lumina_exact_rule_ids": sorted(media_lumina),
                "missed_rule_ids": sorted(media_reference - media_lumina),
            }

        rule_rows = []
        for rule_id in sorted(universe_ids):
            row = self.rules[rule_id]
            variables = sorted(_field(row, "variables", []) or [])
            rule_rows.append(
                {
                    "rule_id": rule_id,
                    "phase": _field(row, "phase"),
                    "paranoia": _field(row, "paranoia"),
                    "mechanism": _field(row, "mechanism"),
                    "variables": variables,
                    "body_capable": bool(set(variables) & BODY_DERIVED_COLLECTIONS),
                    "config_resolved_active": rule_id in active_ids,
                    "reference_positive_tests": len(self.reference_positive[rule_id]),
                    "lumina_exact_tests": len(self.lumina_exact[rule_id]),
                    "reference_negative_tests": len(self.reference_negative[rule_id]),
                    "lumina_negative_pass_tests": len(
                        self.lumina_negative_pass[rule_id]
                    ),
                    "supplemental_direct_tests": len(
                        self.supplemental_direct_expected[rule_id]
                    ),
                    "supplemental_direct_exact_tests": len(
                        self.supplemental_direct_exact[rule_id]
                    ),
                }
            )

        return {
            "schema": 1,
            "internal_only": True,
            "reference_contract": {
                "basis": "pinned-owasp-crs-ftw-expectations",
                "modsecurity_runtime_verified": False,
                "publication_eligible": False,
                "note": (
                    "Reference activations come from FTW expectations. They have not "
                    "yet been replayed and qualified against pinned ModSecurity."
                ),
            },
            "supplemental_direct_contract": {
                "basis": "direct-lumina-public-bundle-regressions",
                "modsecurity_runtime_verified": False,
                "publication_eligible": False,
                "note": (
                    "These cases prove Lumina implementation coverage for active "
                    "rules absent from the selected FTW positives. They do not "
                    "increase FTW reference coverage or comparator parity."
                ),
            },
            "provenance": provenance,
            "universe": {
                "definition": (
                    "active inbound phase 1/2 PL2 rules that directly add inbound "
                    "anomaly score, including chain heads whose members add the score"
                ),
                "source_inbound_rule_count": len(self.source_rule_ids),
                "testable_detection_rule_count": len(universe_ids),
                "testable_detection_rule_ids": sorted(universe_ids),
                "config_inactive_rule_count": len(self.config_inactive_rule_ids),
                "config_inactive_rule_ids": sorted(self.config_inactive_rule_ids),
                "config_resolved_active_rule_count": len(active_ids),
                "config_resolved_active_rule_ids": sorted(active_ids),
                "body_capable_rule_count": len(body_capable_ids),
                "body_capable_rule_ids": sorted(body_capable_ids),
            },
            "coverage": {
                "reference_positive": {
                    "matched": len(reference_ids),
                    "total": len(universe_ids),
                    "percent": percent(len(reference_ids), len(universe_ids)),
                    "uncovered_rule_ids": sorted(universe_ids - reference_ids),
                },
                "config_resolved_reference_positive": {
                    "matched": len(reference_ids & active_ids),
                    "total": len(active_ids),
                    "percent": percent(
                        len(reference_ids & active_ids), len(active_ids)
                    ),
                    "uncovered_rule_ids": sorted(active_ids - reference_ids),
                },
                "lumina_exact_rule": {
                    "matched": len(lumina_ids & reference_ids),
                    "total": len(reference_ids),
                    "percent": percent(
                        len(lumina_ids & reference_ids), len(reference_ids)
                    ),
                    "missed_rule_ids": sorted(reference_ids - lumina_ids),
                },
                "supplemental_direct_exact": {
                    "matched": len(supplemental_exact_ids & supplemental_ids),
                    "total": len(supplemental_ids),
                    "percent": percent(
                        len(supplemental_exact_ids & supplemental_ids),
                        len(supplemental_ids),
                    ),
                    "expected_rule_ids": sorted(supplemental_ids),
                    "missed_rule_ids": sorted(
                        supplemental_ids - supplemental_exact_ids
                    ),
                },
                "combined_internal_active_implementation": {
                    "matched": len(combined_internal_ids & active_ids),
                    "total": len(active_ids),
                    "percent": percent(
                        len(combined_internal_ids & active_ids), len(active_ids)
                    ),
                    "uncovered_rule_ids": sorted(
                        active_ids - combined_internal_ids
                    ),
                },
                "reference_negative": {
                    "matched": len(negative_ids),
                    "total": len(universe_ids),
                    "percent": percent(len(negative_ids), len(universe_ids)),
                    "uncovered_rule_ids": sorted(universe_ids - negative_ids),
                },
                "dual_sided": {
                    "matched": len(dual_ids),
                    "total": len(universe_ids),
                    "percent": percent(len(dual_ids), len(universe_ids)),
                    "uncovered_rule_ids": sorted(universe_ids - dual_ids),
                },
                "observed_body_reference": {
                    "matched": len(observed_body_reference_ids & body_capable_ids),
                    "total": len(body_capable_ids),
                    "percent": percent(
                        len(observed_body_reference_ids & body_capable_ids),
                        len(body_capable_ids),
                    ),
                    "uncovered_rule_ids": sorted(
                        body_capable_ids - observed_body_reference_ids
                    ),
                },
                "observed_body_lumina_exact": {
                    "matched": len(observed_body_lumina_ids),
                    "total": len(observed_body_reference_ids),
                    "percent": percent(
                        len(observed_body_lumina_ids),
                        len(observed_body_reference_ids),
                    ),
                    "missed_rule_ids": sorted(
                        observed_body_reference_ids - observed_body_lumina_ids
                    ),
                },
            },
            "observed_body_media": media_rows,
            "multi_expectation_test_count": len(self.multi_expectation_tests),
            "non_testable_expected_rule_ids": sorted(self.non_testable_expected_ids),
            "rules": rule_rows,
        }
