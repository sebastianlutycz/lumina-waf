import base64
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/eval_suite"))
sys.path.insert(0, str(ROOT / "tools"))

from audit_crs_mechanisms import audit_rules, summarize  # noqa: E402
from ftw_input import normalize_encoded_input, request_body_class  # noqa: E402
from pl2_coverage_oracle import CoverageTracker  # noqa: E402


class Pl2CoverageOracleTest(unittest.TestCase):
    def test_encoded_request_preserves_binary_body(self):
        body = b"\xac\xed\x00\x05\xff"
        request = (
            b"POST /deserialize HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: 5\r\n\r\n"
            + body
        )
        normalized = normalize_encoded_input(
            {"encoded_request": base64.b64encode(request).decode("ascii")}
        )
        self.assertEqual(normalized["data"], body)
        self.assertEqual(normalized["method"], "POST")
        self.assertEqual(normalized["uri"], "/deserialize")
        self.assertEqual(request_body_class(normalized), "opaque")
        self.assertNotIn("encoded_request", normalized)
        self.assertIs(normalize_encoded_input(normalized), normalized)

    def test_tracker_keeps_rule_coverage_separate_from_test_parity(self):
        rows = [
            {
                "rule_id": 100,
                "phase": 2,
                "paranoia": 1,
                "direct_score_bearing": True,
                "chain_head_score_bearing": False,
                "mechanism": "C2_AOT_REGEX",
                "variables": ["ARGS"],
            },
            {
                "rule_id": 200,
                "phase": 2,
                "paranoia": 2,
                "direct_score_bearing": False,
                "chain_head_score_bearing": True,
                "mechanism": "C6_CHAIN",
                "variables": ["REQUEST_HEADERS"],
            },
            {
                "rule_id": 949110,
                "phase": 2,
                "paranoia": 1,
                "direct_score_bearing": False,
                "chain_head_score_bearing": False,
                "mechanism": "CONTROL_BLOCKING_EVAL",
                "variables": ["TX"],
            },
        ]
        tracker = CoverageTracker(rows)
        tracker.observe_reference_positive("a", [100], "json")
        tracker.observe_lumina_exact("a", [100], "json")
        tracker.observe_reference_positive("b", [200], "none")
        tracker.observe_negative("c", [100], [100])
        report = tracker.report({"complete_test_corpus": True})

        self.assertEqual(report["universe"]["testable_detection_rule_count"], 2)
        self.assertEqual(report["coverage"]["reference_positive"]["matched"], 2)
        self.assertEqual(report["coverage"]["lumina_exact_rule"]["matched"], 1)
        self.assertEqual(
            report["coverage"]["lumina_exact_rule"]["missed_rule_ids"], [200]
        )
        self.assertFalse(
            report["reference_contract"]["modsecurity_runtime_verified"]
        )
        self.assertEqual(
            report["observed_body_media"]["json"]["reference_rule_ids"], [100]
        )

    def test_tracker_reports_config_resolved_active_coverage_separately(self):
        rows = [
            {
                "rule_id": rule_id,
                "phase": 2,
                "paranoia": 1,
                "direct_score_bearing": True,
                "chain_head_score_bearing": False,
                "mechanism": "C2_AOT_REGEX",
                "variables": ["ARGS"],
            }
            for rule_id in (100, 200)
        ]
        tracker = CoverageTracker(rows, config_inactive_rule_ids={200, 999})
        tracker.observe_reference_positive("active", [100], "json")
        report = tracker.report({"complete_test_corpus": True})

        self.assertEqual(
            report["universe"]["config_resolved_active_rule_ids"], [100]
        )
        self.assertEqual(
            report["coverage"]["reference_positive"]["total"], 2
        )
        self.assertEqual(
            report["coverage"]["config_resolved_reference_positive"],
            {
                "matched": 1,
                "total": 1,
                "percent": 100.0,
                "uncovered_rule_ids": [],
            },
        )

    def test_supplemental_direct_coverage_remains_separate_from_ftw(self):
        rows = [
            {
                "rule_id": rule_id,
                "phase": 1,
                "paranoia": 1,
                "direct_score_bearing": True,
                "chain_head_score_bearing": False,
                "mechanism": "C4_STRUCTURAL",
                "variables": ["REQUEST_HEADERS"],
            }
            for rule_id in (100, 200)
        ]
        tracker = CoverageTracker(rows)
        tracker.observe_reference_positive("ftw", [100], "none")
        tracker.observe_lumina_exact("ftw", [100], "none")
        tracker.observe_supplemental_direct("direct", 200, True)
        report = tracker.report({"complete_test_corpus": True})

        self.assertEqual(
            report["coverage"]["reference_positive"]["matched"], 1
        )
        self.assertEqual(
            report["coverage"]["supplemental_direct_exact"]["matched"], 1
        )
        self.assertEqual(
            report["coverage"]["combined_internal_active_implementation"],
            {
                "matched": 2,
                "total": 2,
                "percent": 100.0,
                "uncovered_rule_ids": [],
            },
        )
        self.assertFalse(
            report["supplemental_direct_contract"]["publication_eligible"]
        )

    def test_pinned_pl2_universe_includes_score_bearing_chain_heads(self):
        rows = audit_rules(ROOT / "tests/eval_suite/coreruleset/rules", 2, ROOT / "src")
        summary = summarize(rows)
        tracker = CoverageTracker(rows)

        self.assertEqual(len({row.rule_id for row in rows}), 423)
        self.assertEqual(summary["chain_head_score_bearing_rules"], 44)
        self.assertEqual(summary["score_bearing_rules"], 245)
        self.assertEqual(len(tracker.rules), 245)


if __name__ == "__main__":
    unittest.main()
