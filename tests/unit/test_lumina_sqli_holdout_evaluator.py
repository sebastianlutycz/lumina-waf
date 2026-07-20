#!/usr/bin/env python3
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
EVALUATOR_PATH = ROOT / "tools" / "evaluate_lumina_sqli_holdout.py"
SPEC = importlib.util.spec_from_file_location("lumina_sqli_holdout", EVALUATOR_PATH)
EVALUATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVALUATOR)


class LuminaSqliHoldoutEvaluatorTest(unittest.TestCase):
    def test_build_classifier_uses_verdict_only_abi(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pathlib.Path(tmp)
            (candidate / "api").mkdir()
            (candidate / "src").mkdir()
            (candidate / "api" / "lumina_sqli.h").write_text(
                "#include <stddef.h>\n#include <stdint.h>\n"
                "int lumina_sqli_detect(const uint8_t *data, size_t len);\n",
                encoding="ascii",
            )
            (candidate / "src" / "lumina_sqli.c").write_text(
                "#include \"lumina_sqli.h\"\n"
                "int lumina_sqli_detect(const uint8_t *data, size_t len) {\n"
                "    return data != 0 && len == 1 && data[0] == 0x41;\n}\n",
                encoding="ascii",
            )
            temporary, classify = EVALUATOR.build_classifier(candidate)
            try:
                self.assertEqual(classify(b"A"), 1)
                self.assertEqual(classify(b"B"), 0)
                self.assertEqual(classify(b""), 0)
            finally:
                temporary.cleanup()

    def test_summary_separates_false_negative_and_false_positive(self):
        rows = [
            {"id": "a", "input": b"a", "match": 1},
            {"id": "b", "input": b"b", "match": 0},
        ]
        observed = {
            b"a": 0,
            b"b": 1,
        }
        summary, details = EVALUATOR.evaluate_rows(rows, observed.__getitem__)
        self.assertEqual(summary["false_negative"], 1)
        self.assertEqual(summary["false_positive"], 1)
        self.assertFalse(summary["passed"])
        self.assertEqual(len(details), 2)

    def test_clean_summary_passes(self):
        rows = [
            {"id": "a", "input": b"a", "match": 1},
            {"id": "b", "input": b"b", "match": 0},
        ]
        observed = {b"a": 1, b"b": 0}
        summary, details = EVALUATOR.evaluate_rows(rows, observed.__getitem__)
        self.assertTrue(summary["passed"])
        self.assertEqual(details, [])

    def test_details_must_be_outside_checkout(self):
        with self.assertRaisesRegex(ValueError, "outside the reference checkout"):
            EVALUATOR.write_details(ROOT / "holdout-details.json", [])

    def test_candidate_marker_scan_is_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            candidate = pathlib.Path(tmp)
            source = candidate / "source.c"
            source.write_text("/* third_party/reference */", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "forbidden reference marker"):
                EVALUATOR.scan_candidate(candidate)

    def test_holdout_path_is_explicit(self):
        result = subprocess.run(
            [sys.executable, str(EVALUATOR_PATH), "candidate", "--details-output", "details.json"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--holdout", result.stderr)


if __name__ == "__main__":
    unittest.main()
