import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "verify_release_tree.py"
SPEC = importlib.util.spec_from_file_location("verify_release_tree", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ReleaseTreeTests(unittest.TestCase):
    def test_current_index_has_no_forbidden_artifacts(self):
        self.assertEqual(MODULE.validate_entries(MODULE.tracked_entries(ROOT)), [])

    def test_rejects_crs_data_generated_code_and_vendor_copy(self):
        entries = [
            ("160000", MODULE.CRS_GITLINK),
            ("100644", "tests/eval_suite/sql-errors.data"),
            ("100644", "src/parser_rules_0001.c"),
            ("100644", "third_party/libinjection/libinjection_sqli.c"),
        ]
        errors = MODULE.validate_entries(entries)
        self.assertEqual(len(errors), 3)

    def test_rejects_checked_out_crs_tree_instead_of_gitlink(self):
        errors = MODULE.validate_entries([("100644", MODULE.CRS_GITLINK)])
        self.assertEqual(len(errors), 1)
        self.assertIn("must be a Git submodule", errors[0])

    def test_rejects_internal_markdown_and_historical_benchmark_files(self):
        entries = [
            ("160000", MODULE.CRS_GITLINK),
            ("100644", ".github/CODEOWNERS.md"),
            ("100644", "task_private_release_plan.md"),
            ("100644", "bench/iron_benchmark/iron_harness_v9.sh"),
            ("100644", "benchmark_results.json"),
        ]
        errors = MODULE.validate_entries(entries)
        self.assertEqual(len(errors), 4)

    def test_accepts_public_documentation_allowlist(self):
        entries = [("160000", MODULE.CRS_GITLINK)]
        entries.extend(("100644", path) for path in sorted(MODULE.ALLOWED_MARKDOWN))
        entries.append(("100644", ".github/CODEOWNERS"))
        entries.append(
            ("100644", "reports/benchmark_harness_v1/v0.4.0-rc.1/BENCHMARK_RESULTS.md")
        )
        self.assertEqual(MODULE.validate_entries(entries), [])

    def test_rejects_mutable_or_unversioned_report_markdown(self):
        entries = [
            ("160000", MODULE.CRS_GITLINK),
            ("100644", "reports/latest/BENCHMARK_RESULTS.md"),
            ("100644", "reports/benchmark_harness_v1/current/BENCHMARK_RESULTS.md"),
        ]
        errors = MODULE.validate_entries(entries)
        self.assertEqual(len(errors), 2)


if __name__ == "__main__":
    unittest.main()
