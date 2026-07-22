import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


manifest_module = load_module(
    "harness_manifest", ROOT / "bench/benchmark_harness/manifest.py"
)
e2e_module = load_module("harness_e2e", ROOT / "bench/benchmark_harness/e2e.py")
report_module = load_module("harness_report", ROOT / "bench/benchmark_harness/report.py")
run_module = load_module("harness_run", ROOT / "bench/benchmark_harness/run.py")
coraza_module = load_module(
    "harness_coraza_correctness",
    ROOT / "bench/benchmark_harness/coraza_correctness.py",
)
workload_codegen_module = load_module(
    "harness_workload_codegen",
    ROOT / "bench/benchmark_harness/generate_workload_header.py",
)
reference_config_module = load_module(
    "harness_reference_config",
    ROOT / "bench/benchmark_harness/generate_reference_config.py",
)
setup_module = load_module(
    "harness_crs_setup",
    ROOT / "bench/benchmark_harness/generate_crs_setup.py",
)


class BenchmarkHarnessTest(unittest.TestCase):
    def materialize_real_reference_config(self, directory: Path) -> Path:
        setup = directory / "crs-setup.conf"
        setup.write_text(
            setup_module.render(
                ROOT / "tests/eval_suite/coreruleset/crs-setup.conf.example"
            ),
            encoding="utf-8",
        )
        config = directory / "modsecurity_crs_pl2.conf"
        config.write_text(
            reference_config_module.render(
                ROOT / "tests/eval_suite/modsec_crs_pl2.conf",
                ROOT / "tests/eval_suite/coreruleset",
                setup,
            ),
            encoding="utf-8",
        )
        return config

    def test_repository_launcher_fails_fast_when_auto_bootstrap_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = os.environ.copy()
            environment.update({
                "LUMINA_BENCH_V1_CACHE": directory,
                "LUMINA_BENCH_V1_AUTO_BOOTSTRAP": "0",
            })
            process = subprocess.run(
                [str(ROOT / "bench/benchmark_harness/run.sh"), "--help"],
                cwd=ROOT, env=environment, capture_output=True, text=True,
            )
            self.assertEqual(process.returncode, 2)
            self.assertIn("Benchmark Harness v1 cache is incomplete", process.stderr)
            self.assertIn("bootstrap.sh", process.stderr)

    def test_repository_launcher_refreshes_runtime_before_run(self):
        launcher = (ROOT / "bench/benchmark_harness/run.sh").read_text(encoding="utf-8")
        bootstrap = (ROOT / "bench/benchmark_harness/bootstrap.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$SCRIPT_DIR/prepare_runtime.sh" --check-cache', launcher)
        self.assertIn('"$SCRIPT_DIR/materialize_runtime.sh"', launcher)
        self.assertIn(
            '"$SCRIPT_DIR/materialize_runtime.sh"\n'
            'LUMINA_BENCH_V1_CACHE="$CACHE" "$SCRIPT_DIR/prepare_runtime.sh"',
            launcher,
        )
        self.assertIn('source "$CACHE/env.sh"', launcher)
        self.assertIn('"$HERE/prepare_runtime.sh"', bootstrap)
        self.assertIn('"$HERE/materialize_runtime.sh"', bootstrap)
        self.assertIn("LUMINA_BENCH_V1_WRK", launcher + bootstrap + (
            ROOT / "bench/benchmark_harness/prepare_runtime.sh"
        ).read_text(encoding="utf-8"))

    def test_nginx_runtime_prefix_is_materialized_from_source(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "test_nginx"
            stale = prefix / "html/stale"
            stale.parent.mkdir(parents=True)
            stale.write_bytes(b"stale")
            e2e_module.prepare_prefix(prefix)
            self.assertFalse(stale.exists())
            self.assertEqual((prefix / "html/about").read_bytes(), b"OK")
            workload = json.loads(
                (ROOT / "bench/benchmark_harness/workloads/requests.json").read_text(
                    encoding="utf-8"
                )
            )
            for request in workload["requests"]:
                target = prefix / "html" / request["path"].lstrip("/")
                self.assertEqual(target.read_bytes(), b"OK")
            for relative in ("logs", "tmp/client_body", "tmp/proxy", "html"):
                self.assertTrue((prefix / relative).is_dir())

    def test_rendered_nginx_config_has_no_internal_redirect_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.conf"
            source.write_text(
                "worker_processes 1;\n"
                "pid /tmp/source.pid;\n"
                "events {}\n"
                "http { server { listen 8080; location / { "
                "try_files $uri =404; } } }\n",
                encoding="utf-8",
            )
            output = root / "rendered.conf"
            adapter = e2e_module.Adapter("baseline", "baseline", source)
            with mock.patch.object(e2e_module, "PREFIX", root / "runtime"):
                e2e_module.render_config(adapter, output, 19090, 1)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("try_files $uri =404;", rendered)
            self.assertNotIn("/about", rendered)

    def test_reference_config_rewrites_host_specific_crs_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crs = root / "crs"
            (crs / "rules").mkdir(parents=True)
            (crs / "crs-setup.conf").write_text("setup\n", encoding="utf-8")
            rule = crs / "rules/REQUEST-901.conf"
            rule.write_text("rule\n", encoding="utf-8")
            template = root / "template.conf"
            template.write_text(
                "SecRuleEngine On\n"
                "Include /old/checkout/tests/eval_suite/coreruleset/crs-setup.conf\n"
                "Include /old/checkout/tests/eval_suite/coreruleset/rules/REQUEST-901.conf\n",
                encoding="utf-8",
            )
            rendered = reference_config_module.render(template, crs)
            self.assertIn(f"Include {(crs / 'crs-setup.conf').resolve()}", rendered)
            self.assertIn(f"Include {rule.resolve()}", rendered)
            self.assertNotIn("/old/checkout", rendered)

    def test_reference_config_renders_repository_relative_includes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crs = root / "crs"
            crs.mkdir()
            setup = crs / "crs-setup.conf"
            setup.write_text("setup\n", encoding="utf-8")
            template = root / "template.conf"
            template.write_text(
                "SecRuleEngine On\nInclude coreruleset/crs-setup.conf\n",
                encoding="utf-8",
            )
            rendered = reference_config_module.render(template, crs)
            self.assertIn(f"Include {setup.resolve()}", rendered)

    def test_crs_setup_is_materialized_from_downloaded_example(self):
        rendered = setup_module.render(
            ROOT / "tests/eval_suite/coreruleset/crs-setup.conf.example"
        )
        self.assertIn("setvar:tx.blocking_paranoia_level=2", rendered)
        self.assertIn("setvar:tx.detection_paranoia_level=2", rendered)
        self.assertIn('SecDefaultAction "phase:1,nolog,pass"', rendered)

    def test_overhead_adapter_set_has_balanced_three_layers(self):
        with mock.patch.dict("os.environ", {
            "LUMINA_BENCH_V1_BASELINE_NGINX_CONFIG": "/tmp/e0.conf",
            "LUMINA_BENCH_V1_LUMINA_OFF_NGINX_CONFIG": "/tmp/e1.conf",
            "LUMINA_BENCH_V1_LUMINA_NGINX_CONFIG": "/tmp/e2.conf",
        }):
            values = e2e_module.adapters(False, "overhead")
        self.assertEqual(
            [item.name for item in values],
            ["baseline", "luminawaf-loaded-off", "luminawaf"],
        )
        self.assertEqual(
            [item.name for item in e2e_module.rotated_order(values, 1)],
            ["luminawaf-loaded-off", "luminawaf", "baseline"],
        )

    def test_lumina_off_and_on_configs_share_normalized_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            off = Path(directory) / "off.conf"
            on = Path(directory) / "on.conf"
            off.write_text(
                "pid /tmp/off.pid;\nserver { listen 19090; lumina_waf off; }\n",
                encoding="utf-8",
            )
            on.write_text(
                "pid /tmp/on.pid;\nserver { listen 19091; lumina_waf on; }\n",
                encoding="utf-8",
            )
            self.assertEqual(
                e2e_module.normalized_config_sha256(off),
                e2e_module.normalized_config_sha256(on),
            )

    def test_overhead_pairing_rejects_config_mismatch(self):
        results = []
        for engine, cpu in (
            ("baseline", 100.0), ("luminawaf-loaded-off", 110.0),
            ("luminawaf", 260.0),
        ):
            results.append({
                "engine": engine, "repetition": 0, "connections": 10,
                "round_id": "overhead-r00-c10", "workload_sha256": "workload",
                "normalized_config_sha256": "lumina" if engine != "baseline" else "base",
                "server_cpu_ns_per_request": cpu, "valid": True,
            })
        rows, errors = report_module.overhead_paired_rows({
            "canonical_requested": False, "results": results,
        })
        self.assertFalse(errors)
        self.assertEqual(
            next(row for row in rows if row["metric"] == "module_hook")["value_ns"], 10.0
        )
        self.assertEqual(
            next(row for row in rows if row["metric"] == "adapter_plus_pl2")["value_ns"],
            150.0,
        )
        results[-1]["normalized_config_sha256"] = "different"
        rows, errors = report_module.overhead_paired_rows({"results": results})
        self.assertFalse(rows)
        self.assertTrue(any("config identity" in error for error in errors))

    def test_generated_direct_workload_uses_all_six_allow_requests(self):
        workload = ROOT / "bench/benchmark_harness/workloads/requests.json"
        rendered = workload_codegen_module.render(workload)
        self.assertEqual(rendered.count("inline constexpr Header kHeaders"), 6)
        self.assertIn("allow_static_asset", rendered)
        self.assertIn("kWorkloadSha256", rendered)

    def test_real_crs_manifest_passes_strict_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            payload = manifest_module.build_manifest(
                ROOT / "tests/eval_suite/coreruleset",
                self.materialize_real_reference_config(Path(directory)),
                True,
            )
        self.assertTrue(payload["canonical"])
        self.assertEqual(payload["crs"]["policy"]["blocking_paranoia_level"], 2)
        self.assertEqual(payload["crs"]["policy"]["detection_paranoia_level"], 2)
        self.assertEqual(payload["crs"]["policy"]["inbound_anomaly_score_threshold"], 5)
        self.assertGreater(payload["crs"]["inbound_pl2_rule_count"], 0)
        self.assertIn(911100, payload["crs"]["inbound_pl2_rule_ids"])
        self.assertGreater(payload["lumina"]["generated_rule_count"], 0)

    def test_strict_manifest_rejects_untracked_crs_input(self):
        original_git = manifest_module.git

        def dirty_git(path: Path, *args: str):
            if args == ("status", "--porcelain=v1", "--untracked-files=all"):
                return "?? rules/local-override.conf"
            return original_git(path, *args)

        with tempfile.TemporaryDirectory() as directory:
            config = self.materialize_real_reference_config(Path(directory))
            with mock.patch.object(manifest_module, "git", side_effect=dirty_git):
                with self.assertRaisesRegex(ValueError, "untracked entries"):
                    manifest_module.build_manifest(
                        ROOT / "tests/eval_suite/coreruleset", config, True
                    )

    def test_wrk2_parser_preserves_p99_9_and_validity(self):
        raw = """
 50.000%  843.00us
 90.000%    2.91ms
 99.000%    4.38ms
 99.900%    5.25ms
 100.000%    7.00ms
  100001 requests in 10.00s
Requests/sec: 10000.10
"""
        parsed = e2e_module.parse_wrk(raw, requested_rate=10_000, min_samples=100_000)
        self.assertTrue(parsed["valid"])
        self.assertEqual(parsed["latency_us"]["p99_9"], 5250.0)
        self.assertEqual(parsed["latency_us"]["max"], 7000.0)
        self.assertEqual(parsed["accepted_requests"], 100001)
        self.assertEqual(parsed["socket_errors"], 0)
        self.assertEqual(parsed["socket_error_breakdown"], {})

    def test_wrk_parser_rejects_transport_errors(self):
        raw = """
  100001 requests in 10.00s
Requests/sec: 10000.10
  Socket errors: connect 1, read 2, write 3, timeout 4
"""
        parsed = e2e_module.parse_wrk(raw, requested_rate=None, min_samples=0)
        self.assertFalse(parsed["valid"])
        self.assertEqual(parsed["socket_errors"], 10)
        self.assertEqual(
            parsed["socket_error_breakdown"],
            {"connect": 1, "read": 2, "write": 3, "timeout": 4},
        )
        self.assertIn("socket errors=10", parsed["invalid_reasons"])

    def test_wrk_parser_rejects_malformed_socket_error_line(self):
        raw = """
  100001 requests in 10.00s
Requests/sec: 10000.10
  Socket errors: timeout unknown
"""
        parsed = e2e_module.parse_wrk(raw, requested_rate=None, min_samples=0)
        self.assertFalse(parsed["valid"])
        self.assertIn("unparsed socket error counters", parsed["invalid_reasons"])

    def test_canonical_saturation_accepts_overload_beyond_stable_point(self):
        results = [
            {
                "engine": "luminawaf", "connections": 50, "repetition": index,
                "raw": f"clean-{index}.txt", "valid": True, "invalid_reasons": [],
            }
            for index in range(5)
        ] + [
            {
                "engine": "luminawaf", "connections": 200, "repetition": index,
                "raw": f"overload-{index}.txt", "valid": False,
                "invalid_reasons": ["socket errors=3"],
            }
            for index in range(5)
        ]
        validity = e2e_module.evaluate_measurement_validity(
            mode="saturation", canonical=True, adapter_set="all",
            results=results,
            stability=[
                {"engine": "luminawaf", "connections": 50, "stable": True},
                {"engine": "luminawaf", "connections": 200, "stable": False},
            ],
            identity_errors=[], engine_names=["luminawaf"], expected_results=10,
        )
        self.assertTrue(validity["valid"])
        self.assertTrue(validity["coverage_valid"])
        self.assertEqual(len(validity["overload_invalid_legs"]), 5)
        self.assertEqual(validity["infrastructure_invalid_legs"], [])

    def test_canonical_saturation_rejects_infrastructure_failure(self):
        results = [
            {
                "engine": "luminawaf", "connections": 50, "repetition": index,
                "raw": f"clean-{index}.txt", "valid": True, "invalid_reasons": [],
            }
            for index in range(5)
        ] + [{
            "engine": "luminawaf", "connections": 200, "repetition": 0,
            "raw": "broken.txt", "valid": False,
            "invalid_reasons": ["load generator exit=2"],
        }]
        validity = e2e_module.evaluate_measurement_validity(
            mode="saturation", canonical=True, adapter_set="all",
            results=results,
            stability=[{"engine": "luminawaf", "connections": 50, "stable": True}],
            identity_errors=[], engine_names=["luminawaf"], expected_results=6,
        )
        self.assertFalse(validity["valid"])
        self.assertEqual(len(validity["infrastructure_invalid_legs"]), 1)

    def test_canonical_saturation_mixed_failure_is_infrastructure_failure(self):
        results = [
            {
                "engine": "luminawaf", "connections": 50, "repetition": index,
                "raw": f"clean-{index}.txt", "valid": True, "invalid_reasons": [],
            }
            for index in range(5)
        ] + [{
            "engine": "luminawaf", "connections": 200, "repetition": 0,
            "raw": "mixed-failure.txt", "valid": False,
            "invalid_reasons": ["socket errors=3", "load generator exit=2"],
        }]
        validity = e2e_module.evaluate_measurement_validity(
            mode="saturation", canonical=True, adapter_set="all",
            results=results,
            stability=[{"engine": "luminawaf", "connections": 50, "stable": True}],
            identity_errors=[], engine_names=["luminawaf"], expected_results=6,
        )
        self.assertFalse(validity["valid"])
        self.assertEqual(validity["overload_invalid_legs"], [])
        self.assertEqual(len(validity["infrastructure_invalid_legs"]), 1)

    def test_canonical_saturation_rejects_incomplete_sweep(self):
        results = [{
            "engine": "luminawaf", "connections": 50, "repetition": index,
            "raw": f"clean-{index}.txt", "valid": True, "invalid_reasons": [],
        } for index in range(5)]
        validity = e2e_module.evaluate_measurement_validity(
            mode="saturation", canonical=True, adapter_set="all",
            results=results,
            stability=[{"engine": "luminawaf", "connections": 50, "stable": True}],
            identity_errors=[], engine_names=["luminawaf"], expected_results=10,
        )
        self.assertFalse(validity["valid"])
        self.assertFalse(validity["coverage_valid"])

    def test_canonical_fixed_rate_rejects_transport_error(self):
        results = [{
            "engine": "luminawaf", "connections": 10, "repetition": index,
            "raw": f"fixed-{index}.txt", "valid": index != 4,
            "invalid_reasons": [] if index != 4 else ["socket errors=1"],
        } for index in range(5)]
        validity = e2e_module.evaluate_measurement_validity(
            mode="fixed", canonical=True, adapter_set="all",
            results=results,
            stability=[{"engine": "luminawaf", "connections": 10, "stable": True}],
            identity_errors=[], engine_names=["luminawaf"], expected_results=5,
        )
        self.assertFalse(validity["valid"])

    def test_canonical_overhead_saturation_rejects_any_invalid_leg(self):
        results = [{
            "engine": "luminawaf", "connections": 100, "repetition": index,
            "raw": f"overhead-{index}.txt", "valid": index != 4,
            "invalid_reasons": [] if index != 4 else ["socket errors=1"],
        } for index in range(5)]
        validity = e2e_module.evaluate_measurement_validity(
            mode="saturation", canonical=True, adapter_set="overhead",
            results=results,
            stability=[{"engine": "luminawaf", "connections": 100, "stable": True}],
            identity_errors=[], engine_names=["luminawaf"], expected_results=5,
        )
        self.assertFalse(validity["valid"])

    def test_manifest_proves_coraza_and_modsecurity_include_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.materialize_real_reference_config(Path(directory))
            payload = manifest_module.build_manifest(
                ROOT / "tests/eval_suite/coreruleset", config, True,
                coraza_config=config, require_coraza=True,
            )
        self.assertEqual(
            payload["comparators"]["coraza"]["ordered_include_identity"],
            payload["comparators"]["modsecurity"]["ordered_include_identity"],
        )
        self.assertEqual(payload["comparators"]["coraza"]["external_rule_overrides"], [])

    def test_allow_workload_generates_multi_request_lua(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "workload.lua"
            count = e2e_module.write_wrk_script(
                ROOT / "bench/benchmark_harness/workloads/requests.json", output
            )
            self.assertGreaterEqual(count, 5)
            rendered = output.read_text(encoding="utf-8")
            self.assertIn("wrk.format", rendered)
            self.assertIn("body=nil", rendered)
            self.assertNotIn('body=""', rendered)

    def test_allow_workload_requires_explicit_host_header(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workload = root / "requests.json"
            workload.write_text(json.dumps({
                "requests": [{
                    "id": "missing-host", "class": "allow", "method": "GET",
                    "path": "/", "headers": [], "body": "",
                }],
            }), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "exactly one Host header"):
                e2e_module.write_wrk_script(workload, root / "workload.lua")

    def test_wrk_command_does_not_inject_headers_outside_the_workload(self):
        with mock.patch("subprocess.Popen") as popen, mock.patch.object(
            e2e_module, "pin_load_generator_threads", return_value=[]
        ):
            process = popen.return_value
            process.communicate.return_value = ("", "")
            process.returncode = 0
            result = e2e_module.run_wrk(
                Path("/tmp/wrk"), "2", 19090, "1s", 1, 10, 100,
                Path("/tmp/workload.lua"),
            )
        command = popen.call_args.args[0]
        self.assertNotIn("-H", command)
        self.assertEqual(command.count("/tmp/wrk"), 1)
        self.assertEqual(result.returncode, 0)

    def test_task_affinity_binds_one_task_per_cpu_and_verifies_it(self):
        with mock.patch("os.sched_setaffinity") as set_affinity, mock.patch(
            "os.sched_getaffinity", side_effect=({4}, {5})
        ):
            mapping = e2e_module.bind_tasks_to_cpus(
                [202, 101], [4, 5], "nginx-worker"
            )
        self.assertEqual(
            set_affinity.call_args_list,
            [mock.call(101, {4}), mock.call(202, {5})],
        )
        self.assertEqual(
            mapping,
            [
                {"task_id": 101, "cpu": 4, "role": "nginx-worker"},
                {"task_id": 202, "cpu": 5, "role": "nginx-worker"},
            ],
        )

    def test_task_affinity_rejects_shared_cpu_mapping(self):
        with self.assertRaisesRegex(RuntimeError, "do not match allocated CPUs"):
            e2e_module.bind_tasks_to_cpus([101, 202], [4], "nginx-worker")

    def test_direct_comparators_check_intervention_after_every_phase(self):
        source = (ROOT / "bench/benchmark_harness/lumina_benchmark_harness.cpp").read_text(
            encoding="utf-8"
        )
        modsecurity = source.split("class ModSecurityEngine", 1)[1].split(
            "class CorazaEngine", 1
        )[0]
        coraza = source.split("class CorazaEngine", 1)[1].split(
            "void verify_or_skip", 1
        )[0]
        for implementation in (modsecurity, coraza):
            cursor = 0
            for token in (
                "process_connection" if implementation is coraza else "processConnection",
                "intervention_blocked",
                "process_uri" if implementation is coraza else "processURI",
                "intervention_blocked",
                "add_header" if implementation is coraza else "addRequestHeader",
                "process_headers" if implementation is coraza else "processRequestHeaders",
                "intervention_blocked",
                "process_body" if implementation is coraza else "processRequestBody",
                "intervention_blocked",
            ):
                cursor = implementation.find(token, cursor)
                self.assertNotEqual(cursor, -1, token)
                cursor += len(token)

    def test_coraza_ftw_summary_rejects_outcome_overrides(self):
        summary = coraza_module.normalize_ftw(
            {"run": 4, "success": ["1", "2", "3"], "failed": ["4"],
             "ignored": ["5"], "forced-pass": [], "forced-fail": []},
            "manifest",
        )
        self.assertEqual(summary["overall_parity"], 75.0)
        self.assertEqual(summary["outcome_overrides"], ["5"])

    def test_coraza_ftw_summary_excludes_selection_skips_from_denominator(self):
        summary = coraza_module.normalize_ftw(
            {"run": 100, "success": [str(value) for value in range(90)],
             "failed": ["failure"], "skipped": [str(value) for value in range(9)],
             "ignored": [], "forced-pass": [], "forced-fail": []},
            "manifest",
        )
        self.assertEqual(summary["tests"], 91)
        self.assertEqual(summary["selection_skipped"], 9)
        self.assertAlmostEqual(summary["overall_parity"], 100.0 * 90.0 / 91.0)

    def test_wrk2_parser_rejects_insufficient_tail(self):
        raw = """
 50.000%  1.00ms
 90.000%  2.00ms
 99.000%  3.00ms
 99.900%  4.00ms
  99999 requests in 10.00s
Requests/sec: 9999.90
"""
        parsed = e2e_module.parse_wrk(raw, requested_rate=10_000, min_samples=100_000)
        self.assertFalse(parsed["valid"])
        self.assertTrue(any("accepted samples" in reason for reason in parsed["invalid_reasons"]))

    def test_report_is_derived_from_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            result = Path(directory)
            manifest = manifest_module.build_manifest(
                ROOT / "tests/eval_suite/coreruleset",
                self.materialize_real_reference_config(result),
                True,
            )
            (result / "crs_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
            (result / "run_manifest.json").write_text(
                json.dumps({"mode": "smoke", "canonical": False,
                            "validity_reason": "test",
                            "scaling_qualification": {
                                "requested": True, "valid": True,
                            },
                            "phases": {"scaling": "passed"}}), encoding="utf-8"
            )
            (result / "environment.json").write_text(
                json.dumps({
                    "host_profile": "shared-loaded-homelab",
                    "host_note": "Background services remained active.",
                    "kernel_isolated_cpus": "",
                    "benchmark_cpu_sets": {"server": "1,3", "client": "0,2", "micro": "1"},
                    "governor": "performance", "loadavg": "2.00 2.50 3.00 1/100 1",
                    "pressure": {"cpu": "some avg10=1.00"}, "process_count": "100",
                }), encoding="utf-8",
            )
            (result / "environment_end.json").write_text(
                json.dumps({
                    "loadavg": "3.00 2.50 2.00 1/110 2",
                    "pressure": {"cpu": "some avg10=2.00"}, "process_count": "110",
                }), encoding="utf-8",
            )
            (result / "correctness_lumina.log").write_text(
                "elapsed: 1.0s tests=3986\ntransport_skipped=22\n"
                "positive(block) : 98.33% (3117/3170)\n"
                "positive(exact) : 99.72% (3161/3170)\n"
                "negative(excl) : 99.88% (815/816)\n"
                "timeouts=0 exceptions=0\nOVERALL PARITY : 99.75%\n",
                encoding="utf-8",
            )
            (result / "correctness_lumina.json").write_text(
                json.dumps({
                    "oracle": "test oracle", "tests": 3986, "overall_parity": 99.75,
                    "metrics": {
                        "positive_block": {"matched": 3117, "total": 3170, "percent": 98.33},
                        "positive_exact": {"matched": 3161, "total": 3170, "percent": 99.72},
                        "negative_exclusion": {"matched": 815, "total": 816, "percent": 99.88},
                    },
                    "skips": {"transport": 22, "paranoia_level": 0, "configuration": 0},
                    "timeouts": 0, "exceptions": 0, "failure_count": 10,
                }),
                encoding="utf-8",
            )
            (result / "micro.log").write_text("raw benchmark output\n", encoding="utf-8")
            (result / "correctness_coraza.json").write_text(
                json.dumps({"tests": 4009, "overall_parity": 99.825,
                            "transport_skipped": 0, "failed": 7,
                            "timeouts": 0, "exceptions": 0,
                            "outcome_overrides": []}),
                encoding="utf-8",
            )
            scaling = result / "e2e_scaling"
            scaling.mkdir()
            (scaling / "results.json").write_text(
                json.dumps({
                    "valid": True,
                    "rows": [{
                        "engine": "luminawaf", "table": "crs", "workers": 2,
                        "rps": 1900.0, "speedup": 1.9,
                        "scaling_efficiency_percent": 95.0,
                        "rps_per_worker": 950.0,
                        "server_cpu_ns_per_request": 110000.0,
                        "connections": 100,
                        "client_cpu_utilization_percent": 61.0,
                        "client_cpu_utilization_max_percent": 64.0,
                        "runs": 5, "rps_cv_percent": 1.2, "qualified": True,
                    }],
                }),
                encoding="utf-8",
            )
            rendered = report_module.render(result)
            self.assertIn("NON-CANONICAL", rendered)
            self.assertIn(manifest["manifest_sha256"], rendered)
            self.assertIn("Full CRS PL2 Correctness Gates", rendered)
            self.assertIn("99.75%", rendered)
            self.assertIn("HTTP verdict (rule IDs unavailable)", rendered)
            self.assertIn("98.33% (3117/3170)", rendered)
            self.assertIn("Generated Lumina execution units", rendered)
            self.assertIn("Raw Google Benchmark Output", rendered)
            self.assertIn("raw benchmark output", rendered)
            self.assertIn("Host State Annotation", rendered)
            self.assertIn("(../../../methodology/README.md)", rendered)
            self.assertIn("shared-loaded-homelab", rendered)
            self.assertIn("Background services remained active.", rendered)
            self.assertIn("A host annotation documents contention", rendered)
            self.assertIn("Multi-Worker Scaling", rendered)
            self.assertIn("95.00%", rendered)

    def test_micro_qualification_requires_raw_repetitions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "micro.json"
            benchmarks = []
            for workload in ("Allow", "Attack"):
                run_name = f"FullTransaction/LuminaWAF/{workload}/repeats:10"
                benchmarks.extend({"run_name": run_name, "cpu_time": 10.0} for _ in range(10))
                benchmarks.extend(
                    {"run_name": run_name, "aggregate_name": aggregate, "cpu_time": 10.0}
                    for aggregate in ("mean", "median", "stddev", "cv")
                )
            path.write_text(json.dumps({"benchmarks": benchmarks}), encoding="utf-8")
            result = run_module.validate_micro_artifacts([path], ["LuminaWAF"], 1, 10)
            self.assertTrue(result["valid"])
            aggregate_only = [item for item in benchmarks if item.get("aggregate_name")]
            path.write_text(json.dumps({"benchmarks": aggregate_only}), encoding="utf-8")
            result = run_module.validate_micro_artifacts([path], ["LuminaWAF"], 1, 10)
            self.assertFalse(result["valid"])
            self.assertTrue(any("raw repetitions=0" in error for error in result["errors"]))

    def test_luminawaf_must_not_contain_legacy_classifier_symbols(self):
        clean = run_module.symbol_isolation_evidence(
            "Symbol table '.dynsym' contains 10 entries",
            "Relocation section '.rela.dyn'",
            "0x0000000000000001 (NEEDED) Shared library: [libc.so.6]",
        )
        self.assertTrue(clean["valid"])
        self.assertEqual(clean["dt_needed"], ["libc.so.6"])

        exported = run_module.symbol_isolation_evidence(
            "42: 000000000005f800 FUNC GLOBAL DEFAULT libinjection_sqli", "", ""
        )
        self.assertFalse(exported["valid"])
        self.assertEqual(exported["legacy_libinjection_symbols"], ["libinjection_sqli"])

        relocated = run_module.symbol_isolation_evidence(
            "", "R_X86_64_JUMP_SLOT libinjection_sqli@Base + 0", ""
        )
        self.assertFalse(relocated["valid"])
        self.assertEqual(
            relocated["legacy_libinjection_relocations"], ["libinjection_sqli"]
        )

        linked = run_module.symbol_isolation_evidence(
            "", "", "0x0000000000000001 (NEEDED) Shared library: [libpcre2-8.so.0]"
        )
        self.assertFalse(linked["valid"])
        self.assertEqual(linked["forbidden_dt_needed"], ["libpcre2-8.so.0"])

    def test_fixed_rate_qualification_requires_stable_rps(self):
        results = []
        for index, rate in enumerate((1000.0, 1001.0, 999.0, 1000.5, 999.5)):
            results.append({
                "engine": "luminawaf", "table": "crs", "valid": True,
                "accepted_requests": 100_000, "requests_per_second": rate,
                "latency_us": {"p50": 10.0, "p90": 20.0, "p99": 30.0, "p99_9": 40.0},
                "repetition": index,
            })
        rows = report_module.fixed_rows({
            "canonical_requested": True, "requested_rate": 1000, "results": results,
        })
        self.assertTrue(rows[0]["qualified"])
        results[-1]["requests_per_second"] = 1500.0
        rows = report_module.fixed_rows({
            "canonical_requested": True, "requested_rate": 1000, "results": results,
        })
        self.assertFalse(rows[0]["qualified"])

    def test_sampling_plan_uses_slowest_stable_engine(self):
        saturation = {
            "results": [
                {"engine": "luminawaf"}, {"engine": "modsecurity"},
                {"engine": "coraza"},
            ],
            "stability": [
                {"engine": "luminawaf", "sustainable": True, "median_rps": 2500.0},
                {"engine": "modsecurity", "sustainable": True, "median_rps": 300.0},
                {"engine": "coraza", "sustainable": True, "median_rps": 170.0},
            ],
        }
        plan = run_module.derive_sampling_plan(
            saturation, target_samples=100_000, load_fraction=0.60
        )
        self.assertEqual(plan["limiting_engine"], "coraza")
        self.assertEqual(plan["fixed_rate"], 102)
        self.assertGreaterEqual(plan["projected_accepted_at_qualification_floor"], 100_000)

    def test_sampling_plan_rejects_unsafe_overrides(self):
        saturation = {
            "results": [{"engine": "coraza"}],
            "stability": [
                {"engine": "coraza", "sustainable": True, "median_rps": 100.0}
            ],
        }
        with self.assertRaises(RuntimeError):
            run_module.derive_sampling_plan(
                saturation, target_samples=100_000, load_fraction=0.60,
                requested_rate=61,
            )
        with self.assertRaises(RuntimeError):
            run_module.derive_sampling_plan(
                saturation, target_samples=100_000, load_fraction=0.60,
                requested_duration="10s",
            )
        with self.assertRaises(RuntimeError):
            run_module.derive_sampling_plan(
                saturation, target_samples=100_000, load_fraction=0.61,
            )

    def test_scaling_plan_assigns_disjoint_cpu_prefixes(self):
        plan = run_module.derive_scaling_plan("4-11", "12-15")
        self.assertEqual(
            plan["points"],
            [
                {"workers": 1, "server_cpu": "4", "client_cpu": "12,13,14,15", "client_threads": 4},
                {"workers": 2, "server_cpu": "4,5", "client_cpu": "12,13,14,15", "client_threads": 4},
                {"workers": 4, "server_cpu": "4,5,6,7", "client_cpu": "12,13,14,15", "client_threads": 4},
                {"workers": 8, "server_cpu": "4,5,6,7,8,9,10,11", "client_cpu": "12,13,14,15", "client_threads": 4},
            ],
        )
        with self.assertRaises(RuntimeError):
            run_module.derive_scaling_plan("4-7", "7-8", (1, 2, 4))
        with self.assertRaises(RuntimeError):
            run_module.derive_scaling_plan("4-7", "12-15")
        with self.assertRaises(RuntimeError):
            e2e_module.parse_cpu_set("7-4")

    def test_affinity_probe_checks_taskset_capability(self):
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(run_module.subprocess, "run", return_value=completed) as run:
            self.assertTrue(run_module.affinity_available({4, 5, 6}))
        self.assertEqual(run.call_args.args[0], ["taskset", "-c", "4,5,6", "true"])
        completed = subprocess.CompletedProcess([], 1)
        with mock.patch.object(run_module.subprocess, "run", return_value=completed):
            self.assertFalse(run_module.affinity_available({4}))

    def test_scaling_summary_requires_stability_and_client_headroom(self):
        def point(workers, rates, client_utilization):
            results = []
            for repetition, rate in enumerate(rates):
                results.append({
                    "engine": "luminawaf", "table": "crs", "valid": True,
                    "connections": 100, "repetition": repetition,
                    "requests_per_second": rate,
                    "server_cpu_ns_per_request": 100_000 / workers,
                    "client_cpu_utilization_percent": client_utilization,
                })
            mean = sum(rates) / len(rates)
            variance = sum((rate - mean) ** 2 for rate in rates) / (len(rates) - 1)
            cv = variance ** 0.5 / mean * 100.0
            return {
                "workers": workers, "server_cpu": f"4-{3 + workers}",
                "client_cpu": "12-15", "client_threads": min(workers, 4),
                "results": results,
                "stability": [{
                    "engine": "luminawaf", "connections": 100,
                    "valid_runs": 5, "median_rps": sorted(rates)[2],
                    "cv_percent": cv, "sustainable": cv <= 5.0,
                }],
            }

        summary = run_module.summarize_scaling([
            point(1, [995, 1000, 1001, 1002, 1005], 40.0),
            point(2, [1890, 1900, 1902, 1904, 1910], 70.0),
        ])
        self.assertTrue(summary["valid"])
        two_workers = next(row for row in summary["rows"] if row["workers"] == 2)
        self.assertAlmostEqual(two_workers["speedup"], 1902 / 1001)
        self.assertAlmostEqual(
            two_workers["scaling_efficiency_percent"], 1902 / 1001 / 2 * 100
        )

        saturated = run_module.summarize_scaling([
            point(1, [995, 1000, 1001, 1002, 1005], 95.0)
        ])
        self.assertFalse(saturated["valid"])
        self.assertTrue(any("client-headroom" in error for error in saturated["errors"]))

        diagnostic = point(1, [995, 1000, 1001, 1002, 1005], 40.0)
        baseline_rates = [1990, 2000, 2002, 2004, 2010]
        for repetition, rate in enumerate(baseline_rates):
            diagnostic["results"].append({
                "engine": "baseline", "table": "baseline", "valid": True,
                "connections": 100, "repetition": repetition,
                "requests_per_second": rate,
                "server_cpu_ns_per_request": 20_000,
                "client_cpu_utilization_percent": 95.0,
            })
        diagnostic["stability"].append({
            "engine": "baseline", "connections": 100,
            "valid_runs": 5, "median_rps": 2002,
            "cv_percent": 0.4, "sustainable": True,
        })
        baseline_limited = run_module.summarize_scaling([diagnostic])
        self.assertTrue(baseline_limited["valid"])
        baseline = next(
            row for row in baseline_limited["rows"] if row["engine"] == "baseline"
        )
        self.assertFalse(baseline["qualified"])
        self.assertEqual(baseline["qualification_scope"], "diagnostic")
        self.assertTrue(any("baseline" in item for item in baseline_limited["warnings"]))

    def test_artifact_validation_rejects_post_measurement_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary.so"
            path.write_bytes(b"release")
            manifest = {"binary": run_module.artifact(path)}
            self.assertTrue(run_module.validate_artifact_manifest(manifest)["valid"])
            path.write_bytes(b"changed")
            evidence = run_module.validate_artifact_manifest(manifest)
            self.assertFalse(evidence["valid"])
            self.assertIn("binary: SHA256 drift", evidence["errors"])

    def test_build_provenance_retains_effective_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            result = root / "result"
            build.mkdir()
            result.mkdir()
            (build / "CMakeCache.txt").write_text(
                "CMAKE_BUILD_TYPE:STRING=Release\n"
                "CMAKE_C_COMPILER:FILEPATH=/usr/bin/cc\n"
                "CMAKE_CXX_COMPILER:FILEPATH=/usr/bin/c++\n",
                encoding="utf-8",
            )
            (build / "compile_commands.json").write_text(
                json.dumps([{"command": "cc -O3 -c unit.c", "file": "unit.c"}]),
                encoding="utf-8",
            )
            path = run_module.capture_build_provenance(
                build, result, ["cmake", "-S", "."], ["cmake", "--build", "build"]
            )
            evidence = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(evidence["build_type"], "Release")
            self.assertEqual(evidence["effective_compile_commands"], 1)
            self.assertTrue((result / "CMakeCache.txt").is_file())
            self.assertTrue((result / "compile_commands.json").is_file())

    def test_micro_rows_expose_inner_cv_without_fake_process_ci(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "micro.json"
            name = "FullTransaction/LuminaWAF/Allow/repeats:10"
            path.write_text(json.dumps({"benchmarks": [
                {"run_name": name, "aggregate_name": "median", "cpu_time": 100.0},
                {"run_name": name, "aggregate_name": "cv", "cpu_time": 0.025},
            ]}), encoding="utf-8")
            rows = report_module.micro_rows([path])
            self.assertEqual(rows[0]["inner_cv"], 2.5)
            self.assertIsNone(rows[0]["ci"])

    def test_pmu_rows_preserve_core_metrics_and_partial_unavailability(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pmu_luminawaf.csv"
            path.write_text(
                "1000,,cycles,100,100.00,,\n"
                "2000,,instructions,100,100.00,,\n"
                "500,,branches,100,100.00,,\n"
                "25,,branch-misses,100,100.00,,\n"
                "400,,L1-dcache-loads,80,80.00,,\n"
                "20,,L1-dcache-load-misses,80,80.00,,\n"
                "<not supported>,,LLC-loads,0,100.00,,\n"
                "<not supported>,,LLC-load-misses,0,100.00,,\n",
                encoding="utf-8",
            )
            (Path(directory) / "pmu_luminawaf_group_00.log").write_text(
                "FullTransaction/LuminaWAF/Allow/repeats:10  100 ns  100 ns  5 bytes=x\n"
                "FullTransaction/LuminaWAF/Allow/repeats:10  100 ns  100 ns  5 bytes=x\n",
                encoding="utf-8",
            )
            row = report_module.pmu_rows(Path(directory))[0]
            self.assertEqual(row["ipc"], 2.0)
            self.assertEqual(row["cycles_per_transaction"], 100.0)
            self.assertEqual(row["instructions_per_transaction"], 200.0)
            self.assertEqual(row["branch_miss"], 5.0)
            self.assertEqual(row["l1d_miss"], 5.0)
            self.assertIsNone(row["llc_miss"])
            self.assertEqual(row["running"], 80.0)
            self.assertFalse(row["qualified"])

    def test_execute_pmu_group_records_strict_unsupported_event(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "pmu_group_03.log"
            csv_path = root / "pmu.csv"
            csv_path.write_text("1000,,cycles,100,100.00,,\n", encoding="utf-8")
            run_module.execute_pmu_group(
                [
                    sys.executable,
                    "-c",
                    "print('Error:\\nThe LLC-loads event is not supported.'); raise SystemExit(255)",
                ],
                cwd=root,
                log=log,
                csv_path=csv_path,
                events=("LLC-loads", "LLC-load-misses"),
            )
            evidence = csv_path.read_text(encoding="utf-8")
            self.assertIn("<not supported>,,LLC-loads,0,0.00", evidence)
            self.assertIn("<not supported>,,LLC-load-misses,0,0.00", evidence)
            status = json.loads(log.with_suffix(".status.json").read_text(encoding="utf-8"))
            self.assertEqual(status["classification"], "unsupported_pmu_event_group")
            self.assertEqual(status["returncode"], 255)
            self.assertEqual(status["events"], ["LLC-loads", "LLC-load-misses"])

    def test_execute_pmu_group_rejects_non_capability_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(RuntimeError, r"command failed \(2\)"):
                run_module.execute_pmu_group(
                    [sys.executable, "-c", "print('permission denied'); raise SystemExit(2)"],
                    cwd=root,
                    log=root / "pmu_group.log",
                    csv_path=root / "pmu.csv",
                    events=("cycles", "instructions"),
                )

    def test_overhead_pmu_rows_count_direct_kernel_iterations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "overhead_pmu_inspectprebuilt.csv").write_text(
                "1000,,cycles,100,100.00,,\n"
                "2000,,instructions,100,100.00,,\n"
                "500,,branches,100,100.00,,\n"
                "25,,branch-misses,100,100.00,,\n",
                encoding="utf-8",
            )
            (root / "overhead_pmu_inspectprebuilt_group_00.log").write_text(
                "Overhead/LuminaWAF/InspectPrebuilt/AllowRotation/repeats:10  "
                "100 ns  100 ns  10 bytes=x\n",
                encoding="utf-8",
            )
            row = report_module.overhead_pmu_rows(root)[0]
            self.assertEqual(row["cycles_per_transaction"], 100.0)
            self.assertEqual(row["instructions_per_transaction"], 200.0)
            self.assertEqual(row["ipc"], 2.0)
            self.assertTrue(row["qualified"])
            self.assertTrue(
                run_module.validate_pmu_csv(
                    root / "overhead_pmu_inspectprebuilt.csv"
                )["valid"]
            )


if __name__ == "__main__":
    unittest.main()
