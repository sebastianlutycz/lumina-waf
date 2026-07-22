#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TRANSLATOR_PATH = ROOT / "tools" / "sidecar_translator.py"
SPEC = importlib.util.spec_from_file_location("sidecar_translator", TRANSLATOR_PATH)
TRANSLATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSLATOR)


class SidecarTranslatorTest(unittest.TestCase):
    def test_first_byte_mask_density_requires_every_byte(self):
        dense = [[0, 1] for _ in range(256)]
        sparse = [row[:] for row in dense]
        sparse[255] = [0, 0]
        self.assertTrue(TRANSLATOR.first_byte_mask_is_dense(dense))
        self.assertFalse(TRANSLATOR.first_byte_mask_is_dense(sparse))

    @staticmethod
    def _generated_u64_rows(source, symbol):
        match = re.search(
            rf"const uint64_t {symbol}[^=]*= \{{(.*?)\n\}};",
            source,
            re.DOTALL,
        )
        if match is None:
            raise AssertionError(f"missing generated table {symbol}")
        return [
            tuple(int(value, 16) for value in re.findall(r"0x([0-9a-f]+)ULL", row))
            for row in re.findall(r"\{([^{}]+)\}", match.group(1))
        ]

    def test_runtime_covered_pm_rule_emits_shared_scanner_and_stable_wrapper(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:User-Agent "@pmFromFile scanners-user-agents.data" \
                "id:913100,phase:1,deny,t:none,t:lowercase,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_pm_runtime_913100(const unsigned char *, size_t);
        static int scan(const char *value) {
            return lumina_pm_runtime_913100(
                (const unsigned char *)value, strlen(value));
        }
        int main(void) {
            if (scan("Mozilla/5.0 Chrome/120 Safari/537.36") != 0) return 1;
            if (scan("Mozilla/5.0 SQLMAP") != 1) return 2;
            if (scan("prefix MoZlIlA suffix") != 1) return 3;
            if (scan("ordinary-browser-nik") != 0) return 4;
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            (rules_dir / "scanners-user-agents.data").write_text(
                "sqlmap\nmozlila\n", encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            pm_source = (out_dir / "parser_rules_0001.c").read_text(encoding="utf-8")
            header = (out_dir / "generated" / "crs_short_rules.h").read_text(
                encoding="utf-8")
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text())
            driver_path = pathlib.Path(tmp) / "driver.c"
            executable = pathlib.Path(tmp) / "runtime_pm"
            driver_path.write_text(driver, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", f"-I{out_dir}", f"-I{ROOT / 'src'}",
                 str(out_dir / "parser_rules_0001.c"), str(driver_path),
                 "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)
        self.assertIn("int lumina_pm_scanners_user_agents_data", pm_source)
        self.assertIn("int lumina_pm_runtime_913100", pm_source)
        self.assertIn("extern int lumina_pm_runtime_913100", header)
        self.assertNotIn(913100, manifest["generated_rule_ids"])
        self.assertIn(913100, manifest["runtime_covered_rule_ids"])

    def test_runtime_pm_wrapper_is_stub_when_rule_is_absent(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx attack" \
                "id:100001,phase:2,deny,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            pm_source = (out_dir / "parser_rules_0001.c").read_text(encoding="utf-8")
        self.assertIn("int lumina_pm_runtime_913100", pm_source)
        self.assertIn("(void)data; (void)len;", pm_source)

    def test_single_conf_ignores_commented_secaction_examples(self):
        conf = textwrap.dedent(
            r'''
            #SecAction \
            #    "id:100000,phase:1,pass,setvar:tx.disabled_limit=5"
            SecAction "id:100001,phase:1,pass,setvar:tx.active_limit=7"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "setup.conf"
            path.write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(path))
        self.assertEqual([rule["id"] for rule in parsed], ["100001"])
        self.assertEqual(TRANSLATOR.collect_static_tx_values(parsed), {"active_limit": "7"})

    def test_nullable_regex_is_decided_at_translation_time(self):
        self.assertTrue(TRANSLATOR.regex_matches_empty(r"^$"))
        self.assertTrue(TRANSLATOR.regex_matches_empty(r"^(?:x)?$"))
        self.assertFalse(TRANSLATOR.regex_matches_empty(r"^x$"))

    def test_variable_split_preserves_regex_alternation(self):
        expression = "ARGS|!ARGS:/^(?:foo|bar)$/|REQUEST_HEADERS:X-Custom"
        self.assertEqual(
            TRANSLATOR.split_variable_expression(expression),
            ["ARGS", "!ARGS:/^(?:foo|bar)$/", "REQUEST_HEADERS:X-Custom"],
        )

    def test_cookie_collections_do_not_map_to_headers(self):
        bindings = TRANSLATOR.parse_variable_bindings(
            "REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS|ARGS_NAMES"
        )
        contract = TRANSLATOR.compile_binding_contract(bindings)
        self.assertEqual(
            contract["scope"],
            TRANSLATOR.SCOPE_URI | TRANSLATOR.SCOPE_HEADERS | TRANSLATOR.SCOPE_BODY,
        )
        self.assertEqual(
            contract["var_type_mask"],
            (1 << 1) | (1 << 2) | (1 << 6) | (1 << 9),
        )

    def test_file_values_names_and_args_names_have_distinct_runtime_slots(self):
        args_names = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("ARGS_NAMES|ARGS_POST_NAMES")
        )
        file_values = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("FILES")
        )
        file_names = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("FILES_NAMES")
        )
        self.assertEqual(args_names["var_type_mask"], 1 << 6)
        self.assertEqual(file_values["var_type_mask"], 1 << 7)
        self.assertEqual(file_names["var_type_mask"], 1 << 10)

    def test_negated_file_rule_is_bound_per_projected_value(self):
        rule = {
            "bindings": TRANSLATOR.parse_variable_bindings("FILES|FILES_NAMES"),
        }
        self.assertTrue(TRANSLATOR.negated_rx_runtime_safe(rule))

    def test_query_string_is_distinct_from_projected_args(self):
        query = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("QUERY_STRING")
        )
        args = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("ARGS|ARGS_NAMES")
        )
        self.assertEqual(query["var_type_mask"], 1 << 8)
        self.assertEqual(args["var_type_mask"], (1 << 1) | (1 << 6))
        self.assertEqual(query["var_type_mask"] & args["var_type_mask"], 0)

    def test_filename_and_basename_have_distinct_projected_slots(self):
        filename = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("REQUEST_FILENAME")
        )
        basename = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("REQUEST_BASENAME")
        )
        uri = TRANSLATOR.compile_binding_contract(
            TRANSLATOR.parse_variable_bindings("REQUEST_URI")
        )
        self.assertEqual(filename["var_type_mask"], 1 << 11)
        self.assertEqual(basename["var_type_mask"], 1 << 12)
        self.assertEqual((filename["var_type_mask"] | basename["var_type_mask"])
                         & uri["var_type_mask"], 0)

    def test_transform_aware_routing_preserves_raw_trigger_bytes(self):
        first = TRANSLATOR.transform_aware_first_bytes(r"for", ["cmdLine"])
        self.assertIn(ord("f"), first)
        self.assertIn(ord("F"), first)
        encoded = TRANSLATOR.transform_aware_first_bytes(r"attack", ["urlDecodeUni"])
        self.assertIn(ord("%"), encoded)
        self.assertTrue(TRANSLATOR.transform_requires_offset_zero(["base64Decode"]))
        self.assertTrue(TRANSLATOR.transform_requires_offset_zero(["length"]))
        self.assertTrue(TRANSLATOR.transform_requires_offset_zero(["utf8toUnicode"]))
        self.assertFalse(TRANSLATOR.transform_requires_offset_zero(["urlDecodeUni"]))

    def test_nullable_prefix_routing_continues_to_required_alternative(self):
        first = TRANSLATOR.first_bytes_of(r'''(?i)\(?["']*(?:assert|exec|system)\(''')
        for byte in b"('aAeEsS":
            self.assertIn(byte, first)

    def test_detect_sqli_uses_lumina_owned_classifier(self):
        generated = TRANSLATOR.emit_detect_sqli("100049")
        self.assertIn("lumina_sqli_detect", generated)
        self.assertNotIn("libinjection_sqli", generated)
        self.assertNotIn("lumina_scan_sqli", generated)
        self.assertNotIn("pcre", generated.lower())
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100049(const unsigned char *, size_t, size_t);
        static int scan(const char *value) {
            return lumina_scan_rule_100049(
                (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan("1' OR 1=1--") != 100049) return 1;
            if (scan("ordinary account description") != 0) return 2;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "detect_sqli.c"
            exe = pathlib.Path(tmp) / "detect_sqli"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                [
                    "cc", "-std=c11", "-O2", str(src),
                    str(ROOT / "src/lumina_sqli.c"),
                    "-I", str(ROOT / "src"),
                    "-o", str(exe),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_standalone_modsecurity_conf_parses_typed_binding(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:X-Custom "!@rx ^[0-9]+$" \
                "id:100001,phase:1,deny,t:none,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rules = TRANSLATOR.parse_conf_files(tmp)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule["operator"], "@rx")
        self.assertTrue(rule["negated"])
        self.assertEqual(rule["bindings"][0].collection, "REQUEST_HEADERS")
        self.assertEqual(rule["bindings"][0].selector, "X-Custom")

    def test_negated_rx_is_whole_value_and_repeat_is_not_truncated(self):
        generated = TRANSLATOR.emit_negated_rx("100002", r"^\d+$")
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100002(const unsigned char *, size_t, size_t);
        int main(void) {
            const char *valid = "123456789";
            const char *invalid = "123x";
            if (lumina_scan_rule_100002((const unsigned char *)valid, strlen(valid), 0) != 0) return 1;
            if (lumina_scan_rule_100002((const unsigned char *)invalid, strlen(invalid), 0) != 100002) return 2;
            if (lumina_scan_rule_100002((const unsigned char *)invalid, strlen(invalid), 1) != 0) return 3;
            return 0;
        }
        '''
        source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "test.c"
            exe = pathlib.Path(tmp) / "test"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_auto_mode_compiles_ordinary_disruptive_modsecurity_rule(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx attack" \
                "id:100003,phase:2,deny,t:none,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(manifest["rule_mode"], "modsecurity")
        self.assertEqual(manifest["generated_rule_ids"], [100003])
        self.assertEqual(manifest["dfa_state_budget"], 1536)
        self.assertEqual(manifest["dfa_table_budget"], 2 * 1024 * 1024)
        self.assertEqual(manifest["dfa_compact_state_budget"], 4096)
        self.assertEqual(manifest["dfa_compact_pattern_limit"], 256)

    def test_named_header_selector_does_not_gate_sibling_collections(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx attack" \
                "id:100011,phase:2,deny,t:none,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            source = (out_dir / "parser_rules_0000.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        contract = manifest["generated_rules"][0]["binding_contract"]
        self.assertEqual(contract["header_mask"], TRANSLATOR.HEADER_MASKS["USER-AGENT"])
        self.assertIn("var_type != 3 || g_short_rule_hdr_mask[idx] == 0", source)

    def test_header_active_masks_are_precomputed_per_selector(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx attack" \
                "id:100011,phase:2,deny,t:none,severity:'CRITICAL'"
            SecRule REQUEST_HEADERS:Host "@rx attack" \
                "id:100012,phase:2,deny,t:none,severity:'CRITICAL'"
            SecRule REQUEST_HEADERS "@rx attack" \
                "id:100013,phase:2,deny,t:none,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            source = (out_dir / "parser_rules_0000.c").read_text(encoding="utf-8")
            header = (out_dir / "generated" / "crs_short_rules.h").read_text(
                encoding="utf-8"
            )

        rows = self._generated_u64_rows(source, "g_short_rule_header_active_pos0")
        header_scope = TRANSLATOR.SCOPE_HEADERS
        slots = TRANSLATOR.HEADER_SELECTOR_SLOTS
        generic = rows[header_scope * slots]
        host = rows[header_scope * slots + 4]
        user_agent = rows[header_scope * slots + 5]
        self.assertEqual(generic[0] & 0x7, 0x4)
        self.assertEqual(host[0] & 0x7, 0x6)
        self.assertEqual(user_agent[0] & 0x7, 0x5)

        ordinary = self._generated_u64_rows(source, "g_short_rule_active_pos0")
        args_row = ordinary[TRANSLATOR.SCOPE_URI * TRANSLATOR.VAR_TYPE_SLOTS + 1]
        self.assertEqual(args_row[0] & 0x7, 0x1)
        self.assertIn("#define LUMINA_HEADER_SELECTOR_SLOTS 13", header)
        self.assertNotIn("g_short_rule_hdr_filter_present", source)

    def test_same_buffer_chain_scores_on_idless_child_and_executes_as_one_rule(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|REQUEST_BODY|XML:/* "@rx alpha" \
                "id:100004,phase:2,deny,capture,t:none,severity:'CRITICAL',\
                setvar:'tx.100004_matched_var_name=%{matched_var_name}',chain"
            SecRule MATCHED_VARS "@rx omega" \
                    "t:none,chain"
                SecRule MATCHED_VARS "!@rx forbidden" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(tmp)
            grouped = TRANSLATOR.group_rule_chains(parsed)
            self.assertEqual(len(grouped), 1)
            rule = grouped[0]
            self.assertTrue(TRANSLATOR.chain_is_score_bearing(rule))
            self.assertIsNone(TRANSLATOR.same_buffer_rx_chain_reason(rule))
            generated = TRANSLATOR.emit_same_buffer_rx_chain(rule)
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100004(const unsigned char *, size_t, size_t);
            int main(void) {
                const char *both = "alpha payload omega";
                const char *head_only = "alpha payload";
                const char *excluded = "alpha forbidden omega";
                const char *xml_name = "<?xml version=\"1.0\"?><alphaomega>value</alphaomega>";
                const char *xml_value = "<?xml version=\"1.0\"?><node key=\"alpha omega\">value</node>";
                if (lumina_scan_rule_100004((const unsigned char *)both, strlen(both), 0) != 100004) return 1;
                if (lumina_scan_rule_100004((const unsigned char *)head_only, strlen(head_only), 0) != 0) return 2;
                if (lumina_scan_rule_100004((const unsigned char *)both, strlen(both), 1) != 0) return 3;
                if (lumina_scan_rule_100004((const unsigned char *)xml_name, strlen(xml_name), 0) != 0) return 4;
                if (lumina_scan_rule_100004((const unsigned char *)xml_value, strlen(xml_value), 0) != 100004) return 5;
                if (lumina_scan_rule_100004((const unsigned char *)excluded, strlen(excluded), 0) != 0) return 6;
                return 0;
            }
            '''
            source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver
            src = pathlib.Path(tmp) / "chain.c"
            exe = pathlib.Path(tmp) / "chain"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_same_buffer_chain_accumulates_positive_global_xml_values(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|REQUEST_BODY|XML:/*|XML://@* "@rx runtime|processbuilder" \
                "id:100049,phase:2,deny,t:none,chain"
                SecRule MATCHED_VARS|XML:/*|XML://@* "@rx (?i)(?:java\.|unmarshaller)" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+5'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            grouped = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp))
            self.assertEqual(len(grouped), 1)
            rule = grouped[0]
            self.assertIsNone(TRANSLATOR.same_buffer_rx_chain_reason(rule))
            generated = TRANSLATOR.emit_same_buffer_rx_chain(rule)
            self.assertTrue(rule["_chain_global_xml"])
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100049(const unsigned char *, size_t, size_t);
            static int scan(const char *value) {
                return lumina_scan_rule_100049(
                    (const unsigned char *)value, strlen(value), 0);
            }
            int main(void) {
                const char *split = "<?xml version=\"1.0\"?><x a=\"java.lang.string\" b=\"runtime\">safe</x>";
                const char *names = "<?xml version=\"1.0\"?><java.runtime>safe</java.runtime>";
                const char *head_only = "<?xml version=\"1.0\"?><x a=\"runtime\">safe</x>";
                if (scan("java.runtime") != 100049) return 1;
                if (scan("runtime only") != 0) return 2;
                if (scan(split) != 100049) return 3;
                if (scan(names) != 0) return 4;
                if (scan(head_only) != 0) return 5;
                return 0;
            }
            '''
            source = pathlib.Path(tmp) / "xml_collection_chain.c"
            executable = pathlib.Path(tmp) / "xml_collection_chain"
            source.write_text(
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
                generated + driver,
                encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(source), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

        negated = {
            "id": "100051",
            "variables": "ARGS|XML:/*|XML://@*",
            "bindings": TRANSLATOR.parse_variable_bindings(
                "ARGS|XML:/*|XML://@*"),
            "_chain_members": [
                {"operator": "@rx", "pattern": "runtime", "negated": False,
                 "variables": "ARGS|XML:/*|XML://@*", "transforms": ["none"]},
                {"operator": "@rx", "pattern": r"java\.", "negated": True,
                 "variables": "MATCHED_VARS|XML:/*|XML://@*",
                 "transforms": ["none"]},
            ],
        }
        self.assertEqual(
            TRANSLATOR.same_buffer_rx_chain_reason(negated),
            "chain-collection-requires-state",
        )

    def test_same_buffer_chain_uses_bounded_nfa_before_recursive_dfa(self):
        head_pattern = (
            r'''(?i)(?:,[^\)]*?(?:[0-9a-f]+|\([0-9a-f]+\))|'''
            r'''\([^,]+(?:,[\s\x0b]*[0-9a-f]+)+\))(?:$|["'`]'''
            r'''(?:$|[^"'`]+["'`])|(?:\r?\n)?\z)|,[^\)]*?["'`]'''
            r'''[^"'`]+["'`]|[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from|'''
            r'''(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|'''
            r'''(?:inser|selec)t|load)[\s\x0b]*?\([\s\x0b]*?space'''
            r'''[\s\x0b]*?\('''
        )
        rule = {
            "id": "100050",
            "variables": "ARGS|REQUEST_HEADERS:User-Agent",
            "bindings": TRANSLATOR.parse_variable_bindings(
                "ARGS|REQUEST_HEADERS:User-Agent"
            ),
            "_chain_members": [
                {"operator": "@rx", "pattern": head_pattern,
                 "negated": False, "variables": "ARGS",
                 "transforms": ["none"]},
                {"operator": "@rx", "pattern": r"^[,\-0-9=A-Z_a-z]+$",
                 "negated": True, "variables": "MATCHED_VARS",
                 "transforms": ["none"]},
            ],
        }
        generated = TRANSLATOR.emit_same_buffer_rx_chain(rule)
        self.assertFalse(rule["_chain_recursive_dfa"])
        self.assertTrue(rule["_chain_bounded_nfa"])
        self.assertTrue(rule["_chain_seeded_nfa"])
        self.assertIn("lumina_chain_dfa_100050_0_bounded_nfa", generated)
        self.assertIn("mandatory_seed_present", generated)
        self.assertIn("seed_checked", generated)
        self.assertIn("seed_candidates", generated)
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100050(const unsigned char *, size_t, size_t);
        static int scan(const char *value) {
            return lumina_scan_rule_100050(
                (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan("hash = 'abc', 0x1a") != 100050) return 1;
            if (scan("'admin', '1'='1'") != 100050) return 2;
            if (scan("999, rue d'Arlon") != 0) return 3;
            if (scan(" x SELECT payload FROM users") != 100050) return 4;
            if (scan("select ( space (") != 100050) return 5;
            if (scan("Mozilla/5.0 ordinary browser") != 0) return 6;
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            source = pathlib.Path(tmp) / "recursive_chain.c"
            executable = pathlib.Path(tmp) / "recursive_chain"
            source.write_text(
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver,
                encoding="utf-8",
            )
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(source), "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_terminal_capture_tx1_chain_executes_as_parent_first_native_dfas(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|ARGS_NAMES|REQUEST_HEADERS:X-Test|XML:/* "@rx ^prefix[\s\x0b]*([A-Za-z]+)\b" \
                "id:100042,phase:2,deny,capture,t:none,severity:'CRITICAL',chain"
                SecRule TX:1 "@rx ^(?:allow|permit)$" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rule = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp)
            )[0]
            self.assertIsNone(
                TRANSLATOR.terminal_capture_same_value_chain_reason(rule))
            generated = TRANSLATOR.emit_terminal_capture_same_value_chain(rule)
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100042(const unsigned char *, size_t, size_t);
            static int scan(const char *value, size_t offset) {
                return lumina_scan_rule_100042(
                    (const unsigned char *)value, strlen(value), offset);
            }
            int main(void) {
                const char *xml_ok = "<?xml version=\"1.0\"?><node>prefix permit</node>";
                const char *xml_name = "<?xml version=\"1.0\"?><prefix allow>value</prefix>";
                if (scan("prefix allow", 0) != 100042) return 1;
                if (scan("prefix    permit", 0) != 100042) return 2;
                if (scan("prefix deny", 0) != 0) return 3;
                if (scan("prefix allow", 1) != 0) return 4;
                if (scan(xml_ok, 0) != 100042) return 5;
                if (scan(xml_name, 0) != 0) return 6;
                return 0;
            }
            '''
            source = (
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
                generated + driver
            )
            src = pathlib.Path(tmp) / "terminal_capture_chain.c"
            exe = pathlib.Path(tmp) / "terminal_capture_chain"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_terminal_capture_chain_rejects_nonterminal_and_multiple_captures(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx ^prefix([A-Za-z]+)-tail$" \
                "id:100043,phase:2,deny,capture,t:none,severity:'CRITICAL',chain"
                SecRule TX:1 "@rx ^allow$" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

            SecRule ARGS "@rx ^(prefix)([A-Za-z]+)$" \
                "id:100044,phase:2,deny,capture,t:none,severity:'CRITICAL',chain"
                SecRule TX:1 "@rx ^prefix$" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rules = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp)
            )
        self.assertEqual(len(rules), 2)
        self.assertIsNotNone(
            TRANSLATOR.terminal_capture_same_value_chain_reason(rules[0]))
        self.assertIsNotNone(
            TRANSLATOR.terminal_capture_same_value_chain_reason(rules[1]))

    def test_two_capture_equality_chains_execute_as_composed_native_dfas(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|XML:/* "@rx (?i)[ ]*\b([A-Z0-9]+)\b[ ]*(?:=|<=>)[ ]*\b([A-Z0-9]+)\b" \
                "id:100051,phase:2,deny,capture,t:none,severity:'CRITICAL',chain"
                SecRule TX:1 "@streq %{TX.2}" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"

            SecRule ARGS|XML:/* "@rx (?i)[ ]*\b([A-Z0-9]+)\b[ ]*(?:!=|<[=>]?)[ ]*\b([A-Z0-9]+)\b" \
                "id:100052,phase:2,deny,capture,multiMatch,t:none,severity:'CRITICAL',chain"
                SecRule TX:1 "!@streq %{TX.2}" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rules = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp))
            self.assertEqual(len(rules), 2)
            self.assertIsNone(
                TRANSLATOR.two_capture_compare_chain_reason(rules[0]))
            self.assertIsNone(
                TRANSLATOR.two_capture_compare_chain_reason(rules[1]))
            generated = "\n".join(
                TRANSLATOR.emit_two_capture_compare_chain(rule)
                for rule in rules)
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100051(const unsigned char *, size_t, size_t);
            int lumina_scan_rule_100052(const unsigned char *, size_t, size_t);
            static int scan(int rule, const char *value) {
                if (rule == 100051) return lumina_scan_rule_100051(
                    (const unsigned char *)value, strlen(value), 0);
                return lumina_scan_rule_100052(
                    (const unsigned char *)value, strlen(value), 0);
            }
            int main(void) {
                const char *xml = "<?xml version=\"1.0\"?><node>42=42</node>";
                if (scan(100051, "1=1") != 100051) return 1;
                if (scan(100051, "b,1=1") != 100051) return 2;
                if (scan(100051, "11=1") != 0) return 3;
                if (scan(100051, "A=a") != 0) return 4;
                if (scan(100051, xml) != 100051) return 5;
                if (scan(100052, "11!=1") != 100052) return 6;
                if (scan(100052, "11!=11") != 0) return 7;
                if (scan(100052, "1<=2") != 100052) return 8;
                if (scan(100052, "1!=1 2!=3") != 100052) return 9;
                return 0;
            }
            '''
            source = (
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
                generated + driver)
            src = pathlib.Path(tmp) / "two_capture_compare.c"
            exe = pathlib.Path(tmp) / "two_capture_compare"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_transaction_chain_is_classified_by_shape_not_rule_id(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS_NAMES "@rx ^sessionid$" \
                "id:100009,phase:2,deny,capture,t:none,t:lowercase,severity:'CRITICAL',chain"
                SecRule REQUEST_HEADERS:Referer "@rx ^(?:ht|f)tps?://(.*?)/" \
                    "capture,chain"
                    SecRule TX:1 "!@endsWith %{request_headers.host}" \
                        "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rule = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp)
            )[0]
            descriptor = TRANSLATOR.classify_transaction_chain(rule)
        self.assertEqual(descriptor["kind"], "arg-name-and-off-domain-header")
        self.assertEqual(descriptor["capture_header_mask"], TRANSLATOR.HEADER_MASKS["REFERER"])
        self.assertEqual(descriptor["suffix_header_mask"], TRANSLATOR.HEADER_MASKS["HOST"])

    def test_request_metadata_chains_lower_to_one_generic_native_evaluator(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
                "id:100030,phase:1,deny,t:none,severity:'CRITICAL',chain"
                SecRule REQUEST_HEADERS:Content-Length "!@rx ^0?$" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

            SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" \
                "id:100031,phase:1,deny,t:none,severity:'CRITICAL',chain"
                SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"

            SecRule REQUEST_PROTOCOL "!@within HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0" \
                "id:100032,phase:1,deny,t:none,severity:'WARNING',chain"
                SecRule REQUEST_METHOD "@streq POST" "chain"
                    SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "chain"
                        SecRule &REQUEST_HEADERS:Transfer-Encoding "@eq 0" \
                            "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"

            SecRule &REQUEST_HEADERS:Transfer-Encoding "!@eq 0" \
                "id:100033,phase:1,deny,t:none,severity:'WARNING',chain"
                SecRule &REQUEST_HEADERS:Content-Length "!@eq 0" \
                    "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"

            SecRule REQUEST_HEADERS:Range "@rx ^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){6}" \
                "id:100034,phase:1,deny,t:none,severity:'WARNING',chain"
                SecRule REQUEST_BASENAME "!@endsWith .pdf" \
                    "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'"

            SecRule REQUEST_BODY_LENGTH "@gt 0" \
                "id:100035,phase:2,deny,t:none,severity:'CRITICAL',chain"
                SecRule &REQUEST_HEADERS:Content-Type "@eq 0" \
                    "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            grouped = TRANSLATOR.group_rule_chains(parsed)
            descriptors = [TRANSLATOR.classify_transaction_chain(rule) for rule in grouped]
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = out_dir / "crs_tx_rules.c"
            source = tx_source.read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(tx_source)],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            [descriptor["kind"] for descriptor in descriptors],
            ["request-metadata-chain"] * 6,
        )
        self.assertEqual(
            [entry["transaction_kind"] for entry in manifest["generated_rules"]],
            ["request-metadata-chain"] * 6,
        )
        self.assertIn("lumina_tx_metadata_rx_0_0", source)
        self.assertIn("hdr_transfer_encoding_count", source)
        self.assertIn("hdr_presence_mask", source)
        self.assertIn("lumina_tx_projected_within", source)
        self.assertIn("lumina_tx_request_basename", source)
        self.assertIn("lumina_tx_request_body_length", source)
        self.assertNotIn("100030 ==", source)

    def test_metadata_chain_supports_named_header_phrase_negation(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:Accept "@rx ^$" \
                "id:100036,phase:1,deny,t:none,severity:'NOTICE',chain"
                SecRule REQUEST_METHOD "!@rx ^OPTIONS$" "chain"
                    SecRule REQUEST_HEADERS:User-Agent "!@pm AppleWebKit Android Business" \
                        "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(out_dir / "crs_tx_rules.c")],
                check=True, capture_output=True, text=True,
            )
        self.assertEqual(
            manifest["generated_rules"][0]["transaction_kind"],
            "request-metadata-chain",
        )
        self.assertIn("lumina_pm_tx_metadata_pm_0_2", tx_source)
        self.assertIn("metadata_predicate_0_2", tx_source)

    def test_metadata_basename_chain_preserves_url_decode_transform(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_BASENAME "@endsWith .pdf" \
                "id:100037,phase:1,deny,t:none,t:urlDecodeUni,severity:'WARNING',chain"
                SecRule REQUEST_HEADERS:Range "@rx ^bytes=" \
                    "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            grouped = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(str(rules_dir)))
        descriptor = TRANSLATOR.classify_transaction_chain(grouped[0])
        self.assertEqual(descriptor["kind"], "request-metadata-chain")
        self.assertEqual(descriptor["predicates"][0]["transforms"], ["urldecodeuni"])

    def test_direct_raw_uri_contains_uses_zero_copy_metadata_path(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_URI_RAW "@contains #" \
                "id:100039,phase:1,deny,t:none,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            grouped = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(str(rules_dir)))
            descriptor = TRANSLATOR.classify_whole_value_request_rule(grouped[0])
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
        self.assertEqual(descriptor["kind"], "request-metadata-chain")
        self.assertEqual(descriptor["predicates"][0]["type"], "raw-uri-contains")
        self.assertIn("lumina_tx_raw_uri", tx_source)
        self.assertIn("lumina_tx_projected_contains", tx_source)
        self.assertNotIn("100039 ==", tx_source)

    def test_named_header_decimal_capture_uses_linear_compare_microkernel(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:Range "@rx (\d+)-(\d+)" \
                "id:100038,phase:1,deny,capture,t:none,severity:'WARNING',chain"
                SecRule TX:2 "@lt %{tx.1}" \
                    "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            grouped = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(str(rules_dir)))
        descriptor = TRANSLATOR.classify_transaction_chain(grouped[0])
        self.assertEqual(descriptor["kind"], "named-header-decimal-capture-compare")
        self.assertEqual(descriptor["operator"], "@lt")
        self.assertEqual(descriptor["separator"], ord("-"))

    def test_named_header_capture_views_are_zero_copy_transaction_rules(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:Referer "@rx ^[^#]+" \
                "id:100040,phase:1,deny,capture,t:none,t:lowercase,t:urlDecodeUni,\
                severity:'CRITICAL',chain"
                SecRule TX:0 "@rx ^[^.]+[.](.*foo)" "capture,t:none,chain"
                    SecRule TX:1 "@rx /" "t:none,chain"
                        SecRule TX:1 "@rx \s" \
                            "t:none,setvar:'tx.inbound_anomaly_score_pl1=+5'"

            SecRule REQUEST_HEADERS:Referer "@rx #.*" \
                "id:100041,phase:1,deny,capture,t:none,t:lowercase,t:urlDecodeUni,\
                severity:'CRITICAL',chain"
                SecRule TX:0 "@rx foo.*bar" "capture,t:none,chain"
                    SecRule MATCHED_VAR "@rx /" "t:none,chain"
                        SecRule MATCHED_VAR "@rx \s" "t:none,chain"
                            SecRule MATCHED_VAR "!@beginsWith #:~:text=" \
                                "t:none,setvar:'tx.inbound_anomaly_score_pl1=+5'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            grouped = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(str(rules_dir)))
            descriptors = [
                TRANSLATOR.classify_named_header_capture_view_chain(rule)
                for rule in grouped
            ]
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(out_dir / "crs_tx_rules.c")],
                check=True, capture_output=True, text=True,
            )
        self.assertEqual([item["mode"] for item in descriptors],
                         ["terminal-capture", "matched-var"])
        self.assertIn("lumina_tx_capture_view_mask_0_0", tx_source)
        self.assertIn("lumina_tx_capture_view_child_1", tx_source)
        self.assertNotIn("100040 ==", tx_source)
        self.assertNotIn("100041 ==", tx_source)

    def test_multipart_named_field_policy_uses_streaming_body_projection(self):
        conf = textwrap.dedent(
            r'''
            SecAction "id:100042,phase:1,pass,nolog,\
                setvar:'tx.allowed_charsets=|utf-8| |latin1|'"
            SecRule &MULTIPART_PART_HEADERS:encoding "!@eq 0" \
                "id:100043,phase:2,deny,t:none,severity:'CRITICAL',\
                setvar:'tx.selected_encoding=|%{ARGS.encoding}|',chain"
                SecRule TX:selected_encoding "!@within %{tx.allowed_charsets}" \
                    "t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+5'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            grouped = TRANSLATOR.group_rule_chains(parsed)
            descriptor = TRANSLATOR.classify_transaction_chain(
                grouped[1], TRANSLATOR.collect_static_tx_values(parsed))
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(out_dir / "crs_tx_rules.c")],
                check=True, capture_output=True, text=True,
            )
        self.assertEqual(descriptor["kind"], "multipart-field-not-within-static-tx")
        self.assertEqual(descriptor["field_name"], "encoding")
        self.assertIn("lumina_tx_multipart_field_not_within", tx_source)
        self.assertIn("if (lumina_tx_multipart_field_not_within(", tx_source)
        self.assertNotIn("100043 ==", tx_source)

    def test_transform_dispatch_tracks_cmdline_boundary_fold(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx /[a-z]+" \
                "id:100044,phase:2,deny,t:none,t:cmdLine,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+5'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            dispatch_source = (out_dir / "parser_rules_0000.c").read_text(encoding="utf-8")
        self.assertIn("bool cmdline_boundary_fold = false", dispatch_source)
        self.assertIn("s[transformed_offset - 1] == ' '", dispatch_source)
        self.assertIn("transformed_offset -= cmdline_boundary_fold", dispatch_source)
        self.assertIn("lumina_transform_sequence_may_change", dispatch_source)
        self.assertIn("g_transform_sequence_dirty_by_byte[data[i]]", dispatch_source)
        self.assertIn("g_transform_input_class.valid = 0", dispatch_source)

    def test_transform_dirty_classifier_preserves_generated_match_results(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx ^abc$" \
                "id:100046,phase:2,deny,t:none,t:lowercase,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+5'"
            SecRule ARGS "@rx ^a b$" \
                "id:100047,phase:2,deny,t:none,t:urlDecodeUni,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+5'"
            '''
        )
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_dispatch_rule(int, const unsigned char *, size_t, size_t);
        void lumina_reset_transform_view_cache(void);
        static int scan(int idx, const char *value) {
            lumina_reset_transform_view_cache();
            return lumina_dispatch_rule(
                idx, (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan(0, "abc") != 100046) return 1;
            if (scan(0, "ABC") != 100046) return 2;
            if (scan(0, "abd") != 0) return 3;
            if (scan(1, "a b") != 100047) return 4;
            if (scan(1, "a%20b") != 100047) return 5;
            if (scan(1, "a+b") != 100047) return 6;
            if (scan(1, "axb") != 0) return 7;
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            rules_dir = root / "rules"
            out_dir = root / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            subprocess.run(
                ["python3", str(ROOT / "tools" / "gen_transform_mask.py"),
                 "--manifest", str(out_dir / "generated" / "rule_manifest.json"),
                 "--rules-dir", str(rules_dir),
                 "--out-dir", str(out_dir / "generated")],
                check=True, capture_output=True, text=True,
            )
            driver_path = root / "driver.c"
            executable = root / "transform_dirty"
            driver_path.write_text(driver, encoding="utf-8")
            parser_sources = sorted(out_dir.glob("parser_rules_*.c"))
            subprocess.run(
                ["cc", "-std=c11", "-O1", "-mavx2",
                 f"-I{ROOT / 'src'}", f"-I{out_dir}",
                 *map(str, parser_sources),
                 str(ROOT / "src" / "lumina_transforms.c"),
                 str(out_dir / "generated" / "crs_transform_mask.c"),
                 str(driver_path), "-o", str(executable)],
                check=True, capture_output=True, text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_procedural_lazy_gap_uses_selective_overlay_microkernel(self):
        pattern = (r"(?i)\boverlay\b[^0-9A-Z_a-z]*?\(.*?\b"
                   r"[^0-9A-Z_a-z]*?plac(?:ing)\b")
        generated = TRANSLATOR.emit_procedural_fallback(100045, pattern)
        self.assertIn("lumina_overlay_placing_100045", generated)
        self.assertIn("if (lumina_overlay_placing_100045(data, len, offset))", generated)

    def test_generated_tx_evaluator_uses_bounded_slice_operations(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS_NAMES "@rx ^sessionid$" \
                "id:100010,phase:2,deny,capture,t:none,t:lowercase,severity:'CRITICAL',chain"
                SecRule &REQUEST_HEADERS:Referer "@eq 0" \
                    "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            header = (out_dir / "generated" / "crs_short_rules.h").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertNotIn("strstr", tx_source)
        self.assertNotIn("strncasecmp", tx_source)
        self.assertIn("predicate_rules", tx_source)
        self.assertIn(
            f"LUMINA_GENERATED_VAR_TYPE_SLOTS {TRANSLATOR.VAR_TYPE_SLOTS}",
            header,
        )
        self.assertIn("g_short_rule_request_body_mask", header)
        self.assertIn("g_short_rule_xml_container_mask", header)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "arg-name-and-header-absent")

    def test_typed_rule_remove_control_targets_generated_engine_index(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQBODY_PROCESSOR "@streq JSON" \
                "id:100500,phase:2,pass,t:none,nolog,ctl:ruleRemoveById=100501"
            SecRule ARGS "@rx attack" \
                "id:100501,phase:2,deny,t:none,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            detection_rule = next(rule for rule in parsed if rule.get("id") == "100501")
            controls, unsupported = TRANSLATOR.collect_rule_removal_controls(
                parsed, [detection_rule])
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-Werror", "-fsyntax-only",
                 "-I", str(out_dir), "-I", str(ROOT / "src"),
                 str(out_dir / "crs_tx_rules.c")],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(unsupported, [])
        self.assertEqual(controls[0]["target_rule_ids"], [100501])
        self.assertEqual(controls[0]["target_engine_indices"], [0])
        self.assertIn("lumina_tx_rule_remove_value_0", tx_source)
        self.assertIn("lumina_slab_mark(&state->disabled_rules, 0)", tx_source)
        self.assertEqual(manifest["rule_removal_controls"][0]["source_rule_id"], 100500)
        self.assertEqual(manifest["rule_removal_controls"][0]["target_rule_ids"], [100501])

    def test_rule_remove_target_by_tag_lowers_to_collection_local_slab(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_FILENAME "!@validateByteRange 45-47,48-57,65-90,95,97-122" \
                "id:100600,phase:1,pass,t:none,nolog,\
                ctl:ruleRemoveTargetByTag=fast-skip;REQUEST_FILENAME"
            SecRule REQUEST_FILENAME|ARGS "@rx attack" \
                "id:100601,phase:2,deny,t:none,tag:'fast-skip',severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            SecRule REQUEST_FILENAME "@rx second" \
                "id:100602,phase:2,deny,t:none,tag:'fast-skip',severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            detection = [
                rule for rule in parsed if rule.get("id") in {"100601", "100602"}
            ]
            controls, unsupported = (
                TRANSLATOR.collect_rule_target_removal_controls(parsed, detection))
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-Werror", "-fsyntax-only",
                 "-I", str(out_dir), "-I", str(ROOT / "src"),
                 str(out_dir / "crs_tx_rules.c")],
                check=True,
                capture_output=True,
                text=True,
            )

        self.assertEqual(unsupported, [])
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0]["target_engine_indices"], [0, 1])
        self.assertTrue(controls[0]["operator_negated"])
        self.assertEqual(controls[0]["target_collection_slot"], 10)
        self.assertIn("lumina_eval_target_controls", tx_source)
        self.assertIn("disabled_rule_targets[10]", tx_source)
        self.assertEqual(
            manifest["rule_target_removal_controls"][0]["target_rule_ids"],
            [100601, 100602],
        )

    def test_method_override_chain_uses_static_tx_and_private_value_dfa(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:allow_override "@eq 0" \
                "id:100012,phase:1,pass,nolog,setvar:'tx.allow_override=0'"
            SecRule TX:allow_override "@eq 0" \
                "id:100013,phase:2,deny,t:none,severity:'CRITICAL',chain"
                SecRule REQUEST_METHOD "!@streq %{ARGS._method}" \
                    "t:none,t:lowercase,chain"
                    SecRule ARGS:_method "@rx ^[a-z]{3,10}$" \
                        "t:none,t:urlDecodeUni,t:lowercase,"
                        "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100013")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(defaults["allow_override"], "0")
        self.assertEqual(descriptor["kind"], "request-method-override-parameter")
        self.assertIn("lumina_tx_method_override_parameter", tx_source)
        self.assertIn("lumina_tx_value_match_0", tx_source)
        self.assertNotIn("strstr", tx_source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "request-method-override-parameter")

    def test_argument_authority_chain_is_lowered_to_tagged_prefix_dfa(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx (?i)https?://(?:[^@]+@)?([^/]*)" \
                "id:100014,phase:2,deny,capture,t:none,severity:'CRITICAL',setvar:'tx.target=.%{tx.1}',chain"
                SecRule TX:/target/ "!@endsWith .%{request_headers.host}" \
                    "setvar:'tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            chain = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp)
            )[0]
            descriptor = TRANSLATOR.classify_transaction_chain(chain, {})
        self.assertEqual(descriptor["kind"], "arg-url-authority-off-domain")
        self.assertEqual(descriptor["suffix_header_mask"], TRANSLATOR.HEADER_MASKS["HOST"])
        self.assertTrue(descriptor["prefix_pattern"].endswith("(?:[^@]+@)?"))

    def test_header_capture_policy_preserves_full_static_tx_allowlist(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:allowed_charsets "@eq 0" \
                "id:100015,phase:1,pass,nolog,setvar:'tx.allowed_charsets=|utf-8| |iso-8859-1| |windows-1252|'"
            SecRule REQUEST_HEADERS:Content-Type "@rx charset\s*=\s*[\"']?([^;\"'\s]+)" \
                "id:100016,phase:1,deny,capture,t:none,severity:'CRITICAL',setvar:'tx.charset=|%{tx.1}|',chain"
                SecRule TX:charset "!@within %{tx.allowed_charsets}" \
                    "t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100016")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(defaults["allowed_charsets"],
                         "|utf-8| |iso-8859-1| |windows-1252|")
        self.assertEqual(descriptor["kind"],
                         "named-header-capture-not-within-static-tx")
        self.assertEqual(descriptor["capture_pattern"], r'''[^;\"'\s]+''')
        self.assertEqual(descriptor["value_prefix"], "|")
        self.assertEqual(descriptor["value_suffix"], "|")
        self.assertIn("lumina_tx_header_capture_not_within", tx_source)
        self.assertIn("lumina_tx_capture_prefix_0", tx_source)
        self.assertIn("lumina_tx_capture_value_0", tx_source)
        self.assertNotIn("strstr", tx_source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "named-header-capture-not-within-static-tx")

    def test_basename_capture_policy_applies_declared_transform_and_static_tx(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:blocked_suffixes "@eq 0" \
                "id:100036,phase:1,pass,nolog,setvar:'tx.blocked_suffixes=.bak/ .db/ .sql/'"
            SecRule REQUEST_BASENAME "@rx \.([^.]+)$" \
                "id:100037,phase:1,deny,capture,t:none,t:urlDecodeUni,severity:'CRITICAL',setvar:'tx.suffix=.%{tx.1}/',chain"
                SecRule TX:suffix "@within %{tx.blocked_suffixes}" \
                    "t:none,t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100037")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = out_dir / "crs_tx_rules.c"
            source = tx_source.read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(tx_source)],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(descriptor["kind"],
                         "request-basename-capture-within-static-tx")
        self.assertEqual(descriptor["prefix_pattern"], r"\.")
        self.assertEqual(descriptor["capture_pattern"], r"[^.]+$")
        self.assertEqual(descriptor["head_transforms"], ["urldecodeuni"])
        self.assertEqual(descriptor["allowed_value"], ".bak/ .db/ .sql/")
        self.assertIn("LUMINA_T_URL_DECODE_UNI", source)
        self.assertIn("lumina_tx_basename_capture_within", source)
        self.assertIn("lumina_tx_basename_capture_prefix_0", source)
        self.assertIn("lumina_tx_basename_capture_value_0", source)
        self.assertNotIn("100037 ==", source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "request-basename-capture-within-static-tx")

    def test_static_tx_gate_lowers_typed_utf8_validation(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:validate_utf8 "@eq 0" \
                "id:100038,phase:1,pass,nolog,setvar:'tx.validate_utf8=1'"
            SecRule TX:validate_utf8 "@eq 1" \
                "id:100039,phase:2,deny,t:none,severity:'WARNING',chain"
                SecRule REQUEST_FILENAME|ARGS|ARGS_NAMES "@validateUtf8Encoding" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100039")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = out_dir / "crs_tx_rules.c"
            source = tx_source.read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(tx_source)],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(descriptor["kind"], "static-tx-gated-utf8-validator")
        self.assertEqual(descriptor["collections"],
                         ["ARGS", "ARGS_NAMES", "REQUEST_FILENAME"])
        self.assertIn("lumina_tx_bundle_invalid_utf8", source)
        self.assertIn("b0 == 0xedu", source)
        self.assertNotIn("100039 ==", source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "static-tx-gated-utf8-validator")

    def test_reqbody_processor_chain_lowers_to_native_url_validator(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQBODY_PROCESSOR "@streq URLENCODED" \
                "id:100049,phase:2,deny,t:none,severity:'WARNING',chain"
                SecRule REQUEST_BODY "@rx \x25" "t:none,chain"
                    SecRule REQUEST_BODY "@validateUrlEncoding" \
                        "t:none,setvar:'tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "arbitrary-body-policy.conf").write_text(
                conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            chain = TRANSLATOR.group_rule_chains(parsed)[0]
            descriptor = TRANSLATOR.classify_transaction_chain(chain, {})
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = out_dir / "crs_tx_rules.c"
            source = tx_source.read_text(encoding="utf-8")
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(tx_source)],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(descriptor["kind"],
                         "request-body-processor-url-validator")
        self.assertEqual(descriptor["processor"], "URLENCODED")
        self.assertEqual(descriptor["body_precondition_pattern"], r"\x25")
        self.assertIn("lumina_tx_reqbody_processor_url_invalid", source)
        self.assertIn("lumina_tx_invalid_url_encoding", source)
        self.assertIn("lumina_tx_body_precondition_0", source)
        self.assertNotIn("100049 ==", source)
        self.assertNotIn("pcre", source.lower())
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "request-body-processor-url-validator")

    def test_header_whole_match_policy_lowers_tx_zero_to_tagged_dfa(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:allowed_media_types "@eq 0" \
                "id:100018,phase:1,pass,nolog,setvar:'tx.allowed_media_types=|application/json| |text/xml|'"
            SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\s]+" \
                "id:100019,phase:1,deny,capture,t:none,severity:'CRITICAL',setvar:'tx.media_type=|%{tx.0}|',chain"
                SecRule TX:media_type "!@within %{tx.allowed_media_types}" \
                    "t:lowercase,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100019")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(descriptor["kind"],
                         "named-header-match-not-within-static-tx")
        self.assertEqual(descriptor["match_pattern"], r"^[^;\s]+")
        self.assertEqual(descriptor["value_prefix"], "|")
        self.assertEqual(descriptor["value_suffix"], "|")
        self.assertIn("lumina_tx_header_match_not_within", tx_source)
        self.assertIn("lumina_tx_match_value_0", tx_source)
        self.assertNotIn("strstr", tx_source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "named-header-match-not-within-static-tx")

    def test_header_name_dynamic_tx_policy_is_folded_without_runtime_tx_map(self):
        conf = textwrap.dedent(
            r'''
            SecRule &TX:blocked_headers "@eq 0" \
                "id:100040,phase:1,pass,nolog,setvar:'tx.blocked_headers=/x-internal/ /x-override/'"
            SecRule REQUEST_HEADERS_NAMES "@rx ^.*$" \
                "id:100041,phase:1,deny,capture,t:none,t:lowercase,severity:'CRITICAL',setvar:'tx.seen_header_%{tx.0}=/%{tx.0}/',chain"
                SecRule TX:/^seen_header_/ "@within %{tx.blocked_headers}" \
                    "setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "arbitrary-policy.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            defaults = TRANSLATOR.collect_static_tx_values(parsed)
            chain = next(rule for rule in TRANSLATOR.group_rule_chains(parsed)
                         if rule.get("id") == "100041")
            descriptor = TRANSLATOR.classify_transaction_chain(chain, defaults)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = out_dir / "crs_tx_rules.c"
            source = tx_source.read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
            subprocess.run(
                ["cc", "-std=c11", "-fsyntax-only", "-I", str(ROOT / "src"),
                 "-I", str(out_dir), str(tx_source)],
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(descriptor["kind"],
                         "header-name-match-within-static-tx")
        self.assertTrue(descriptor["match_lowercase"])
        self.assertTrue(descriptor["lowercase_value"])
        self.assertEqual(descriptor["value_prefix"], "/")
        self.assertEqual(descriptor["value_suffix"], "/")
        self.assertEqual(descriptor["allowed_value"],
                         "/x-internal/ /x-override/")
        self.assertIn("lumina_tx_header_name_within", source)
        self.assertIn("var->name", source)
        self.assertIn("lumina_tx_header_name_match_0", source)
        self.assertNotIn("100041 ==", source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "header-name-match-within-static-tx")

    def test_multipart_header_producer_links_to_dynamic_tx_consumer(self):
        conf = textwrap.dedent(
            r'''
            SecRule MULTIPART_PART_HEADERS "@rx ^x-media\s*:\s*(.*)$" \
                "id:100020,phase:2,pass,capture,t:none,t:lowercase,nolog,setvar:'tx.part_media_%{tx.part_counter}=%{tx.1}'"
            SecRule TX:/PART_MEDIA_*/ "!@rx ^(?:application/json|text/plain)$" \
                "id:100021,phase:2,deny,capture,t:none,t:lowercase,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            producers = TRANSLATOR.collect_dynamic_tx_collection_producers(parsed)
            consumer = next(rule for rule in parsed if rule.get("id") == "100021")
            descriptor = TRANSLATOR.classify_transaction_chain(
                consumer, {}, producers)
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(len(producers), 1)
        self.assertEqual(descriptor["kind"],
                         "multipart-header-capture-negated-rx")
        self.assertEqual(descriptor["producer_capture_pattern"], r".*$")
        self.assertIn("lumina_tx_multipart_header_invalid", tx_source)
        self.assertIn("lumina_tx_multipart_value_positive_0", tx_source)
        self.assertNotIn("strstr", tx_source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "multipart-header-capture-negated-rx")

    def test_negated_named_header_dfa_reads_raw_value_with_declared_lowercase(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_HEADERS:Accept "!@rx ^(?:text/html|\*/\*)$" \
                "id:100017,phase:1,deny,t:none,t:lowercase,severity:'CRITICAL'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp) / "rules"
            out_dir = pathlib.Path(tmp) / "out"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(str(rules_dir))
            descriptor = TRANSLATOR.classify_whole_value_request_rule(parsed[0])
            subprocess.run(
                ["python3", str(TRANSLATOR_PATH), str(rules_dir), str(out_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            tx_source = (out_dir / "crs_tx_rules.c").read_text(encoding="utf-8")
            manifest = json.loads((out_dir / "generated" / "rule_manifest.json").read_text())
        self.assertEqual(descriptor["kind"], "named-header-negated-rx")
        self.assertTrue(descriptor["lowercase_value"])
        self.assertIn("lumina_tx_header_positive_0", tx_source)
        self.assertIn("input_byte >= 'A' && input_byte <= 'Z'", tx_source)
        self.assertEqual(manifest["generated_rules"][0]["transaction_kind"],
                         "named-header-negated-rx")

    def test_phrase_chain_uses_same_value_and_preserves_xml_boundaries(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS|XML:/* "@pmFromFile high-risk.data" \
                "id:100007,phase:2,deny,capture,t:none,severity:'CRITICAL',chain"
                SecRule MATCHED_VARS "@pm ( )" \
                    "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            parsed = TRANSLATOR.parse_conf_files(tmp)
            rule = TRANSLATOR.group_rule_chains(parsed)[0]
            self.assertIsNone(TRANSLATOR.same_buffer_phrase_chain_reason(rule))
            generated = TRANSLATOR.emit_same_buffer_phrase_chain(
                rule, ["base64_decode", "is_array"]
            )
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100007(const unsigned char *, size_t, size_t);
            int main(void) {
                const char *positive = "prefix BASE64_deCOde(foo)";
                const char *head_only = "base64_decode";
                const char *split_values = "<?xml version=\"1.0\"?><n a=\"base64_decode\">(</n>";
                const char *xml_name = "<?xml version=\"1.0\"?><base64_decode attr=\"()\">safe</base64_decode>";
                const char *xml_value = "<?xml version=\"1.0\"?><n a=\"is_array()\">safe</n>";
                if (lumina_scan_rule_100007((const unsigned char *)positive, strlen(positive), 0) != 100007) return 1;
                if (lumina_scan_rule_100007((const unsigned char *)head_only, strlen(head_only), 0) != 0) return 2;
                if (lumina_scan_rule_100007((const unsigned char *)positive, strlen(positive), 1) != 0) return 3;
                if (lumina_scan_rule_100007((const unsigned char *)split_values, strlen(split_values), 0) != 0) return 4;
                if (lumina_scan_rule_100007((const unsigned char *)xml_name, strlen(xml_name), 0) != 0) return 5;
                if (lumina_scan_rule_100007((const unsigned char *)xml_value, strlen(xml_value), 0) != 100007) return 6;
                return 0;
            }
            '''
            source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver
            src = pathlib.Path(tmp) / "phrase_chain.c"
            exe = pathlib.Path(tmp) / "phrase_chain"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_phrase_chain_composes_positive_and_negated_regex_children(self):
        conf = textwrap.dedent(
            r'''
            SecRule FILES|REQUEST_HEADERS:X-Upload "@pmFromFile restricted.data" \
                "id:100045,phase:2,deny,capture,t:none,t:removeWhitespace,severity:'CRITICAL',chain"
                SecRule MATCHED_VARS "@rx (?i)\bcommand\b" "t:none,chain"
                    SecRule MATCHED_VARS "!@rx (?i)\btrusted\b" \
                        "t:none,setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "custom.conf"
            path.write_text(conf, encoding="utf-8")
            rule = TRANSLATOR.group_rule_chains(
                TRANSLATOR.parse_conf_files(tmp)
            )[0]
            self.assertIsNone(TRANSLATOR.same_buffer_phrase_chain_reason(rule))
            generated = TRANSLATOR.emit_same_buffer_phrase_chain(
                rule, ["restricted"]
            )
            driver = r'''
            #include <stddef.h>
            #include <string.h>
            int lumina_scan_rule_100045(const unsigned char *, size_t, size_t);
            static int scan(const char *value, size_t offset) {
                return lumina_scan_rule_100045(
                    (const unsigned char *)value, strlen(value), offset);
            }
            int main(void) {
                if (scan("restricted command", 0) != 100045) return 1;
                if (scan("restricted command trusted", 0) != 0) return 2;
                if (scan("restricted payload", 0) != 0) return 3;
                if (scan("command only", 0) != 0) return 4;
                if (scan("restricted command", 1) != 0) return 5;
                return 0;
            }
            '''
            source = (
                "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
                generated + driver
            )
            src = pathlib.Path(tmp) / "phrase_rx_chain.c"
            exe = pathlib.Path(tmp) / "phrase_rx_chain"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_fixed_prefix_gap_uses_native_suffix_dfa(self):
        generated = TRANSLATOR.emit_gap_split_dfa(
            "100005", r"(?is)\r\n.*?\b(?:LIST|TOP) [0-9]+"
        )
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100005(const unsigned char *, size_t, size_t);
        int main(void) {
            const char *positive = "x\r\nfirst\nlist 3";
            const char *negative = "x list 3";
            if (lumina_scan_rule_100005((const unsigned char *)positive, strlen(positive), 1) != 100005) return 1;
            if (lumina_scan_rule_100005((const unsigned char *)negative, strlen(negative), 1) != 0) return 2;
            return 0;
        }
        '''
        source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "gap.c"
            exe = pathlib.Path(tmp) / "gap"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_nested_gap_is_not_split_as_top_level_prefix(self):
        with self.assertRaises(TRANSLATOR.DfaUnsupportedRegex):
            TRANSLATOR.emit_gap_split_dfa("100006", r"(?:prefix.*suffix)tail")

    def test_unanchored_dfa_is_lowered_to_one_linear_search(self):
        pattern, is_search = TRANSLATOR.dfa_search_lowering(
            r"(?i).(?:xlink:href|@import)\b"
        )
        self.assertTrue(is_search)
        selective, is_selective_search = TRANSLATOR.dfa_search_lowering(
            r"[.0-:A-Z_a-z]+\s*\(\)"
        )
        self.assertTrue(is_selective_search)
        self.assertTrue(selective.startswith(r"(?:[\x00-\xff]*)"))
        fixed, is_fixed_search = TRANSLATOR.dfa_search_lowering(r"needle.*suffix")
        self.assertFalse(is_fixed_search)
        self.assertEqual(fixed, r"needle.*suffix")
        anchored, is_anchored_search = TRANSLATOR.dfa_search_lowering(r"^fixed$")
        self.assertFalse(is_anchored_search)
        self.assertEqual(anchored, r"^fixed$")
        multiline, is_multiline_search = TRANSLATOR.dfa_search_lowering(r"(?m)^fixed$")
        self.assertTrue(is_multiline_search)
        absolute, is_absolute_search = TRANSLATOR.dfa_search_lowering(r"\Afixed$")
        self.assertFalse(is_absolute_search)
        self.assertEqual(absolute, r"\Afixed$")
        generated = TRANSLATOR.emit_dfa_c("100008", pattern)
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100008(const unsigned char *, size_t, size_t);
        int main(void) {
            const char *positive = "prefix <XLINK:HREF suffix";
            const char *negative = "prefix harmless suffix";
            if (lumina_scan_rule_100008((const unsigned char *)positive, strlen(positive), 0) != 100008) return 1;
            if (lumina_scan_rule_100008((const unsigned char *)negative, strlen(negative), 0) != 0) return 2;
            return 0;
        }
        '''
        source = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" + generated + driver
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "dfa_search.c"
            exe = pathlib.Path(tmp) / "dfa_search"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_oversized_concat_factors_prefix_and_branch_dfas(self):
        generated = TRANSLATOR.emit_factored_branch_concat_dfa(
            "100027",
            r"(?i)(?:foo|foobar)\s*(?:cat|dog)\b",
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        self.assertIn("lumina_factored_100027_suffix", generated)
        self.assertIn("lumina_factored_100027_shard_0", generated)
        self.assertNotIn("pcre", generated.lower())
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100027(const unsigned char *, size_t, size_t);
        int main(void) {
            const char *short_branch = "FOO cat ";
            const char *long_branch = "foobarDOG ";
            const char *bad_boundary = "foo catapult";
            const char *bad_suffix = "foobar fox ";
            if (lumina_scan_rule_100027((const unsigned char *)short_branch,
                                        strlen(short_branch), 0) != 100027) return 1;
            if (lumina_scan_rule_100027((const unsigned char *)long_branch,
                                        strlen(long_branch), 0) != 100027) return 2;
            if (lumina_scan_rule_100027((const unsigned char *)bad_boundary,
                                        strlen(bad_boundary), 0) != 0) return 3;
            if (lumina_scan_rule_100027((const unsigned char *)bad_suffix,
                                        strlen(bad_suffix), 0) != 0) return 4;
            return 0;
        }
        '''
        source = ("#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
                  generated + driver)
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "factored_dfa.c"
            exe = pathlib.Path(tmp) / "factored_dfa"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_recursive_factored_dag_shares_multiple_branch_continuations(self):
        pattern = r"(?i)^pre(?:alpha|beta)[0-9]+(?:cat|wolf)$"
        generated = TRANSLATOR.emit_recursive_factored_concat_dfa(
            "100046",
            pattern,
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        self.assertGreaterEqual(generated.count("lumina_recursive_100046_dispatch"), 2)
        self.assertNotIn("pcre", generated.lower())
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100046(const unsigned char *, size_t, size_t);
        static int scan(const char *value) {
            return lumina_scan_rule_100046(
                (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan("PREalpha42cat") != 100046) return 1;
            if (scan("prebeta7wolf") != 100046) return 2;
            if (scan("prealpha42fox") != 0) return 3;
            if (scan("xprebeta7wolf") != 0) return 4;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "recursive_factored_dfa.c"
            exe = pathlib.Path(tmp) / "recursive_factored_dfa"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)
        with self.assertRaises(TRANSLATOR.DfaUnsupportedRegex):
            TRANSLATOR.emit_recursive_factored_concat_dfa(
                "100047",
                pattern,
                state_budget=128,
                table_budget=64 * 1024,
                total_table_budget=1,
            )

    def test_recursive_factored_dag_searches_filtered_offsets_once(self):
        pattern = r"(?i).\|(?:cat|dog)(?:one|two)$"
        generated = TRANSLATOR.emit_recursive_factored_concat_dfa(
            "100048",
            pattern,
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        self.assertIn("lumina_recursive_100048_candidate_mask[2][4]", generated)
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100048(const unsigned char *, size_t, size_t);
        static int scan(const char *value) {
            return lumina_scan_rule_100048(
                (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan("prefix x|CATtwo") != 100048) return 1;
            if (scan("prefix x-CATtwo") != 0) return 2;
            if (scan("x|catthree") != 0) return 3;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "recursive_factored_search_dfa.c"
            exe = pathlib.Path(tmp) / "recursive_factored_search_dfa"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_top_level_alternative_router_preserves_exact_search_semantics(self):
        pattern = (r"(?:\beval\(|function\(\)\{|this\.constructor|"
                   r"process(?:\.env|\[))")
        generated = TRANSLATOR.emit_top_level_alternative_dfa_router(
            "100053",
            pattern,
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        self.assertEqual(generated.count("static int lumina_alt_100053_shard_"), 4)
        self.assertIn("lumina_alt_100053_route[256]", generated)
        self.assertNotIn("lumina_recursive_100053", generated)
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100053(const unsigned char *, size_t, size_t);
        static int scan_at(const char *value, size_t offset) {
            return lumina_scan_rule_100053(
                (const unsigned char *)value, strlen(value), offset);
        }
        int main(void) {
            if (scan_at("prefix eval(x)", 0) != 100053) return 1;
            if (scan_at("prefix xeval(x)", 0) != 0) return 2;
            if (scan_at("xxfunction(){", 2) != 100053) return 3;
            if (scan_at("xxfunction(){", 3) != 0) return 4;
            if (scan_at("this.constructor", 0) != 100053) return 5;
            if (scan_at("This.constructor", 0) != 0) return 6;
            if (scan_at("process.env", 0) != 100053) return 7;
            if (scan_at("process[", 0) != 100053) return 8;
            if (scan_at("process.env", strlen("process.env")) != 0) return 9;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "alternative_router.c"
            exe = pathlib.Path(tmp) / "alternative_router"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)
        with self.assertRaises(TRANSLATOR.DfaUnsupportedRegex):
            TRANSLATOR.emit_top_level_alternative_dfa_router(
                "100054", r"(?:alpha|beta|gamma|)")

    def test_terminal_alternation_uses_the_factored_dfa_backend(self):
        generated = TRANSLATOR.emit_factored_branch_concat_dfa(
            "100028",
            r"(?i)(?:foo|foobar)\s*(?:cat|dog)",
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        self.assertIn("lumina_factored_100028_suffix", generated)
        self.assertIn("lumina_factored_100028_shard_1", generated)
        self.assertIn("lumina_scan_rule_100028", generated)

    def test_crlf_command_grammar_emits_first_byte_routed_native_microkernel(self):
        pattern = (r"(?i)\r\n.*?\b(?:HELO[\s\x0b][\-\.a-z]{1,8}|"
                   r"MAIL[\s\x0b]FROM:<.{1,4}@.{1,8}>|"
                   r"R(?:SET\b|CPT[\s\x0b]TO:<.{1,4}>))")
        plan = TRANSLATOR.crlf_command_grammar_plan(pattern)
        self.assertIsNotNone(plan)
        generated = TRANSLATOR.emit_crlf_command_grammar("100049", pattern)
        self.assertIn("switch (route)", generated)
        self.assertIn("lumina_crlf_command_100049_", generated)
        self.assertNotIn("pcre", generated.lower())
        self.assertIsNone(TRANSLATOR.crlf_command_grammar_plan(
            r"(?is)\r\n.*?\b(?:HELO|MAIL)"))
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100049(const unsigned char *, size_t, size_t);
        static int scan(const char *value, size_t offset) {
            return lumina_scan_rule_100049(
                (const unsigned char *)value, strlen(value), offset);
        }
        int main(void) {
            if (scan("x\r\nprefix HELO foo.bar", 1) != 100049) return 1;
            if (scan("x\r\nMAIL FROM:<user@host>", 1) != 100049) return 2;
            if (scan("x\r\nRCPT TO:<user>", 1) != 100049) return 3;
            if (scan("x\r\nRSET ", 1) != 100049) return 4;
            if (scan("x\r\nxHELO foo", 1) != 0) return 5;
            if (scan("x\r\nRSETTING", 1) != 0) return 6;
            if (scan("x\r\nMAIL FROM:<user@host", 1) != 0) return 7;
            if (scan("x\r\nprefix\nHELO foo", 1) != 0) return 8;
            if (scan("x\r\nHELO foo", 0) != 0) return 9;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "crlf_command.c"
            exe = pathlib.Path(tmp) / "crlf_command"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_repeated_token_threshold_uses_one_linear_native_scan(self):
        pattern = (r"((?:(?:[!@]|\x{c2}\x{b4}|\x{e2}\x80[\x98\x99])"
                   r"[^!@]*?){3})")
        plan = TRANSLATOR.repeated_token_threshold_plan(pattern)
        self.assertIsNotNone(plan)
        self.assertEqual(plan["threshold"], 3)
        generated = TRANSLATOR.emit_repeated_token_threshold("100050", pattern)
        self.assertIn("lumina_token_threshold_100050_single", generated)
        self.assertNotIn("pcre", generated.lower())
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100050(const unsigned char *, size_t, size_t);
        static int scan(const unsigned char *value, size_t len) {
            return lumina_scan_rule_100050(value, len, 0);
        }
        int main(void) {
            const unsigned char ascii[] = "a!b@c!";
            const unsigned char unicode[] = {0xc2,0xb4,'x',0xe2,0x80,0x98,'y','@'};
            const unsigned char short_value[] = "a!b@";
            const unsigned char benign_utf8[] = {0xe4,0xbd,0xa0,0xe5,0xa5,0xbd};
            if (scan(ascii, sizeof(ascii)-1) != 100050) return 1;
            if (scan(unicode, sizeof(unicode)) != 100050) return 2;
            if (scan(short_value, sizeof(short_value)-1) != 0) return 3;
            if (scan(benign_utf8, sizeof(benign_utf8)) != 0) return 4;
            if (lumina_scan_rule_100050(ascii, sizeof(ascii)-1, 1) != 0) return 5;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "token_threshold.c"
            exe = pathlib.Path(tmp) / "token_threshold"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_generated_const_array_interning_shares_rodata_without_dispatch(self):
        chunks = [
            '''#include <stdint.h>\n
static const uint16_t first_transition[4] = {1, 2, 3, 4};
static const uint8_t first_unique[2] = {7, 8};
int first_value(unsigned index) { return first_transition[index]; }\n''',
            '''#include <stdint.h>\n
static const uint16_t second_transition[4] = {
    1, 2, 3, 4
};
int second_value(unsigned index) { return second_transition[index]; }\n''',
        ]
        rewritten, header, shared_source, stats = (
            TRANSLATOR.intern_generated_const_arrays(chunks, min_array_bytes=0))
        self.assertEqual(stats["shared_arrays"], 1)
        self.assertEqual(stats["replaced_arrays"], 2)
        self.assertEqual(stats["reclaimed_bytes"], 8)
        self.assertNotIn("first_transition", rewritten[0])
        self.assertNotIn("second_transition", rewritten[1])
        self.assertIn("first_unique", rewritten[0])
        self.assertIn('visibility("hidden")', header)
        self.assertNotIn("predicate_id", "".join(rewritten))

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            generated_dir = root / "generated"
            generated_dir.mkdir()
            (generated_dir / "crs_shared_tables.h").write_text(
                header, encoding="utf-8")
            sources = []
            for index, source_text in enumerate(rewritten):
                source = root / f"chunk_{index}.c"
                source.write_text(source_text, encoding="utf-8")
                sources.append(source)
            shared = root / "shared.c"
            shared.write_text(shared_source, encoding="utf-8")
            driver = root / "driver.c"
            driver.write_text(
                "int first_value(unsigned); int second_value(unsigned);\n"
                "int main(void) {\n"
                "    return first_value(2) == 3 && second_value(3) == 4 ? 0 : 1;\n"
                "}\n",
                encoding="utf-8",
            )
            executable = root / "interned"
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-fPIC", "-I", str(root),
                 *(str(source) for source in sources), str(shared), str(driver),
                 "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_shared_call_router_returns_fused_rule_mask(self):
        pattern_a = r"(?i)\b(?:foo|bar_baz)\s*\("
        pattern_b = r"(?i)\b(?:qux|foo)\s*\("
        self.assertEqual(
            TRANSLATOR.shared_call_dictionary_plan(pattern_a)["words"],
            (b"bar_baz", b"foo"),
        )
        rules = [
            {
                "id": "100101",
                "operator": "@rx",
                "pattern": pattern_a,
                "transforms": ["none"],
                "_fn": "old recursive forest",
            },
            {
                "id": "100102",
                "operator": "@rx",
                "pattern": pattern_b,
                "transforms": ["none"],
                "_fn": "old recursive forest",
            },
        ]
        stats = TRANSLATOR.lower_shared_call_routers(rules)
        self.assertEqual(stats["routers"], 1)
        self.assertEqual(stats["rules"], 2)
        self.assertEqual(
            [rule["_regex_backend"] for rule in rules],
            ["shared-seed-call-trie", "shared-seed-call-trie"],
        )
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            rules[0]["_fn"] + rules[1]["_fn"] +
            r'''
            int main(void) {
                const unsigned char both[] = "x foo (1); QUX(";
                const unsigned char boundary[] = "afoo(";
                const unsigned char clean[] = "football and quux";
                uint64_t mask = lumina_shared_call_router_0_match(
                    both, sizeof(both) - 1, 0, 3);
                if (mask != 3) return 1;
                if (lumina_shared_call_router_0_match(
                        both, sizeof(both) - 1, 0, 1) != 1)
                    return 6;
                if (lumina_scan_rule_100101(both, sizeof(both) - 1, 0) != 100101)
                    return 2;
                if (lumina_scan_rule_100102(both, sizeof(both) - 1, 0) != 100102)
                    return 3;
                if (lumina_shared_call_router_0_match(
                        boundary, sizeof(boundary) - 1, 0, 3) != 0)
                    return 4;
                if (lumina_shared_call_router_0_match(
                        clean, sizeof(clean) - 1, 0, 3) != 0)
                    return 5;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "shared_call_router.c"
            exe = pathlib.Path(tmp) / "shared_call_router"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_shared_call_router_rejects_unbounded_dictionary_language(self):
        self.assertIsNone(
            TRANSLATOR.shared_call_dictionary_plan(
                r"(?i)\b(?:foo.*bar|baz)\s*\("))

    def test_standalone_call_trie_preserves_case_sensitive_search(self):
        pattern = (
            r"(?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|"
            r"w(?:atch|rite))[\s\x0b]*\(")
        plan = TRANSLATOR.shared_call_dictionary_plan(pattern)
        self.assertFalse(plan["ignore_case"])
        self.assertFalse(plan["start_boundary"])
        self.assertTrue(TRANSLATOR.standalone_call_dictionary_profitable(plan))
        self.assertEqual(
            plan["words"],
            (b"close", b"exists", b"fork", b"open", b"read", b"require",
             b"spawn", b"watch", b"write"),
        )
        rule = {"id": "934101"}
        router, wrappers, _, _ = TRANSLATOR.emit_shared_call_trie_router(
            [(rule, plan)], "rule_934101")
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            router + wrappers["934101"] +
            r'''
            int main(void) {
                const unsigned char direct[] = "spawn(";
                const unsigned char whitespace[] = "prefix require\v \t(";
                const unsigned char no_boundary[] = "disclose(";
                const unsigned char wrong_case[] = "Close(";
                const unsigned char wrong_suffix[] = "closex(";
                if (lumina_scan_rule_934101(
                        direct, sizeof(direct) - 1, 0) != 934101) return 1;
                if (lumina_scan_rule_934101(
                        whitespace, sizeof(whitespace) - 1, 0) != 934101) return 2;
                if (lumina_scan_rule_934101(
                        no_boundary, sizeof(no_boundary) - 1, 0) != 934101) return 3;
                if (lumina_scan_rule_934101(
                        wrong_case, sizeof(wrong_case) - 1, 0) != 0) return 4;
                if (lumina_scan_rule_934101(
                        wrong_suffix, sizeof(wrong_suffix) - 1, 0) != 0) return 5;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "standalone_call_trie.c"
            exe = pathlib.Path(tmp) / "standalone_call_trie"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_shared_dictionary_router_assignment_continuation(self):
        pattern = r"(?i)\b(?:allow_url_fopen|memory_limit)\s*=[^=]"
        plan = TRANSLATOR.shared_call_dictionary_plan(pattern)
        self.assertEqual(plan["continuation"], "ASSIGN_NON_EQ")
        self.assertEqual(
            plan["words"],
            (b"allow_url_fopen", b"memory_limit"),
        )
        rule = {"id": "100103"}
        router, wrappers, _, _ = TRANSLATOR.emit_shared_call_trie_router(
            [(rule, plan)], 0)
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            router + wrappers["100103"] +
            r'''
            int main(void) {
                const unsigned char direct[] = "memory_limit=1";
                const unsigned char spaced[] = "ALLOW_URL_FOPEN \t=0";
                const unsigned char compare[] = "memory_limit==1";
                const unsigned char missing[] = "memory_limit=";
                const unsigned char boundary[] = "xmemory_limit=1";
                if (lumina_scan_rule_100103(
                        direct, sizeof(direct) - 1, 0) != 100103)
                    return 1;
                if (lumina_scan_rule_100103(
                        spaced, sizeof(spaced) - 1, 0) != 100103)
                    return 2;
                if (lumina_scan_rule_100103(
                        compare, sizeof(compare) - 1, 0) != 0)
                    return 3;
                if (lumina_scan_rule_100103(
                        missing, sizeof(missing) - 1, 0) != 0)
                    return 4;
                if (lumina_scan_rule_100103(
                        boundary, sizeof(boundary) - 1, 0) != 0)
                    return 5;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "shared_assignment_router.c"
            exe = pathlib.Path(tmp) / "shared_assignment_router"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_fixed_mask_dictionary_preserves_wildcard_semantics(self):
        alternatives = [f"name{index:03d}" for index in range(256)]
        alternatives.append("foo.bar")
        pattern = (
            r"(?i)\b(?:" + "|".join(alternatives) + r")\s*=[^=]")
        plan = TRANSLATOR.fixed_mask_dictionary_plan(pattern)
        self.assertIsNotNone(plan)
        self.assertEqual(len(plan["patterns"]), 257)
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            TRANSLATOR.emit_fixed_mask_dictionary("100104", plan) +
            r'''
            int main(void) {
                const unsigned char wildcard[] = "FOOxBAR =1";
                const unsigned char dot[] = "foo.bar=0";
                const unsigned char newline[] = "foo\nbar=1";
                const unsigned char compare[] = "fooXbar==1";
                const unsigned char boundary[] = "xfooXbar=1";
                if (lumina_scan_rule_100104(
                        wildcard, sizeof(wildcard) - 1, 0) != 100104)
                    return 1;
                if (lumina_scan_rule_100104(
                        dot, sizeof(dot) - 1, 0) != 100104)
                    return 2;
                if (lumina_scan_rule_100104(
                        newline, sizeof(newline) - 1, 0) != 0)
                    return 3;
                if (lumina_scan_rule_100104(
                        compare, sizeof(compare) - 1, 0) != 0)
                    return 4;
                if (lumina_scan_rule_100104(
                        boundary, sizeof(boundary) - 1, 0) != 0)
                    return 5;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "fixed_mask_dictionary.c"
            exe = pathlib.Path(tmp) / "fixed_mask_dictionary"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_scheme_host_classifier_preserves_ssrf_structure(self):
        rules = TRANSLATOR.parse_conf_files(
            ROOT / "tests" / "eval_suite" / "coreruleset" / "rules")
        rule = next(rule for rule in rules if str(rule.get("id")) == "934120")
        plan = TRANSLATOR.scheme_host_classifier_plan(rule["pattern"])
        self.assertIsNotNone(plan)
        self.assertEqual(len(plan["schemes"]), 106)
        self.assertEqual(len(plan["host_branches"]), 9)
        source = (
            "#include <stdbool.h>\n#include <stdint.h>\n"
            "#include <stddef.h>\n#include <string.h>\n" +
            TRANSLATOR.emit_scheme_host_classifier("934120", plan) +
            r'''
            static int scan(const char *value, size_t offset) {
                return lumina_scan_rule_934120(
                    (const unsigned char *)value, strlen(value), offset);
            }
            int main(void) {
                if (scan("http://2852039166/", 0) != 934120) return 1;
                if (scan("HtTp://0xA9.0xFE.0xA9.0xFE/", 0) != 934120) return 2;
                if (scan("dict:0xA9FEA9FE/", 0) != 934120) return 3;
                if (scan("gopher:/0251.00376.000251.0000376/", 0) != 934120)
                    return 4;
                if (scan("http://[::ffff:127.0.0.1]", 0) != 934120) return 5;
                if (scan("http://example.com", 0) != 0) return 6;
                if (scan("xhttp://2852039166/", 0) != 0) return 7;
                if (scan("xhttp://2852039166/", 1) != 934120) return 8;
                if (scan("http:/123456", 0) != 0) return 9;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "scheme_host_classifier.c"
            exe = pathlib.Path(tmp) / "scheme_host_classifier"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_fixed_mask_suffix_prefilter_preserves_assertions(self):
        commands = [rf"cmd{index:03d}\b" for index in range(256)]
        pattern = (
            r"(?i)(?:^|;)\s*(?:" + "|".join(commands) + ")")
        plan = TRANSLATOR.fixed_mask_suffix_prefilter_plan(pattern)
        self.assertIsNotNone(plan)
        self.assertEqual(plan["continuation"], "MATCH")
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            TRANSLATOR.emit_fixed_mask_dictionary(
                "100105", plan,
                function_name="suffix_prefilter",
                symbol_prefix="suffix_prefilter_tables",
                match_value=1,
                static_function=False,
            ) +
            r'''
            int main(void) {
                const unsigned char command[] = "prefix; CMD042 ";
                const unsigned char longer[] = "cmd042x";
                if (!suffix_prefilter(command, sizeof(command) - 1, 0))
                    return 1;
                if (suffix_prefilter(longer, sizeof(longer) - 1, 0))
                    return 2;
                return 0;
            }
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "fixed_mask_suffix.c"
            exe = pathlib.Path(tmp) / "fixed_mask_suffix"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_compact_prefix_dfa_delegates_to_anchored_fixed_suffix(self):
        commands = [rf"cmd{index:03d}\b" for index in range(256)]
        pattern = (
            r"(?i)(?:^|;)\s*(?:" + "|".join(commands) + ")")
        suffix_plan = TRANSLATOR.fixed_mask_suffix_prefilter_plan(pattern)
        self.assertIsNotNone(suffix_plan)
        plan = TRANSLATOR.compact_prefix_fixed_suffix_plan(
            pattern, suffix_plan,
            state_budget=1024,
            table_budget=256 * 1024,
            minimum_row_savings=1.0,
        )
        self.assertIsNotNone(plan)
        self.assertLess(
            plan["compact_table_bytes"], plan["raw_table_bytes"])
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n" +
            TRANSLATOR.emit_compact_prefix_fixed_suffix_dfa(
                "100106", pattern, plan,
                state_budget=1024,
                table_budget=256 * 1024,
            ) +
            r'''
            int main(void) {
                const unsigned char start[] = "CMD042 ";
                const unsigned char separator[] = "prefix; cmd255\t";
                const unsigned char no_prefix[] = "prefix cmd042 ";
                const unsigned char longer[] = "; cmd042x";
                if (lumina_scan_rule_100106(
                        start, sizeof(start) - 1, 0) != 100106)
                    return 1;
                if (lumina_scan_rule_100106(
                        separator, sizeof(separator) - 1, 0) != 100106)
                    return 2;
                if (lumina_scan_rule_100106(
                        no_prefix, sizeof(no_prefix) - 1, 0) != 0)
                    return 3;
                if (lumina_scan_rule_100106(
                        longer, sizeof(longer) - 1, 0) != 0)
                    return 4;
                return 0;
            }
            '''
        )
        self.assertIn("_transition_row", source)
        self.assertIn("_accept_row", source)
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "compact_prefix_suffix.c"
            exe = pathlib.Path(tmp) / "compact_prefix_suffix"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)


if __name__ == "__main__":
    unittest.main()
