#!/usr/bin/env python3
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from regex_dfa import (bitset_nfa_match, compile_bitset_nfa, compile_dfa,
                       compile_dfa_ast,
                       compile_mandatory_seed_cover,
                       compile_seeded_fast_accept_branches, dfa_match,
                       emit_bitset_nfa_c, emit_dfa_c, parse_regex_ast,
                       requires_dfa)


class RegexDfaCompilerTest(unittest.TestCase):
    def test_parsed_ast_fragment_compiles_with_identical_flags(self):
        pattern = r"(?i)ab+c"
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
        direct = compile_dfa(pattern)
        fragment = compile_dfa_ast(ast, ignore_case, dot_all)
        for value in ("abc", "ABBC", "ac", "abbd"):
            self.assertEqual(dfa_match(direct, value), dfa_match(fragment, value))

    def test_greedy_suffix_is_determinized(self):
        self.assertTrue(requires_dfa(r"a.*b"))
        dfa = compile_dfa(r"a.*b")
        self.assertGreaterEqual(dfa["state_count"], 3)
        self.assertLess(dfa["class_count"], 8)
        self.assertTrue(dfa_match(dfa, "axxxb"))
        self.assertFalse(dfa_match(dfa, "axxxc"))
        self.assertIn("lumina_scan_rule_123", emit_dfa_c(123, r"a.*b"))

    def test_terminal_optional_nested_alternation_is_determinized(self):
        pattern = r"(?:phar|ssh2(?:.(?:shell|exec|tunnel))?)://"
        self.assertTrue(requires_dfa(pattern))
        dfa = compile_dfa(pattern)
        self.assertTrue(dfa_match(dfa, "phar://"))
        self.assertTrue(dfa_match(dfa, "ssh2.shell://"))
        self.assertTrue(dfa_match(dfa, "ssh2.exec://"))
        self.assertFalse(dfa_match(dfa, "ssh2.invalid://"))

    def test_private_matcher_symbols_support_chain_composition(self):
        generated = emit_dfa_c(
            123,
            r"(?:[\x00-\xff]*)(?:needle)",
            function_name="chain_member_0",
            symbol_prefix="chain_member_0_dfa",
            match_value=1,
            static_function=True,
        )
        self.assertIn("static int chain_member_0", generated)
        self.assertIn("return 1;", generated)
        self.assertNotIn("lumina_scan_rule_123", generated)

    def test_accept_delegate_composes_deterministic_fragments(self):
        ast, ignore_case, dot_all = parse_regex_ast(r"ab+")
        dfa = compile_dfa_ast(ast, ignore_case, dot_all)
        generated = emit_dfa_c(
            128, None, compiled_dfa=dfa,
            function_name="factored_prefix", accept_delegate="factored_suffix",
        )
        self.assertIn("factored_suffix(data, len, pos)", generated)
        self.assertIn("factored_suffix(data, len, len)", generated)

    def test_tristate_accept_delegate_can_stop_after_parent_match(self):
        generated = emit_dfa_c(
            129,
            r"^prefix",
            function_name="terminal_prefix",
            accept_delegate_tristate="terminal_capture_child",
        )
        self.assertIn("int delegated = terminal_capture_child(data, len, pos)", generated)
        self.assertIn("if (delegated > 0) return 129", generated)
        self.assertIn("if (delegated < 0) return 0", generated)

    def test_tagged_prefix_reports_longest_accepted_end(self):
        generated = emit_dfa_c(
            124,
            r"(?i)https?://(?:[^@]+@)?",
            function_name="capture_prefix",
            symbol_prefix="capture_prefix_dfa",
            match_value=1,
            static_function=True,
            report_match_end=True,
            longest_match_end=True,
        )
        self.assertIn("size_t *match_end", generated)
        self.assertIn("accepted_end = pos", generated)
        self.assertIn("*match_end = accepted_end", generated)

    def test_generated_matcher_stops_after_reaching_dead_state_by_default(self):
        generated = emit_dfa_c(
            125,
            r"charset\s*=\s*[\"']?",
            function_name="capture_prefix",
            symbol_prefix="capture_prefix_dfa",
            match_value=1,
            static_function=True,
            report_match_end=True,
            longest_match_end=True,
        )
        self.assertRegex(generated, r"if \(state == \d+u\) break;")

    def test_generated_matcher_can_disable_dead_state_termination(self):
        generated = emit_dfa_c(
            127,
            r"^ab$",
            stop_on_dead=False,
        )
        self.assertNotRegex(generated, r"if \(state == \d+u\) break;")

    def test_generated_dfa_can_apply_ascii_lowercase_at_input_boundary(self):
        generated = emit_dfa_c(
            126,
            r"^utf-8$",
            ascii_lower_input=True,
        )
        self.assertIn("input_byte >= 'A' && input_byte <= 'Z'", generated)
        self.assertIn("_class[input_byte]", generated)

    def test_generated_dfa_can_intern_repeated_transition_and_accept_rows(self):
        generated = emit_dfa_c(
            130,
            r"(?:ab|ac|db|dc)",
            intern_transition_rows=True,
            intern_accept_rows=True,
        )
        self.assertIn("lumina_dfa_130_transition_row", generated)
        self.assertIn("lumina_dfa_130_accept_row", generated)
        self.assertIn("lumina_dfa_130_eof_row", generated)
        self.assertIn(
            "lumina_dfa_130_transition_row[state] *", generated)

    def test_multiword_bitset_nfa_matches_dfa_at_mid_buffer_and_eof(self):
        pattern = r"\b[a-z]{40}\b"
        dfa = compile_dfa(pattern)
        nfa = compile_bitset_nfa(pattern)
        self.assertGreater(nfa["word_count"], 1)
        values = (
            "a" * 40,
            "a" * 40 + " ",
            "a" * 39,
            "x" + "a" * 40,
            "a" * 40 + "x",
        )
        for value in values:
            self.assertEqual(
                dfa_match(dfa, value),
                bitset_nfa_match(nfa, value),
                value,
            )

    def test_bitset_nfa_interns_vectors_and_supports_private_symbols(self):
        generated = emit_bitset_nfa_c(
            131,
            r"(?:[\x00-\xff]*)(?:needle\b)",
            function_name="chain_nfa",
            symbol_prefix="chain_nfa_data",
            match_value=1,
            static_function=True,
        )
        self.assertIn("static int chain_nfa", generated)
        self.assertIn("chain_nfa_data_transition_id", generated)
        self.assertIn("chain_nfa_data_vector", generated)
        self.assertIn("chain_nfa_data_source", generated)
        self.assertIn("active[word] & source[word]", generated)
        self.assertIn("return 1;", generated)
        self.assertNotIn("lumina_scan_rule_131", generated)

    def test_seeded_fast_accept_selects_only_mandatory_branch_literals(self):
        pattern = r"(?i)(?:prefix(?:optional)?suffix|select.+from|space\s*\()"
        plans = compile_seeded_fast_accept_branches(pattern)
        selected = {
            plan["alternative_index"]: plan["seed"] for plan in plans
        }
        self.assertIn(selected[0], (b"prefix", b"suffix"))
        self.assertEqual(selected[1], b"select")
        self.assertEqual(selected[2], b"space")
        self.assertNotIn(b"optional", selected.values())

        optional_only = r"(?i)(?:a(?:needle)?z|xy)"
        self.assertEqual(
            compile_seeded_fast_accept_branches(optional_only),
            [],
        )

    def test_mandatory_seed_cover_requires_every_alternative(self):
        pattern = (
            r"(?i)(?:,[^)]*[0-9]+|,[^)]*[a-f]+|"
            r"[^a-z]select.+from|(?:alter|drop)\s*\(\s*space\s*\()")
        cover = compile_mandatory_seed_cover(pattern)
        self.assertEqual(cover["seeds"], (b",", b"select", b"space"))
        self.assertTrue(cover["ignore_case"])
        self.assertIsNone(
            compile_mandatory_seed_cover(r"(?:prefix|[0-9]+)"))

    def test_bitset_nfa_emits_seeded_exact_fast_accept_before_fallback(self):
        branch_pattern = r"(?i)(?:select.+from|space\s*\(|a(?:needle)?z)"
        search_pattern = r"(?:[\x00-\xff]*)(?:" + branch_pattern + ")"
        plans = compile_seeded_fast_accept_branches(branch_pattern)
        cover = compile_mandatory_seed_cover(branch_pattern)
        generated = emit_bitset_nfa_c(
            132,
            search_pattern,
            function_name="seeded_chain_nfa",
            symbol_prefix="seeded_chain_nfa_data",
            match_value=1,
            static_function=True,
            fast_accept_plan=plans,
            mandatory_seed_cover=cover,
        )
        self.assertIn("mandatory_seed_present", generated)
        self.assertIn("if (!seeded_chain_nfa_data_mandatory_seed_present", generated)
        self.assertIn("seed_checked", generated)
        self.assertIn("seed_candidates", generated)
        self.assertIn("seeded_chain_nfa_data_fast_0", generated)
        self.assertIn("seeded_chain_nfa_data_transition_id", generated)

    def test_word_boundary_builds_context_symbols(self):
        dfa = compile_dfa(r"\bcmd\b")
        self.assertGreater(dfa["symbol_count"], dfa["class_count"])
        self.assertTrue(dfa_match(dfa, "cmd "))
        self.assertFalse(dfa_match(dfa, "cmdx"))

    def test_case_insensitive_classes_collapse(self):
        dfa = compile_dfa(r"(?i)abc")
        self.assertEqual(dfa["byte_class"][ord("a")], dfa["byte_class"][ord("A")])
        self.assertTrue(dfa_match(dfa, "ABC"))

    def test_combined_inline_flags_enable_casefold_and_dotall(self):
        dfa = compile_dfa(r"(?is)\r\n.*\bLIST [0-9]+")
        self.assertTrue(dfa_match(dfa, b"\r\nfirst\nlist 3"))
        self.assertFalse(dfa_match(dfa, b"\r\nfirst\nlisting 3"))

    def test_windows_for_rule_shape(self):
        pattern = r"\b(?:for(?:/[dflr].*)? %+[^ ]+ in\(.*\)[\s\x0b]?do|if(?:/i)?(?: not)?(?: (?:e(?:xist|rrorlevel)|defined|cmdextversion)\b|[ \(].*(?:\b(?:g(?:eq|tr)|equ|neq|l(?:eq|ss))\b|==)))"
        dfa = compile_dfa(pattern)
        self.assertTrue(dfa_match(dfa, "for %variable in(set) do command"))
        self.assertTrue(dfa_match(dfa, "for/f %variable in(fileset) do command"))
        self.assertFalse(dfa_match(dfa, "ordinary request value"))


if __name__ == "__main__":
    unittest.main()
