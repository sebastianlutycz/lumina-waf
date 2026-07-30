#!/usr/bin/env python3
import importlib.util
import itertools
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

    def test_dfa_viable_prefix_pairs_rejects_impossible_pair(self):
        pairs = TRANSLATOR.dfa_viable_prefix_pairs(r"(?i)(?:and|select)")
        self.assertIsNotNone(pairs)
        self.assertIn((ord("a") << 8) | ord("n"), pairs)
        self.assertIn((ord("S") << 8) | ord("E"), pairs)
        self.assertNotIn((ord("a") << 8) | ord("a"), pairs)

    def test_dfa_viable_prefix_pairs_keeps_suffix_after_short_match(self):
        pairs = TRANSLATOR.dfa_viable_prefix_pairs(r"a|bc")
        self.assertIsNotNone(pairs)
        for second in range(256):
            self.assertIn((ord("a") << 8) | second, pairs)
        self.assertIn((ord("b") << 8) | ord("c"), pairs)
        self.assertNotIn((ord("b") << 8) | ord("b"), pairs)

    def test_dfa_viable_prefix_pairs_declines_nonselective_dfa(self):
        self.assertIsNone(
            TRANSLATOR.dfa_viable_prefix_pairs(r"[\x00-\xff]*foo")
        )

    def test_alphabet_requirement_gate_never_rejects_matching_value(self):
        def possible(plan, value):
            observed = 0
            for byte in value.encode("latin1"):
                observed |= 1 << byte
            return any(
                all(requirement & observed for requirement in alternative)
                for alternative in plan["alternatives"]
            )

        patterns = (
            r"(?:ab|c[de])f",
            r"(?i)(?:select|union)",
            r"a+b?c",
            r"\bcat(?:alog|erpillar)\b",
            r"(?:x{2,4}|y[^z])",
        )
        alphabet = "abcdfuxyZ"
        values = [character for character in alphabet]
        for _ in range(3):
            values.extend(
                prefix + character
                for prefix in tuple(values)
                for character in alphabet
                if len(prefix) < 4
            )
        for pattern in patterns:
            plan = TRANSLATOR.compile_alphabet_requirement_dnf(pattern)
            self.assertIsNotNone(plan, pattern)
            expression = re.compile(pattern)
            for value in values:
                if expression.search(value):
                    self.assertTrue(possible(plan, value), (pattern, value))

        selective = TRANSLATOR.compile_alphabet_requirement_dnf(
            r"(?i)(?:select|union)"
        )
        self.assertFalse(possible(selective, "catalog"))
        self.assertTrue(possible(selective, "SELECT"))
        self.assertIsNone(
            TRANSLATOR.compile_alphabet_requirement_dnf(r"(?:required)?")
        )

    def test_shared_seed_gate_routes_necessary_fragments_without_false_negative(self):
        gate = TRANSLATOR.build_shared_seed_gate(
            (
                (0, (b"select", b"union")),
                (1, (b"cat", b"dog")),
                (2, (b"ab",)),
            ),
            rule_count=3,
            mask_words=2,
        )

        def possible(value):
            observed = [0, 0]

            def add(class_id):
                if class_id:
                    words = gate["output_classes"][class_id]
                    observed[0] |= words[0]
                    observed[1] |= words[1]

            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            for index, byte in enumerate(lowered):
                add(gate["byte_classes"][byte])
                if index >= 1:
                    add(gate["pair_classes"][
                        (lowered[index - 1] << 8) | byte
                    ])
                if index >= 2:
                    key = (
                        (lowered[index - 2] << 16)
                        | (lowered[index - 1] << 8)
                        | byte
                    )
                    bloom_bit = (key * 2246822519) & 0xffff
                    if not (
                        gate["triple_bloom"][bloom_bit >> 6]
                        & (1 << (bloom_bit & 63))
                    ):
                        continue
                    slot = (key * 2654435761) & (
                        len(gate["triple_keys"]) - 1
                    )
                    while gate["triple_keys"][slot] not in (0, key + 1):
                        slot = (slot + 1) & (
                            len(gate["triple_keys"]) - 1
                        )
                    if gate["triple_keys"][slot] == key + 1:
                        add(gate["triple_classes"][slot])
            return observed[0]

        self.assertEqual(possible(b"catalog") & 0b001, 0)
        self.assertNotEqual(possible(b"SELECT") & 0b001, 0)
        self.assertNotEqual(possible(b"catalog") & 0b010, 0)
        self.assertNotEqual(possible(b"xxabyy") & 0b100, 0)
        self.assertEqual(possible(b"zzzz") & 0b111, 0)
        for stored_key in gate["triple_keys"]:
            if stored_key == 0:
                continue
            key = stored_key - 1
            bloom_bit = (key * 2246822519) & 0xffff
            self.assertNotEqual(
                gate["triple_bloom"][bloom_bit >> 6]
                & (1 << (bloom_bit & 63)),
                0,
            )

    def test_contextual_seed_gate_preserves_required_next_byte_class(self):
        separator = (1 << ord(" ")) | (1 << ord(";")) | (1 << ord("/"))

        def masks(value, next_mask):
            return tuple(1 << byte for byte in value) + (next_mask,)

        gate = TRANSLATOR.build_contextual_seed_gate(
            (
                (0, {
                    "patterns": (
                        masks(b"cat", separator),
                        masks(b"wget", separator),
                    ),
                }),
                (1, {"patterns": (masks(b"x", separator),)}),
            ),
            rule_count=2,
            mask_words=2,
        )

        def possible(value):
            observed = [0, 0]
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )

            def add(row_id, next_byte):
                if not row_id:
                    return
                class_id = gate["next_rows"][row_id][next_byte]
                if not class_id:
                    return
                words = gate["output_classes"][class_id]
                observed[0] |= words[0]
                observed[1] |= words[1]

            for index in range(len(lowered) - 1):
                next_byte = lowered[index + 1]
                add(gate["byte_rows"][lowered[index]], next_byte)
                if index >= 1:
                    pair = (lowered[index - 1] << 8) | lowered[index]
                    add(gate["pair_rows"][pair], next_byte)
                if index >= 2:
                    key = (
                        (lowered[index - 2] << 16)
                        | (lowered[index - 1] << 8)
                        | lowered[index]
                    )
                    bloom_bit = (key * 2246822519) & 0xffff
                    if not (
                        gate["triple_bloom"][bloom_bit >> 6]
                        & (1 << (bloom_bit & 63))
                    ):
                        continue
                    slot = (key * 2654435761) & (
                        len(gate["triple_keys"]) - 1
                    )
                    while gate["triple_keys"][slot] not in (0, key + 1):
                        slot = (slot + 1) & (
                            len(gate["triple_keys"]) - 1
                        )
                    if gate["triple_keys"][slot] == key + 1:
                        add(gate["triple_rows"][slot], next_byte)
            return observed[0]

        self.assertEqual(possible(b"catalog") & 0b01, 0)
        self.assertNotEqual(possible(b"CAT;") & 0b01, 0)
        self.assertNotEqual(possible(b"wget ") & 0b01, 0)
        self.assertEqual(possible(b"example") & 0b10, 0)
        self.assertNotEqual(possible(b"x/") & 0b10, 0)
        self.assertEqual(gate["rule_count"], 2)
        self.assertEqual(gate["witness_count"], 3)

    def test_combined_seed_proof_ac_matches_independent_gate_semantics(self):
        separator = (1 << ord(" ")) | (1 << ord(";")) | (1 << ord("/"))

        def masks(value, next_mask):
            return tuple(1 << byte for byte in value) + (next_mask,)

        shared = TRANSLATOR.build_shared_seed_gate(
            (
                (0, (b"cat", b"at")),
                (1, (b"wget", b"x")),
            ),
            rule_count=2,
            mask_words=2,
        )
        contextual = TRANSLATOR.build_contextual_seed_gate(
            (
                (0, {"patterns": (masks(b"cat", separator),)}),
                (1, {"patterns": (masks(b"at", separator),)}),
            ),
            rule_count=2,
            mask_words=2,
        )
        ac = TRANSLATOR.build_combined_seed_proof_ac(
            shared, contextual, mask_words=2)

        def expected(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            shared_words = [0, 0]
            context_words = [0, 0]
            for fragment, words in shared["fragment_rules"].items():
                if fragment in lowered:
                    for word in range(2):
                        shared_words[word] |= words[word]
            for (length, key), next_rules in contextual[
                    "key_next_rules"].items():
                pattern = key.to_bytes(length, "big")
                for start in range(len(lowered) - length):
                    if lowered[start:start + length] != pattern:
                        continue
                    words = next_rules[lowered[start + length]]
                    for word in range(2):
                        context_words[word] |= words[word]
            return shared_words, context_words

        def observed(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            shared_words = [0, 0]
            context_words = [0, 0]
            state = 0
            for index, byte in enumerate(lowered):
                class_id = ac["byte_classes"][byte]
                state = ac["transitions"][
                    state * ac["class_count"] + class_id
                ]
                output = ac["shared_classes"][state]
                for word in range(2):
                    shared_words[word] |= ac["output_classes"][output][word]
                if index + 1 < len(lowered):
                    row = ac["context_rows"][state]
                    output = ac["next_rows"][row][lowered[index + 1]]
                    for word in range(2):
                        context_words[word] |= ac["output_classes"][output][word]
            return shared_words, context_words

        alphabet = b"cAtx;/ "
        values = [b"", b"CAT;", b"xxcat/", b"catalog", b"WGET x/"]
        for length in range(1, 6):
            values.extend(bytes(value) for value in itertools.product(
                alphabet, repeat=length))
        for value in values:
            self.assertEqual(observed(value), expected(value), value)

    def test_extended_seed_proof_ac_preserves_long_witness_semantics(self):
        separator = (1 << ord(" ")) | (1 << ord(";")) | (1 << ord("/"))

        def masks(value, next_mask):
            return tuple(1 << byte for byte in value) + (next_mask,)

        shared_rule_sets = (
            (0, (b"command", b"execute")),
            (1, (b"select", b"union")),
        )
        contextual_plans = (
            (0, {
                "patterns": (
                    masks(b"wget", separator),
                    masks(b"command", separator),
                ),
            }),
            (1, {"patterns": (masks(b"execute", separator),)}),
        )
        shared = TRANSLATOR.build_extended_shared_seed_patterns(
            shared_rule_sets, mask_words=2, max_fragment_length=5)
        contextual = TRANSLATOR.build_extended_contextual_seed_patterns(
            contextual_plans, mask_words=2, max_literal_length=5)
        ac = TRANSLATOR.build_combined_seed_proof_ac(
            shared, contextual, mask_words=2)

        self.assertTrue(any(
            len(pattern) == 5 for pattern in shared["fragment_rules"]))
        self.assertTrue(any(
            length == 5 for length, _ in contextual["key_next_rules"]))
        self.assertEqual(shared["rule_count"], 2)
        self.assertEqual(contextual["rule_count"], 2)
        self.assertEqual(contextual["witness_count"], 3)

        def direct(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            shared_words = [0, 0]
            context_words = [0, 0]
            for fragment, words in shared["fragment_rules"].items():
                if fragment in lowered:
                    for word in range(2):
                        shared_words[word] |= words[word]
            for (length, key), next_rules in contextual[
                    "key_next_rules"].items():
                pattern = key.to_bytes(length, "big")
                for start in range(len(lowered) - length):
                    if lowered[start:start + length] != pattern:
                        continue
                    words = next_rules[lowered[start + length]]
                    for word in range(2):
                        context_words[word] |= words[word]
            return shared_words, context_words

        def observed(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            shared_words = [0, 0]
            context_words = [0, 0]
            state = 0
            for index, byte in enumerate(lowered):
                state = ac["transitions"][
                    state * ac["class_count"]
                    + ac["byte_classes"][byte]
                ]
                shared_output = ac["shared_classes"][state]
                for word in range(2):
                    shared_words[word] |= ac[
                        "output_classes"][shared_output][word]
                if index + 1 >= len(lowered):
                    continue
                row = ac["context_rows"][state]
                context_output = ac["next_rows"][row][lowered[index + 1]]
                for word in range(2):
                    context_words[word] |= ac[
                        "output_classes"][context_output][word]
            return shared_words, context_words

        values = (
            b"",
            b"comm",
            b"command/",
            b"COMMAND;",
            b"wget ",
            b"execute/",
            b"select",
            b"union",
            b"xxcommandyyexecute zz",
        )
        for value in values:
            self.assertEqual(observed(value), direct(value), value)

    def test_segmented_seed_proof_ac_matches_scalar_boundaries(self):
        separator = (1 << ord(" ")) | (1 << ord(";")) | (1 << ord("/"))

        def masks(value, next_mask):
            return tuple(1 << byte for byte in value) + (next_mask,)

        shared = TRANSLATOR.build_extended_shared_seed_patterns(
            (
                (0, (b"abcde", b"cde")),
                (1, (b"vwxyz", b"xy")),
            ),
            mask_words=1,
            max_fragment_length=5,
        )
        contextual = TRANSLATOR.build_extended_contextual_seed_patterns(
            (
                (0, {"patterns": (masks(b"abcde", separator),)}),
                (1, {"patterns": (masks(b"vwxyz", separator),)}),
            ),
            mask_words=1,
            max_literal_length=5,
        )
        ac = TRANSLATOR.build_combined_seed_proof_ac(
            shared, contextual, mask_words=1)
        self.assertEqual(ac["max_pattern_length"], 5)
        emitted = TRANSLATOR.emit_combined_seed_proof_ac(ac, mask_words=1)
        self.assertIn("SEGMENT_MIN_LEN = 4096", emitted)
        self.assertIn("MAX_SEED_LENGTH = 5", emitted)
        self.assertIn(
            "LUMINA_ENABLE_EXPERIMENTAL_SEGMENT_LOCAL_ACCUMULATORS",
            emitted)
        self.assertIn("segment_observed_bytes[4][4]", emitted)
        self.assertIn("segment_observed_shared[4][1]", emitted)
        self.assertIn("segment_observed_context[4][1]", emitted)
        request_body_emitted = TRANSLATOR.emit_combined_seed_proof_ac(
            ac, mask_words=1,
            function_name="lumina_classify_request_body_seed_proofs_ac")
        self.assertIn(
            "void lumina_classify_request_body_seed_proofs_ac(",
            request_body_emitted)
        self.assertNotIn(
            "void lumina_classify_seed_proofs_ac(",
            request_body_emitted)
        with self.assertRaisesRegex(ValueError, "invalid.*function name"):
            TRANSLATOR.emit_combined_seed_proof_ac(
                ac, mask_words=1, function_name="invalid-name")

        def scan_ranges(value, ranges):
            observed_bytes = 0
            shared_words = 0
            context_words = 0
            final_state = 0
            for start, end, is_final in ranges:
                state = 0
                for index in range(start, end):
                    raw = value[index]
                    observed_bytes |= 1 << raw
                    folded = (
                        raw | 0x20
                        if ord("A") <= raw <= ord("Z")
                        else raw
                    )
                    state = ac["transitions"][
                        state * ac["class_count"]
                        + ac["byte_classes"][folded]
                    ]
                    output = ac["shared_classes"][state]
                    shared_words |= ac["output_classes"][output][0]
                    if index + 1 < len(value):
                        row = ac["context_rows"][state]
                        next_byte = value[index + 1]
                        if ord("A") <= next_byte <= ord("Z"):
                            next_byte |= 0x20
                        output = ac["next_rows"][row][next_byte]
                        context_words |= ac["output_classes"][output][0]
                if is_final:
                    final_state = state
            if value and ac["context_width"] == 257:
                row = ac["context_rows"][final_state]
                output = ac["next_rows"][row][256]
                context_words |= ac["output_classes"][output][0]
            return observed_bytes, shared_words, context_words

        for length in (64, 65, 127, 128, 129):
            value = bytearray(b"q" * length)
            boundaries = (length // 4, length // 2, (length // 4) * 3)
            patterns = (b"abcde;", b"VWXYZ/", b"abcde ")
            for boundary, pattern in zip(boundaries, patterns):
                start = boundary - 2
                value[start:start + len(pattern)] = pattern
            value = bytes(value)
            scalar = scan_ranges(value, ((0, length, True),))
            overlap = ac["max_pattern_length"] - 1
            segmented = scan_ranges(value, (
                (0, boundaries[0], False),
                (boundaries[0] - overlap, boundaries[1], False),
                (boundaries[1] - overlap, boundaries[2], False),
                (boundaries[2] - overlap, length, True),
            ))
            self.assertEqual(segmented, scalar, length)

    def test_extended_contextual_seed_proof_preserves_assertions(self):
        def masks(value, assertion):
            return tuple(1 << byte for byte in value) + (assertion,)

        contextual = TRANSLATOR.build_extended_contextual_seed_patterns(
            (
                (0, {"patterns": (masks(b"dd", -1),)}),
                (1, {"patterns": (masks(b"x", -4),)}),
                (2, {"patterns": (masks(b"zz", -2),)}),
            ),
            mask_words=1,
            max_literal_length=5,
        )
        ac = TRANSLATOR.build_combined_seed_proof_ac(
            {"fragment_rules": {}, "rule_mask": [0]},
            contextual,
            mask_words=1,
        )
        self.assertEqual(ac["context_width"], 257)

        def observed(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            state = 0
            words = 0
            for index, byte in enumerate(lowered):
                state = ac["transitions"][
                    state * ac["class_count"]
                    + ac["byte_classes"][byte]
                ]
                row = ac["context_rows"][state]
                if index + 1 < len(lowered):
                    output = ac["next_rows"][row][lowered[index + 1]]
                    words |= ac["output_classes"][output][0]
            if lowered:
                row = ac["context_rows"][state]
                output = ac["next_rows"][row][256]
                words |= ac["output_classes"][output][0]
            return words

        self.assertEqual(observed(b"ddq") & 0b001, 0)
        self.assertNotEqual(observed(b"dd ") & 0b001, 0)
        self.assertNotEqual(observed(b"dd") & 0b001, 0)
        self.assertEqual(observed(b"xq") & 0b010, 0)
        self.assertNotEqual(observed(b"x") & 0b010, 0)
        self.assertNotEqual(observed(b"zzq") & 0b100, 0)
        self.assertEqual(observed(b"zz ") & 0b100, 0)
        self.assertEqual(observed(b"zz") & 0b100, 0)

    def test_contextual_refinement_correlates_position_and_alphabet(self):
        letters = sum(
            1 << byte for byte in range(ord("a"), ord("z") + 1))

        def masks(value, *suffix):
            return tuple(1 << byte for byte in value) + suffix

        contextual = TRANSLATOR.build_extended_contextual_seed_patterns(
            (
                (0, {
                    "patterns": (
                        masks(b"gcc", letters, -1),
                        masks(b"addgroup", -1),
                    ),
                }),
            ),
            mask_words=1,
            max_literal_length=5,
        )

        def possible(value):
            lowered = bytes(
                byte | 0x20 if ord("A") <= byte <= ord("Z") else byte
                for byte in value
            )
            observed = 0
            for byte in lowered:
                observed |= 1 << byte
            proven = set()

            def is_word(byte):
                return (
                    ord("0") <= byte <= ord("9")
                    or ord("a") <= byte <= ord("z")
                    or byte == ord("_")
                )

            for (length, key), rows in contextual[
                    "key_next_alternatives"].items():
                pattern = key.to_bytes(length, "big")
                start = 0
                while True:
                    position = lowered.find(pattern, start)
                    if position < 0:
                        break
                    context_at = position + length
                    context = (
                        lowered[context_at]
                        if context_at < len(lowered)
                        else 256
                    )
                    for alternative in rows[context]:
                        candidate = (
                            position
                            - contextual["alternative_seed_offsets"][
                                alternative]
                        )
                        if candidate < 0:
                            continue
                        assertion_ok = True
                        for token, offset in contextual[
                                "alternative_assertions"][alternative]:
                            assertion_at = candidate + offset
                            if assertion_at > len(lowered):
                                assertion_ok = False
                                break
                            previous_word = (
                                assertion_at > 0
                                and is_word(lowered[assertion_at - 1])
                            )
                            current_word = (
                                assertion_at < len(lowered)
                                and is_word(lowered[assertion_at])
                            )
                            if token == -1:
                                current_ok = previous_word != current_word
                            elif token == -2:
                                current_ok = previous_word == current_word
                            elif token == -3:
                                current_ok = assertion_at == 0
                            else:
                                current_ok = assertion_at == len(lowered)
                            if not current_ok:
                                assertion_ok = False
                                break
                        if assertion_ok:
                            proven.add(alternative)
                    start = position + 1
            return any(
                all(
                    observed & requirement
                    for requirement in contextual[
                        "alternative_requirements"][alternative]
                )
                for alternative in proven
            )

        self.assertFalse(possible(b"gccjqq"))
        self.assertTrue(possible(b"gccj"))
        self.assertFalse(possible(b"dddgccjqq"))
        self.assertTrue(possible(b"xxaddgroup yy"))

    def test_prefix4_gate_rejects_only_absorbing_dead_prefixes(self):
        generated = TRANSLATOR.emit_dfa_c(
            "100080",
            r"(?i)(?:and|select)",
            emit_prefix4_gate=True,
        )
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100080(const unsigned char *, size_t, size_t);
        int lumina_prefix4_rule_100080(const unsigned char *, size_t, size_t);
        int main(void) {
            const char *dead = "catalog";
            const char *and_value = "andx";
            const char *select_value = "SELECT";
            if (lumina_prefix4_rule_100080(
                    (const unsigned char *)dead, strlen(dead), 0) != 0) return 1;
            if (lumina_scan_rule_100080(
                    (const unsigned char *)dead, strlen(dead), 0) != 0) return 2;
            if (lumina_prefix4_rule_100080(
                    (const unsigned char *)and_value, strlen(and_value), 0) != 1) return 3;
            if (lumina_scan_rule_100080(
                    (const unsigned char *)and_value, strlen(and_value), 0) != 100080) return 4;
            if (lumina_prefix4_rule_100080(
                    (const unsigned char *)select_value, strlen(select_value), 0) != 1) return 5;
            if (lumina_scan_rule_100080(
                    (const unsigned char *)select_value, strlen(select_value), 0) != 100080) return 6;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "prefix4.c"
            exe = pathlib.Path(tmp) / "prefix4"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_incremental_multimatch_views_match_cumulative_replay(self):
        driver = r'''
        #include <stdint.h>
        #include <stdlib.h>
        #include <string.h>

        #include "lumina_transforms.h"

        enum { CAPACITY = 1 << 18 };
        static uint8_t old_view[CAPACITY];
        static uint8_t incremental_view[CAPACITY];

        static int compare_chain(const uint8_t *input, size_t input_len,
                                 const LuminaTransformId *chain) {
            memcpy(incremental_view, input, input_len);
            size_t incremental_len = input_len;
            for (int stage = 0; stage < 11 &&
                                chain[stage] != LUMINA_T_NONE; stage++) {
                LuminaTransformId cumulative[12];
                LuminaTransformId step[2] = {
                    chain[stage], LUMINA_T_NONE
                };
                for (int i = 0; i <= stage; i++) cumulative[i] = chain[i];
                cumulative[stage + 1] = LUMINA_T_NONE;

                memcpy(old_view, input, input_len);
                size_t old_len = lumina_apply_transforms(
                    cumulative, old_view, input_len);
                incremental_len = lumina_apply_transforms(
                    step, incremental_view, incremental_len);
                if (old_len != incremental_len ||
                    memcmp(old_view, incremental_view, old_len) != 0)
                    return stage + 1;
            }
            return 0;
        }

        int main(void) {
            static const LuminaTransformId chain_934100[] = {
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_JS_DECODE,
                LUMINA_T_REMOVE_WS,
                LUMINA_T_BASE64_DECODE,
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_JS_DECODE,
                LUMINA_T_REMOVE_WS,
                LUMINA_T_NONE
            };
            static const LuminaTransformId chain_cmdline[] = {
                LUMINA_T_UTF8_TO_UNICODE,
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_REMOVE_NULLS,
                LUMINA_T_CMDLINE,
                LUMINA_T_NONE
            };
            static const uint8_t encoded[] =
                "ZnVuY3Rpb24lMjglMjklN0IlNUN4NjFsZXJ0JTI4MSUyOSU3RA==";
            static const uint8_t command[] =
                "FOR%20%20/F%20%25V%20IN%20(SET),;%20DO%20C%5EM%5C%22D";
            static uint8_t clean[128 * 1024];
            static uint8_t binary[4096];

            memset(clean, 'a', sizeof(clean));
            for (size_t i = 0; i < sizeof(binary); i++)
                binary[i] = (uint8_t)((i * 73u + 19u) & 0xffu);

            if (compare_chain(clean, sizeof(clean), chain_934100) != 0)
                return 1;
            if (compare_chain(encoded, sizeof(encoded) - 1, chain_934100) != 0)
                return 2;
            if (compare_chain(binary, sizeof(binary), chain_934100) != 0)
                return 3;
            if (compare_chain(command, sizeof(command) - 1, chain_cmdline) != 0)
                return 4;
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "incremental_multimatch.c"
            exe = pathlib.Path(tmp) / "incremental_multimatch"
            src.write_text(driver, encoding="utf-8")
            subprocess.run(
                [
                    "cc", "-std=c11", "-O2",
                    "-I", str(ROOT / "src"),
                    str(src), str(ROOT / "src" / "lumina_transforms.c"),
                    "-o", str(exe),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_transform_features_track_every_materialized_prefix(self):
        driver = r'''
        #include <stdint.h>
        #include <stdlib.h>
        #include <string.h>

        #include "lumina_transforms.h"

        enum { CAPACITY = 1 << 18 };
        static uint8_t reference_view[CAPACITY];
        static uint8_t feature_view[CAPACITY];

        static void classify(
                const uint8_t *data, size_t len, uint64_t observed[4]) {
            memset(observed, 0, sizeof(uint64_t) * 4);
            for (size_t i = 0; i < len; ++i)
                observed[data[i] >> 6] |= UINT64_C(1) << (data[i] & 63);
        }

        static int compare_chain(const uint8_t *input, size_t input_len,
                                 const LuminaTransformId *chain) {
            uint64_t observed[4];
            LuminaTransformFeatures features;
            classify(input, input_len, observed);
            lumina_transform_features_init(&features, observed);
            memcpy(reference_view, input, input_len);
            memcpy(feature_view, input, input_len);
            size_t reference_len = input_len;
            size_t feature_len = input_len;

            for (int stage = 0; stage < 11 &&
                                chain[stage] != LUMINA_T_NONE; ++stage) {
                int possible = lumina_transform_features_may_change(
                    &features, chain[stage]);
                uint8_t before[CAPACITY];
                memcpy(before, reference_view, reference_len);
                size_t before_len = reference_len;
                reference_len = lumina_apply_transform_step(
                    chain[stage], reference_view, reference_len);
                if (!possible &&
                    (reference_len != before_len ||
                     memcmp(reference_view, before, reference_len) != 0))
                    return 10 + stage;

                feature_len = lumina_apply_transform_step_features(
                    chain[stage], feature_view, feature_len, &features);
                if (feature_len != reference_len ||
                    memcmp(feature_view, reference_view, feature_len) != 0)
                    return 30 + stage;

                classify(feature_view, feature_len, observed);
                if (features.known &&
                    memcmp(features.observed_bytes, observed,
                           sizeof(observed)) != 0)
                    return 50 + stage;
                if (!features.known &&
                    !lumina_transform_features_may_change(
                        &features, LUMINA_T_URL_DECODE_UNI))
                    return 70 + stage;
            }
            return 0;
        }

        int main(void) {
            static const LuminaTransformId chain_934100[] = {
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_JS_DECODE,
                LUMINA_T_REMOVE_WS,
                LUMINA_T_BASE64_DECODE,
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_JS_DECODE,
                LUMINA_T_REMOVE_WS,
                LUMINA_T_NONE
            };
            static const LuminaTransformId chain_text[] = {
                LUMINA_T_LOWERCASE,
                LUMINA_T_HTML_ENTITY_DECODE,
                LUMINA_T_REMOVE_NULLS,
                LUMINA_T_COMPRESS_WS,
                LUMINA_T_REPLACE_COMMENTS,
                LUMINA_T_NONE
            };
            static const uint8_t encoded[] =
                "ZnVuY3Rpb24lMjglMjklN0IlNUN4NjFsZXJ0JTI4MSUyOSU3RA==";
            static const uint8_t escaped[] =
                "A%20B\\x43 &amp; D /* comment */";
            static uint8_t random_data[4096];
            uint32_t state = UINT32_C(0x934100);

            for (size_t i = 0; i < sizeof(random_data); ++i) {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                random_data[i] = (uint8_t)state;
            }
            if (compare_chain(encoded, sizeof(encoded) - 1,
                              chain_934100) != 0)
                return 1;
            if (compare_chain(escaped, sizeof(escaped) - 1,
                              chain_text) != 0)
                return 2;
            if (compare_chain(random_data, sizeof(random_data),
                              chain_934100) != 0)
                return 3;
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "transform_features.c"
            exe = pathlib.Path(tmp) / "transform_features"
            src.write_text(driver, encoding="utf-8")
            subprocess.run(
                [
                    "cc", "-std=c11", "-O2",
                    "-I", str(ROOT / "src"),
                    str(src), str(ROOT / "src" / "lumina_transforms.c"),
                    "-o", str(exe),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_multimatch_equal_length_skip_contract(self):
        driver = r'''
        #include <stdint.h>
        #include <stdlib.h>
        #include <string.h>

        #include "lumina_transforms.h"

        enum { CAPACITY = 4096 };
        static uint8_t original[CAPACITY];
        static uint8_t transformed[CAPACITY];

        static int may_change_at_equal_length(LuminaTransformId transform) {
            switch (transform) {
            case LUMINA_T_LOWERCASE:
            case LUMINA_T_URL_DECODE:
            case LUMINA_T_URL_DECODE_UNI:
            case LUMINA_T_COMPRESS_WS:
            case LUMINA_T_NORMALIZE_PATH:
            case LUMINA_T_NORMALIZE_PATH_WIN:
            case LUMINA_T_CMDLINE:
            case LUMINA_T_LENGTH:
                return 1;
            default:
                return 0;
            }
        }

        static int verify(const uint8_t *input, size_t len,
                          LuminaTransformId transform) {
            LuminaTransformId step[2] = {transform, LUMINA_T_NONE};
            memcpy(original, input, len);
            memcpy(transformed, input, len);
            size_t output_len =
                lumina_apply_transforms(step, transformed, len);
            if (!may_change_at_equal_length(transform) &&
                output_len == len &&
                memcmp(original, transformed, len) != 0)
                return 0;
            return 1;
        }

        int main(void) {
            static const LuminaTransformId safe[] = {
                LUMINA_T_REMOVE_NULLS,
                LUMINA_T_URL_DECODE,
                LUMINA_T_URL_DECODE_UNI,
                LUMINA_T_HTML_ENTITY_DECODE,
                LUMINA_T_JS_DECODE,
                LUMINA_T_CSS_DECODE,
                LUMINA_T_REMOVE_WS,
                LUMINA_T_REPLACE_COMMENTS,
                LUMINA_T_UTF8_TO_UNICODE,
                LUMINA_T_ESCAPE_SEQ_DECODE,
                LUMINA_T_BASE64_DECODE,
                LUMINA_T_REMOVE_COMMENTS_CHAR
            };
            static const char *edge_cases[] = {
                "plain ASCII value",
                "%41%u0042%zz",
                "\\x41\\u0042\\q",
                "&amp;&#65;&bogus;",
                "/* comment */ <!-- x -->",
                "YWxlcnQoMSk=",
                "a b\tc\r\nd",
                "\\41 bc",
                "../a/./b",
                "\xC3\xB3"
            };
            uint32_t state = UINT32_C(0x9e3779b9);

            for (size_t transform = 0;
                 transform < sizeof(safe) / sizeof(safe[0]);
                 ++transform) {
                for (size_t edge = 0;
                     edge < sizeof(edge_cases) / sizeof(edge_cases[0]);
                     ++edge) {
                    size_t len = strlen(edge_cases[edge]);
                    if (!verify((const uint8_t *)edge_cases[edge], len,
                                safe[transform]))
                        return 1;
                }
                for (size_t round = 0; round < 2000; ++round) {
                    size_t len = 1u + (round % 257u);
                    for (size_t i = 0; i < len; ++i) {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        original[i] = (uint8_t)state;
                    }
                    if (!verify(original, len, safe[transform]))
                        return 10 + (int)transform;
                }
            }
            return 0;
        }
        '''
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "multimatch_equal_length.c"
            exe = pathlib.Path(tmp) / "multimatch_equal_length"
            src.write_text(driver, encoding="utf-8")
            subprocess.run(
                [
                    "cc", "-std=c11", "-O2",
                    "-I", str(ROOT / "src"),
                    str(src), str(ROOT / "src" / "lumina_transforms.c"),
                    "-o", str(exe),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_mandatory_seed_probe_selects_one_sound_byte_per_alternative(self):
        rule = {
            "operator": "@rx",
            "pattern": r"(?i)(?:<script|javascript:)",
            "negated": False,
        }
        self.assertEqual(
            TRANSLATOR.mandatory_seed_probe_bytes(rule),
            (ord(":"), ord("<")),
        )

    def test_mandatory_seed_probe_rejects_unsafe_rule_shapes(self):
        base = {"operator": "@rx", "pattern": "required", "negated": False}
        self.assertEqual(
            TRANSLATOR.mandatory_seed_probe_bytes({**base, "negated": True}),
            (),
        )
        self.assertEqual(
            TRANSLATOR.mandatory_seed_probe_bytes(
                {**base, "_chain_members": [{"operator": "@rx"}]}
            ),
            (),
        )

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

    def test_native_collection_rules_are_not_generic_dispatched(self):
        conf = textwrap.dedent(
            r'''
            SecRule REQUEST_COOKIES:/\x22?\x24Version/ "@streq 1" \
                "id:921250,phase:1,deny,t:none,t:lowercase,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+5'"
            SecRule MULTIPART_PART_HEADERS "@rx content-transfer-encoding:(.*)" \
                "id:922120,phase:2,deny,t:none,t:lowercase,severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+5'"
            SecRule MULTIPART_PART_HEADERS "@rx [^\x21-\x7E][\x21-\x39\x3B-\x7E]*:" \
                "id:922130,phase:2,deny,t:none,t:lowercase,severity:'CRITICAL',\
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
                check=True,
                capture_output=True,
                text=True,
            )
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text(
                    encoding="utf-8"
                )
            )

        self.assertTrue({921250, 922120, 922130}.issubset(
            set(manifest["runtime_covered_rule_ids"])))
        self.assertTrue({921250, 922120, 922130}.isdisjoint(
            set(manifest["generated_rule_ids"])))

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
        self.assertIn("input->observed_bytes[data[i] >> 6]", dispatch_source)
        self.assertIn("g_transform_sequence_dirty_by_byte[byte]", dispatch_source)
        self.assertNotIn(
            "g_transform_sequence_dirty_by_byte[data[i]]",
            dispatch_source,
        )
        self.assertIn("LuminaTransformDispatchWorkspace", dispatch_source)
        self.assertIn("__attribute__((noinline)) LuminaTransformDispatchWorkspace", dispatch_source)
        self.assertIn("lumina_acquire_transform_dispatch_workspace()", dispatch_source)
        self.assertIn("workspace->input.valid = 0", dispatch_source)
        self.assertIn("&workspace->input, sequence_id, data, len", dispatch_source)
        self.assertNotIn("g_transform_input_class", dispatch_source)

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

    def test_percent_hex_pair_search_is_exact_and_whole_value(self):
        pattern = r"%[0-9a-fA-F]{2}"
        self.assertIsNotNone(
            TRANSLATOR.percent_hex_pair_search_plan(pattern))
        self.assertIsNone(
            TRANSLATOR.percent_hex_pair_search_plan(r"%[0-9a-fA-F]{1,2}"))
        self.assertIsNone(
            TRANSLATOR.percent_hex_pair_search_plan(r"%[0-9a-fA-G]{2}"))
        generated = TRANSLATOR.emit_percent_hex_pair_search(920230, pattern)
        self.assertIn("if (offset != 0 || len < 3) return 0;", generated)
        self.assertIn("for (size_t pos = 0; pos + 2 < len; ++pos)", generated)
        self.assertIn("return 920230;", generated)

    def test_multimatch_prefix_dag_requires_exact_crs_sequences(self):
        rules = [
            {
                "id": int(rule_id),
                "multimatch": True,
                "transforms": list(transforms),
            }
            for rule_id, transforms in
            TRANSLATOR.MULTIMATCH_PREFIX_DAG_EXPECTED.items()
        ]
        plan = TRANSLATOR.multimatch_prefix_dag_plan(rules)
        self.assertEqual(
            plan, {"934100": 0, "934160": 1, "934101": 2})
        rules[1]["transforms"] = rules[1]["transforms"][:-1]
        self.assertIsNone(TRANSLATOR.multimatch_prefix_dag_plan(rules))

    def test_generated_shared_base64_cache_is_sequence_guarded(self):
        source = (
            ROOT / "src" / "parser_rules_0000.c").read_text(encoding="utf-8")
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn(
            "LUMINA_9341XX_SHARED_BASE64", cmake)
        self.assertIn(
            "LUMINA_ENABLE_9341XX_SHARED_BASE64", source)
        self.assertIn(
            "lumina_apply_multimatch_step_shared_base64", source)
        self.assertIn(
            "lumina_dispatch_multimatch_shared_base64_long", source)
        self.assertIn(
            "int lumina_dispatch_rule_long(",
            source)
        self.assertIn(
            'section(".lumina_long_text")',
            source)
        self.assertIn(
            "offset == 0 && input_len >= 4096u && view_len == input_len",
            source)
        self.assertIn(
            "!*prefix_changed && lumina_is_9341xx_shared_base64_rule(idx)",
            source)
        self.assertIn(
            "workspace->multimatch_base64.valid = 0;", source)
        self.assertNotIn(
            "if (cache_slot == 7u) workspace->multimatch_base64.valid = 0;",
            source)
        self.assertIn(
            '#error "The 9341xx shared-Base64 cache and prefix DAG use the '
            'same scratch slots"',
            source)

        manifest = json.loads(
            (ROOT / "src" / "generated" / "rule_manifest.json").read_text(
                encoding="utf-8"))
        family_indices = {
            rule["engine_idx"]
            for rule in manifest["generated_rules"]
            if rule["rule_id"] in {934100, 934160, 934101}
        }
        self.assertEqual(len(family_indices), 3)
        transform_source = (
            ROOT / "src" / "generated" / "crs_transform_mask.c"
        ).read_text(encoding="utf-8")
        sequence_ids = {
            int(index): int(sequence_id)
            for index, sequence_id in re.findall(
                r"/\* \[(\d+)\] CRS \d+ \*/ (\d+),",
                transform_source,
            )
        }
        first = min(family_indices)
        last = max(family_indices)
        for index in range(first, last + 1):
            if index not in family_indices:
                self.assertNotEqual(sequence_ids[index] & 7, 7)

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

    def test_offset_zero_transform_prefers_linear_search_dfa_for_9411xx_shapes(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx (?i).(?:\b(?:(?:x(?:link:href|html|mlns)|data:text/html|formaction)\b|pattern[\s\x0b]*=)|(?:!ENTITY[\s\x0b]+(?:%[\s\x0b]+)?[^\s\x0b]+[\s\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\b)" \
                "id:100008,phase:2,deny,t:none,t:utf8toUnicode,t:urlDecodeUni,\
                t:htmlEntityDecode,t:jsDecode,t:cssDecode,t:removeNulls,\
                severity:'CRITICAL',\
                setvar:'tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}'"
            SecRule ARGS "@rx (?i)[a-z]+=(?:[^:=]+:[^;]+;)*?[^:=]+:url\(javascript" \
                "id:100009,phase:2,deny,t:none,t:utf8toUnicode,t:urlDecodeUni,\
                t:removeWhitespace,severity:'CRITICAL',\
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
            manifest = json.loads(
                (out_dir / "generated" / "rule_manifest.json").read_text()
            )
            source = "\n".join(
                path.read_text(encoding="utf-8")
                for path in sorted(out_dir.glob("parser_rules_*.c"))
            )
        self.assertEqual(
            {
                rule["rule_id"]: rule["regex_backend"]
                for rule in manifest["generated_rules"]
            },
            {
                100008: "dfa-transform-search",
                100009: "dfa-transform-search",
            },
        )
        self.assertIn("lumina_dfa_100008_transition", source)
        self.assertIn("lumina_dfa_100009_transition", source)
        self.assertNotIn("lumina_recursive_100008", source)
        self.assertNotIn("lumina_recursive_100009", source)

    def test_transformed_all_offset_dfas_use_one_full_view_search(self):
        manifest = json.loads(
            (ROOT / "src" / "generated" / "rule_manifest.json").read_text(
                encoding="utf-8"))
        backends = {
            rule["rule_id"]: (
                rule.get("regex_backend"),
                rule.get("transform_search_mode"),
            )
            for rule in manifest["generated_rules"]
            if rule.get("rule_id") in {
                942190, 942360, 942180, 942330, 942362,
            }
        }
        self.assertEqual(
            backends,
            {
                942190: (
                    "dfa-transform-all-offset-search",
                    "full-view-all-offsets"),
                942360: (
                    "dfa-transform-all-offset-search",
                    "full-view-all-offsets"),
                942180: (
                    "dfa-transform-all-offset-search",
                    "full-view-all-offsets"),
                942330: (
                    "dfa-transform-all-offset-search",
                    "full-view-all-offsets"),
                942362: (
                    "dfa-transform-all-offset-search",
                    "full-view-all-offsets"),
            },
        )
        dispatch_source = (
            ROOT / "src" / "parser_rules_0000.c").read_text(encoding="utf-8")
        self.assertIn("lumina_search_exact_offsets", dispatch_source)
        self.assertIn("lumina_call_exact_verifier", dispatch_source)
        self.assertIn(
            "luminawaf_dataplane_record_exact_verifier", dispatch_source)
        self.assertIn("lumina_transform_copy", dispatch_source)
        self.assertIn("lumina_record_transform_view", dispatch_source)
        self.assertIn("lumina_record_transform_cache_hit", dispatch_source)
        table_start = dispatch_source.index(
            "const bool g_short_rule_transform_search")
        table_end = dispatch_source.index("};", table_start)
        self.assertGreaterEqual(
            dispatch_source[table_start:table_end].count("true"), 5)

    def test_transaction_stub_rules_have_no_generic_dispatch_scope(self):
        manifest = json.loads(
            (ROOT / "src" / "generated" / "rule_manifest.json").read_text(
                encoding="utf-8"))
        dispatch_source = (
            ROOT / "src" / "parser_rules_0000.c").read_text(encoding="utf-8")
        table_start = dispatch_source.index(
            "const uint32_t g_short_rule_scope")
        body_start = dispatch_source.index("{", table_start) + 1
        body_end = dispatch_source.index("};", body_start)
        scopes = [
            line.strip().rstrip(",")
            for line in dispatch_source[body_start:body_end].splitlines()
            if line.strip()
        ]
        self.assertEqual(len(scopes), manifest["short_rule_count"])

        transaction_rules = [
            rule for rule in manifest["generated_rules"]
            if rule["transaction_kind"] is not None
        ]
        self.assertGreaterEqual(len(transaction_rules), 20)
        transaction_owned_rules = [
            rule for rule in transaction_rules
            if rule["transaction_exact_matcher_stubbed"]
        ]
        predicate_gated_rules = [
            rule for rule in transaction_rules
            if not rule["transaction_exact_matcher_stubbed"]
        ]
        self.assertGreaterEqual(len(transaction_owned_rules), 20)
        self.assertEqual(
            {rule["rule_id"] for rule in predicate_gated_rules},
            {943110, 943120},
        )
        for rule in transaction_owned_rules:
            self.assertFalse(rule["generic_dispatch_owned"], rule["rule_id"])
            self.assertEqual(
                scopes[rule["engine_idx"]],
                "LUMINA_SCOPE_NONE",
                rule["rule_id"],
            )
        for rule in predicate_gated_rules:
            self.assertTrue(rule["generic_dispatch_owned"], rule["rule_id"])
            self.assertNotEqual(
                scopes[rule["engine_idx"]],
                "LUMINA_SCOPE_NONE",
                rule["rule_id"],
            )
        for rule in manifest["generated_rules"]:
            if rule["transaction_kind"] is None:
                self.assertFalse(rule["transaction_exact_matcher_stubbed"])
                self.assertTrue(rule["generic_dispatch_owned"], rule["rule_id"])

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
        self.assertIn("_route_mask", generated)
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

    def test_recursive_factored_router_keeps_nullable_branch(self):
        pattern = r"(?i)^pre(?:alpha|beta)(?:cat|wolf|)$"
        generated = TRANSLATOR.emit_recursive_factored_concat_dfa(
            "100049",
            pattern,
            state_budget=128,
            table_budget=64 * 1024,
            total_table_budget=256 * 1024,
        )
        driver = r'''
        #include <stddef.h>
        #include <string.h>
        int lumina_scan_rule_100049(const unsigned char *, size_t, size_t);
        static int scan(const char *value) {
            return lumina_scan_rule_100049(
                (const unsigned char *)value, strlen(value), 0);
        }
        int main(void) {
            if (scan("PREalpha") != 100049) return 1;
            if (scan("prebetawolf") != 100049) return 2;
            if (scan("prealphadog") != 0) return 3;
            return 0;
        }
        '''
        source = (
            "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n" +
            generated + driver
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "recursive_factored_nullable.c"
            exe = pathlib.Path(tmp) / "recursive_factored_nullable"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O0", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

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
        self.assertIn("lumina_alt_100053_teddy_low[16]", generated)
        self.assertIn("lumina_alt_100053_candidate_mask", generated)
        self.assertIn("lumina_alt_100053_route_class[256]", generated)
        self.assertIn("LUMINA_DISABLE_ALTERNATIVE_ROUTE_CLASSES", generated)
        self.assertIn(
            "LUMINA_DISABLE_ALTERNATIVE_CORRELATED_PREFIX_GUARDS", generated)
        self.assertIn("_mm256_shuffle_epi8", generated)
        self.assertIn("vqtbl1q_u8", generated)
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

            differential_driver = r'''
            #include <stddef.h>
            #include <stdint.h>
            #include <stdio.h>
            #include <string.h>
            int lumina_scan_rule_100053(
                const unsigned char *, size_t, size_t);

            static uint32_t next_random(uint32_t *state) {
                uint32_t value = *state;
                value ^= value << 13;
                value ^= value >> 17;
                value ^= value << 5;
                *state = value;
                return value;
            }

            int main(void) {
                unsigned char data[521];
                uint32_t random_state = 0x934100u;
                uint64_t hash = 1469598103934665603ULL;
                static const unsigned char needles[][18] = {
                    "eval(",
                    "function(){",
                    "this.constructor",
                    "process.env",
                    "process["
                };
                static const size_t needle_lens[] = {5, 11, 16, 11, 8};

                for (unsigned round = 0; round < 2000u; ++round) {
                    size_t len = 1u + next_random(&random_state) % sizeof(data);
                    for (size_t i = 0; i < len; ++i)
                        data[i] = (unsigned char)next_random(&random_state);
                    if ((round % 3u) == 0u) {
                        unsigned needle = round % 5u;
                        size_t needle_len = needle_lens[needle];
                        if (needle_len <= len) {
                            size_t position = next_random(&random_state) %
                                (len - needle_len + 1u);
                            memcpy(data + position, needles[needle], needle_len);
                        }
                    }
                    for (size_t offset = 0; offset <= len; ++offset) {
                        unsigned result = (unsigned)lumina_scan_rule_100053(
                            data, len, offset);
                        hash ^= (uint64_t)result +
                            ((uint64_t)offset << 32) + round;
                        hash *= 1099511628211ULL;
                    }
                }
                printf("%016llx\n", (unsigned long long)hash);
                return 0;
            }
            '''
            differential_source = (
                "#include <stdint.h>\n#include <stddef.h>\n"
                "#include <stdbool.h>\n" + generated + differential_driver
            )
            diff_src = pathlib.Path(tmp) / "alternative_router_differential.c"
            simd_exe = pathlib.Path(tmp) / "alternative_router_simd"
            scalar_exe = pathlib.Path(tmp) / "alternative_router_scalar"
            generic_exe = pathlib.Path(tmp) / "alternative_router_generic"
            generic_scalar_exe = (
                pathlib.Path(tmp) / "alternative_router_generic_scalar")
            uncorrelated_exe = (
                pathlib.Path(tmp) / "alternative_router_uncorrelated")
            diff_src.write_text(differential_source, encoding="utf-8")
            common = ["cc", "-std=c11", "-O2", "-mavx2", str(diff_src)]
            subprocess.run(
                [*common, "-o", str(simd_exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [*common, "-DLUMINA_DISABLE_ALTERNATIVE_TEDDY_ROUTER",
                 "-o", str(scalar_exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [*common, "-DLUMINA_DISABLE_ALTERNATIVE_ROUTE_CLASSES",
                 "-o", str(generic_exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [*common, "-DLUMINA_DISABLE_ALTERNATIVE_TEDDY_ROUTER",
                 "-DLUMINA_DISABLE_ALTERNATIVE_ROUTE_CLASSES",
                 "-o", str(generic_scalar_exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [*common,
                 "-DLUMINA_DISABLE_ALTERNATIVE_CORRELATED_PREFIX_GUARDS",
                 "-o", str(uncorrelated_exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            simd_hash = subprocess.run(
                [str(simd_exe)], check=True, capture_output=True, text=True,
            ).stdout
            scalar_hash = subprocess.run(
                [str(scalar_exe)], check=True, capture_output=True, text=True,
            ).stdout
            generic_hash = subprocess.run(
                [str(generic_exe)], check=True, capture_output=True, text=True,
            ).stdout
            generic_scalar_hash = subprocess.run(
                [str(generic_scalar_exe)], check=True,
                capture_output=True, text=True,
            ).stdout
            uncorrelated_hash = subprocess.run(
                [str(uncorrelated_exe)], check=True,
                capture_output=True, text=True,
            ).stdout
            self.assertEqual(simd_hash, scalar_hash)
            self.assertEqual(simd_hash, generic_hash)
            self.assertEqual(simd_hash, generic_scalar_hash)
            self.assertEqual(simd_hash, uncorrelated_hash)
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

    def test_shared_exact_phrase_router_fuses_predicates_and_preserves_xml(self):
        group = [
            (
                {"id": "933150"},
                {
                    "stages": [
                        ["eval", "base64_decode"],
                        ["(", ")"],
                    ],
                    "xml_aware": True,
                },
            ),
            (
                {"id": "944130"},
                {
                    "stages": [
                        ["java.lang.Runtime", "ProcessBuilder"],
                    ],
                    "xml_aware": False,
                },
            ),
        ]
        generated, literal_count, stage_count = (
            TRANSLATOR.emit_shared_exact_phrase_ac_router(group, 4))
        self.assertEqual(literal_count, 6)
        self.assertEqual(stage_count, 3)
        source = textwrap.dedent(
            f'''
            #include <stdint.h>
            #include <stddef.h>

            {generated}

            int lumina_scan_rule_933150(
                    const unsigned char *data, size_t len, size_t offset) {{
                static const unsigned char marker[] = "xml-safe-hit";
                (void)offset;
                for (size_t i = 0; i + sizeof(marker) - 1 <= len; ++i) {{
                    size_t q = 0;
                    while (q < sizeof(marker) - 1 &&
                           data[i + q] == marker[q]) ++q;
                    if (q == sizeof(marker) - 1) return 933150;
                }}
                return 0;
            }}

            int lumina_scan_rule_944130(
                    const unsigned char *data, size_t len, size_t offset) {{
                static const unsigned char marker[] = "ProcessBuilder";
                (void)offset;
                for (size_t i = 0; i + sizeof(marker) - 1 <= len; ++i) {{
                    size_t q = 0;
                    while (q < sizeof(marker) - 1 &&
                           data[i + q] == marker[q]) ++q;
                    if (q == sizeof(marker) - 1) return 944130;
                }}
                return 0;
            }}

            static int expect(const char *text, uint64_t wanted, uint64_t expected) {{
                size_t len = 0;
                while (text[len]) ++len;
                return lumina_shared_call_router_4_match(
                    (const unsigned char *)text, len, 0, wanted) == expected;
            }}

            int main(void) {{
                static char repetitive[4097];
                for (size_t i = 0; i < sizeof(repetitive) - 1; ++i)
                    repetitive[i] = "catalog"[i % 7];
                repetitive[sizeof(repetitive) - 1] = 0;
                if (!expect("prefix EVAL suffix (", 3, 1)) return 1;
                if (!expect("ProcessBuilder and BASE64_DECODE()", 3, 3)) return 2;
                if (!expect("base64_decode without call", 3, 0)) return 3;
                if (!expect("jAvA.LaNg.RuNtImE", 3, 2)) return 4;
                if (!expect("ordinary clean value", 3, 0)) return 5;
                if (!expect("<?xml version='1.0'?><eval>text</eval>", 3, 0))
                    return 6;
                if (!expect("<?xml version='1.0'?><x>xml-safe-hit</x>", 3, 1))
                    return 7;
                if (!expect("<?xml version='1.0'?><x>ProcessBuilder</x>", 3, 2))
                    return 8;
                if (!expect("ProcessBuilder and eval(", 1, 1)) return 9;
                if (!expect("ProcessBuilder and eval(", 2, 2)) return 10;
                if (!expect(repetitive, 3, 0)) return 11;
                return 0;
            }}
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            src = pathlib.Path(tmp) / "shared_exact_phrase_router.c"
            exe = pathlib.Path(tmp) / "shared_exact_phrase_router"
            src.write_text(source, encoding="utf-8")
            subprocess.run(
                ["cc", "-std=c11", "-O2", str(src), "-o", str(exe)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run([str(exe)], check=True)

    def test_shared_exact_phrase_router_is_pos0_only(self):
        php_rule = {
            "id": "933150",
            "operator": "@pmFromFile",
            "transforms": [],
            "bindings": [],
            "_regex_backend": "phrase-same-buffer-chain",
            "_shared_seed_literals": ["eval", "shell_exec"],
        }
        php_rule["_chain_members"] = [
            php_rule,
            {
                "operator": "@pm",
                "pattern": "( )",
                "variables": "MATCHED_VARS",
                "transforms": [],
            },
        ]
        java_rule = {
            "id": "944130",
            "operator": "@pm",
            "transforms": [],
            "bindings": [],
            "_shared_seed_literals": ["ProcessBuilder"],
        }

        stats = TRANSLATOR.lower_shared_exact_phrase_routers(
            [php_rule, java_rule], 0)

        self.assertEqual(stats["routers"], 1)
        self.assertEqual(stats["rules"], 2)
        self.assertTrue(php_rule["_force_pos0"])
        self.assertTrue(java_rule["_force_pos0"])
        self.assertEqual(php_rule["_regex_backend"],
                         "shared-exact-phrase-router")
        self.assertEqual(java_rule["_regex_backend"],
                         "shared-exact-phrase-router")

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
