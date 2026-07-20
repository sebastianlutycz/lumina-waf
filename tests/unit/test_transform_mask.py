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
MODULE_PATH = ROOT / "tools" / "gen_transform_mask.py"
SPEC = importlib.util.spec_from_file_location("gen_transform_mask", MODULE_PATH)
TRANSFORMS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TRANSFORMS)


class TransformMaskTest(unittest.TestCase):
    def test_transform_selftest_covers_avx2_lowercase_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = pathlib.Path(tmp) / "transform_selftest"
            subprocess.run(
                ["cc", "-std=c11", "-O2", "-mavx2",
                 "-DLUMINA_TRANSFORMS_SELFTEST", f"-I{ROOT / 'src'}",
                 str(ROOT / "src" / "lumina_transforms.c"),
                 "-o", str(executable)],
                check=True,
                capture_output=True,
                text=True,
            )
            result = subprocess.run(
                [str(executable)], check=True, capture_output=True, text=True)
        self.assertIn("lowercase SIMD boundaries: PASS", result.stdout)
        self.assertIn("OVERALL: PASS", result.stdout)

    def test_actions_ignore_comments_and_do_not_inherit_previous_rule(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx one" \
                "id:100600,phase:2,deny,t:none"
            # Documentation mentions t:cmdLine but is not an action.
            SecRule ARGS "@rx two" \
                "id:100601,phase:2,deny,t:none,t:lowercase"
            SecRule ARGS "@rx three" \
                "id:100602,phase:2,deny"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            rules_dir = pathlib.Path(tmp)
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            sequences, found = TRANSFORMS.build_sequences(
                [100600, 100601, 100602], rules_dir)
        self.assertEqual(found, {100600, 100601, 100602})
        self.assertEqual(sequences[100600], [])
        self.assertEqual(sequences[100601], ["LUMINA_T_LOWERCASE"])
        self.assertEqual(sequences[100602], [])

    def test_emits_shared_uint8_sequence_ids(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx one" "id:100600,phase:2,deny,t:none,t:lowercase"
            SecRule ARGS "@rx two" "id:100601,phase:2,deny,t:none,t:lowercase"
            SecRule ARGS "@rx three" "id:100602,phase:2,deny,t:none,t:urlDecodeUni"
            SecRule ARGS "@rx four" "id:100603,phase:2,deny,t:none"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            rules_dir = root / "rules"
            out_dir = root / "generated"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            manifest_path = root / "rule_manifest.json"
            manifest_path.write_text(
                json.dumps({
                    "generated_rule_ids": [100600, 100601, 100602, 100603],
                    "rules_dir": str(rules_dir),
                }),
                encoding="utf-8")
            subprocess.run(
                ["python3", str(MODULE_PATH), "--manifest", str(manifest_path),
                 "--rules-dir", str(rules_dir), "--out-dir", str(out_dir)],
                check=True, capture_output=True, text=True)
            source = (out_dir / "crs_transform_mask.c").read_text(encoding="utf-8")
            header = (out_dir / "crs_transform_mask.h").read_text(encoding="utf-8")
        self.assertIn("#define LUMINA_TRANSFORM_SEQUENCE_COUNT 3", header)
        ids = [int(value) for value in re.findall(
            r"CRS 10060[0-3] \*/ (\d+),", source)]
        self.assertEqual(ids, [1, 1, 2, 0])

    def test_emits_conservative_transform_dirty_byte_classifier(self):
        conf = textwrap.dedent(
            r'''
            SecRule ARGS "@rx one" "id:100610,phase:2,deny,t:none,t:lowercase"
            SecRule ARGS "@rx two" "id:100611,phase:2,deny,t:none,t:urlDecodeUni"
            SecRule ARGS "@rx three" "id:100612,phase:2,deny,t:none,t:utf8toUnicode"
            SecRule ARGS "@rx four" "id:100613,phase:2,deny,t:none,t:cmdLine"
            SecRule ARGS "@rx five" "id:100614,phase:2,deny,t:none,t:base64Decode"
            SecRule ARGS "@rx six" "id:100615,phase:2,deny,t:none,t:length"
            '''
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            rules_dir = root / "rules"
            out_dir = root / "generated"
            rules_dir.mkdir()
            (rules_dir / "custom.conf").write_text(conf, encoding="utf-8")
            manifest_path = root / "rule_manifest.json"
            manifest_path.write_text(
                json.dumps({
                    "generated_rule_ids": list(range(100610, 100616)),
                    "rules_dir": str(rules_dir),
                }),
                encoding="utf-8",
            )
            subprocess.run(
                ["python3", str(MODULE_PATH), "--manifest", str(manifest_path),
                 "--rules-dir", str(rules_dir), "--out-dir", str(out_dir)],
                check=True, capture_output=True, text=True,
            )
            source = (out_dir / "crs_transform_mask.c").read_text(
                encoding="utf-8")
            header = (out_dir / "crs_transform_mask.h").read_text(
                encoding="utf-8")

        ids = [int(value) for value in re.findall(
            r"CRS 10061[0-5] \*/ (\d+),", source)]
        self.assertEqual(ids, [1, 2, 3, 4, 5, 6])
        rows = {
            int(byte, 16): int(mask, 16)
            for byte, mask in re.findall(
                r"/\* 0x([0-9a-f]{2}) \*/ \{0x([0-9a-f]+)ULL\}", source)
        }
        always = int(re.search(
            r"g_transform_sequence_always_dirty[^=]*= \{0x([0-9a-f]+)ULL\}",
            source,
        ).group(1), 16)
        self.assertIn("#define LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS 1", header)
        self.assertTrue(rows[ord("A")] & (1 << ids[0]))
        self.assertFalse(rows[ord("a")] & (1 << ids[0]))
        self.assertTrue(rows[ord("%")] & (1 << ids[1]))
        self.assertTrue(rows[ord("+")] & (1 << ids[1]))
        self.assertTrue(rows[0x80] & (1 << ids[2]))
        self.assertFalse(rows[0x7f] & (1 << ids[2]))
        self.assertTrue(rows[ord("/")] & (1 << ids[3]))
        self.assertTrue(rows[ord('"')] & (1 << ids[3]))
        self.assertTrue(always & (1 << ids[4]))
        self.assertTrue(always & (1 << ids[5]))
        self.assertFalse(always & (1 << ids[0]))


if __name__ == "__main__":
    unittest.main()
