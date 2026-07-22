#!/usr/bin/env python3
"""Unit tests for the LuminaWAF ELF release gate."""

import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "verify_luminawaf_elf.py"
SPEC = importlib.util.spec_from_file_location("verify_luminawaf_elf", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def dynamic_symbol_output(symbols):
    rows = [
        "Symbol table '.dynsym' contains entries:",
        "   Num:    Value          Size Type    Bind   Vis      Ndx Name",
    ]
    for index, symbol in enumerate(symbols, 1):
        rows.append(
            f"{index:6d}: 0000000000001000    16 FUNC    GLOBAL DEFAULT   12 {symbol}"
        )
    return "\n".join(rows)


class LuminaWafElfTests(unittest.TestCase):
    def test_accepts_required_api_without_local_jump_slots(self):
        symbols = dynamic_symbol_output(MODULE.REQUIRED_PUBLIC_FUNCTIONS)
        relocations = (
            "000000004000  000100000007 R_X86_64_JUMP_SLOT "
            "0000000000000000 memcpy@GLIBC_2.14 + 0\n"
        )
        self.assertEqual(MODULE.verify_outputs(symbols, relocations), [])

    def test_rejects_x86_64_jump_slot_to_defined_function(self):
        symbols = dynamic_symbol_output(MODULE.REQUIRED_PUBLIC_FUNCTIONS)
        relocations = (
            "000000004000  000100000007 R_X86_64_JUMP_SLOT "
            "0000000000001000 luminawaf_inspect_bundle + 0\n"
        )
        errors = MODULE.verify_outputs(symbols, relocations)
        self.assertEqual(len(errors), 1)
        self.assertIn("luminawaf_inspect_bundle", errors[0])

    def test_rejects_aarch64_jump_slot_to_defined_function(self):
        symbols = dynamic_symbol_output(MODULE.REQUIRED_PUBLIC_FUNCTIONS)
        relocations = (
            "000000004000  000100000402 R_AARCH64_JUMP_SLOT "
            "0000000000001000 lumina_commit_generated_rule + 0\n"
        )
        errors = MODULE.verify_outputs(symbols, relocations)
        self.assertEqual(len(errors), 1)
        self.assertIn("lumina_commit_generated_rule", errors[0])

    def test_rejects_missing_public_function(self):
        present = MODULE.REQUIRED_PUBLIC_FUNCTIONS - {"luminawaf_inspect_bundle"}
        errors = MODULE.verify_outputs(dynamic_symbol_output(present), "")
        self.assertEqual(len(errors), 1)
        self.assertIn("luminawaf_inspect_bundle", errors[0])

    def test_cmake_enables_linux_local_function_binding(self):
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("LUMINA_LOCAL_FUNCTION_BINDING", cmake)
        self.assertIn("-Bsymbolic-functions", cmake)
        self.assertIn("verify_luminawaf_elf.py", cmake)


if __name__ == "__main__":
    unittest.main()
