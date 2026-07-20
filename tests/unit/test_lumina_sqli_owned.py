#!/usr/bin/env python3
import ctypes
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]


class LuminaSqliOwnedTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.library_path = pathlib.Path(cls._tmp.name) / "liblumina_sqli_owned.so"
        subprocess.run(
            [
                "cc",
                "-std=c11",
                "-O2",
                "-fPIC",
                "-shared",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "src" / "lumina_sqli.c"),
                "-o",
                str(cls.library_path),
            ],
            check=True,
        )
        cls.library = ctypes.CDLL(str(cls.library_path))
        cls.library.lumina_sqli_detect.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        cls.library.lumina_sqli_detect.restype = ctypes.c_int

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def detect(self, value):
        encoded = value.encode("ascii")
        return self.library.lumina_sqli_detect(encoded, len(encoded))

    def test_public_crs_942100_positive_shapes(self):
        values = [
            "JKGHUKGDI8TDHLFJH72FZLFJSKFH' and sleep(12) --",
            "1'||(select extractvalue(xmltype('<?xml version=\"1.1\" "
            "encoding=\"UTF-8\"?><!DOCTYPE root [ <!ENTITY % toyop SYSTEM "
            "\"https://coreruleset.org/\">%toyop;",
            '\" | type %SystemDrive%\\\\config.ini | \"',
        ]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.detect(value), 1)

    def test_public_crs_942101_path_shape(self):
        self.assertEqual(self.detect("/post/*/*/2 union all/bar"), 1)

    def test_incomplete_union_path_remains_allowed(self):
        self.assertEqual(self.detect("/post/foo/9'union all/bar"), 0)


if __name__ == "__main__":
    unittest.main()
