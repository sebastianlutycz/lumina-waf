import ast
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "nginx_module" / "ngx_http_luminawaf_module.c"


class WildWastelandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = MODULE.read_text(encoding="utf-8")

    def test_response_is_compile_time_only(self):
        self.assertIn("#ifdef LUMINA_WILD_WASTELAND", self.source)
        self.assertRegex(
            self.source,
            re.compile(
                r"#ifdef LUMINA_WILD_WASTELAND\s+"
                r"return ngx_http_luminawaf_wild_response\(r\);\s+"
                r"#else\s+return NGX_HTTP_FORBIDDEN;\s+#endif"
            ),
        )
        self.assertNotIn("LUMINA_WILD_WASTELAND", (ROOT / "README.md").read_text())
        self.assertNotIn("LUMINA_WILD_WASTELAND", (ROOT / "CMakeLists.txt").read_text())

    def test_response_body_is_small_and_static(self):
        match = re.search(
            r"static u_char body\[\] =(?P<body>.*?);",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        literals = re.findall(r'"(?:[^"\\]|\\.)*"', match.group("body"))
        body = "".join(ast.literal_eval(literal) for literal in literals)
        self.assertLessEqual(len(body.encode("utf-8")), 2048)
        self.assertIn("Earl Grey Brownie Protocol", body)
        self.assertIn("No clients or CPU registers were harmed", body)

    def test_response_has_no_retaliatory_behavior(self):
        helper = re.search(
            r"static ngx_int_t ngx_http_luminawaf_wild_response"
            r"\(ngx_http_request_t \*r\) \{(?P<body>.*?)\n\}",
            self.source,
            re.DOTALL,
        )
        self.assertIsNotNone(helper)
        helper_source = helper.group("body").lower()
        for forbidden in (
            "gzip",
            "deflate",
            "sleep(",
            "redirect",
            "unparsed_uri",
            "request_body",
            "headers_in",
        ):
            self.assertNotIn(forbidden, helper_source)
        self.assertIn("r->headers_out.status = 418;", helper.group("body"))
        self.assertIn('"418 I\'m a teapot"', helper.group("body"))
        self.assertIn("sizeof(body) - 1", helper.group("body"))
        self.assertIn("ngx_http_finalize_request(r, rc);", helper.group("body"))
        self.assertIn("return NGX_DONE;", helper.group("body"))


if __name__ == "__main__":
    unittest.main()
