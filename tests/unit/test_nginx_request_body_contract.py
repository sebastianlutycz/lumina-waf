#!/usr/bin/env python3
"""Static contracts for the protocol-neutral NGINX request-body adapter."""

from __future__ import annotations

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE = ROOT / "nginx_module" / "ngx_http_luminawaf_module.c"
BOOTSTRAP = ROOT / "bench" / "benchmark_harness" / "bootstrap.sh"


class NginxRequestBodyContractTest(unittest.TestCase):
    def test_adapter_uses_public_request_body_api_only(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("ngx_http_read_client_request_body(", source)
        self.assertIn("ngx_http_top_request_body_filter", source)
        for transport_internal in (
            "r->stream",
            "r->v3",
            "r->quic",
            "ngx_http_v2_",
            "ngx_http_v3_",
            "ngx_quic_",
        ):
            self.assertNotIn(transport_internal, source)

    def test_adapter_does_not_perform_synchronous_body_file_io(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for blocking_io in (
            "ngx_open_file(",
            "ngx_read_file(",
            "pread(",
            "fread(",
        ):
            self.assertNotIn(blocking_io, source)

    def test_pinned_test_nginx_enables_http2(self) -> None:
        bootstrap = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn("--with-http_v2_module", bootstrap)


if __name__ == "__main__":
    unittest.main()
