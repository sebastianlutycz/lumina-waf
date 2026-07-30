#!/usr/bin/env python3
"""End-to-end request-body lifecycle checks for the NGINX adapter."""

from __future__ import annotations

import hashlib
import http.client
import http.server
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

try:
    import h2.config
    import h2.connection
    import h2.events

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False


ROOT = pathlib.Path(__file__).resolve().parents[2]
CACHE = ROOT / ".cache" / "benchmark_harness_v1"
NGINX = pathlib.Path(
    os.environ.get(
        "LUMINA_INTEGRATION_NGINX",
        CACHE / "sources" / "nginx-1.30.4" / "objs" / "nginx",
    )
)
MODULE = pathlib.Path(
    os.environ.get(
        "LUMINA_INTEGRATION_NGINX_MODULE",
        CACHE
        / "sources"
        / "nginx-1.30.4"
        / "objs"
        / "ngx_http_luminawaf_module.so",
    )
)
LIBRARY_DIR = pathlib.Path(
    os.environ.get("LUMINA_INTEGRATION_LIBRARY_DIR", ROOT / "build")
)
CURL = shutil.which("curl")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class BodyEchoHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = 0

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline()
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _respond(self) -> None:
        type(self).requests += 1
        digest = hashlib.sha256(self._read_body()).hexdigest().encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(digest)))
        self.end_headers()
        self.wfile.write(digest)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond


@unittest.skipUnless(NGINX.is_file() and MODULE.is_file(), "pinned NGINX cache is absent")
class NginxRequestBodyIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="lumina-nginx-body-")
        cls.root = pathlib.Path(cls.temp.name)
        (cls.root / "logs").mkdir()
        (cls.root / "body").mkdir()

        cls.backend_port = free_port()
        cls.nginx_port = free_port()
        cls.nginx_h2_port = free_port()
        cls.backend = http.server.ThreadingHTTPServer(
            ("127.0.0.1", cls.backend_port), BodyEchoHandler
        )
        cls.backend_thread = threading.Thread(
            target=cls.backend.serve_forever, daemon=True
        )
        cls.backend_thread.start()

        cls.config = cls.root / "nginx.conf"
        cls.config.write_text(
            f"""
load_module {MODULE};
worker_processes 1;
pid {cls.root / "nginx.pid"};
error_log {cls.root / "error.log"} notice;
events {{ worker_connections 128; }}
http {{
    access_log off;
    client_max_body_size 128k;
    client_body_buffer_size 1k;
    client_body_temp_path {cls.root / "body"};
    server {{
        listen 127.0.0.1:{cls.nginx_port};
        location / {{
            lumina_waf on;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}
    }}
    server {{
        listen 127.0.0.1:{cls.nginx_h2_port};
        http2 on;
        location / {{
            lumina_waf on;
            proxy_pass http://127.0.0.1:{cls.backend_port};
        }}
    }}
}}
""".strip()
            + "\n",
            encoding="ascii",
        )
        env = os.environ.copy()
        env["LD_LIBRARY_PATH"] = str(LIBRARY_DIR) + os.pathsep + env.get(
            "LD_LIBRARY_PATH", ""
        )
        sanitizer_preload = env.pop("LUMINA_INTEGRATION_LD_PRELOAD", "")
        if sanitizer_preload:
            env["LD_PRELOAD"] = sanitizer_preload
        cls.env = env
        preflight = subprocess.run(
            [str(NGINX), "-t", "-p", str(cls.root), "-c", str(cls.config)],
            env=env,
            capture_output=True,
            text=True,
        )
        if preflight.returncode != 0:
            raise RuntimeError(
                "NGINX preflight failed:\n"
                f"stdout:\n{preflight.stdout}\n"
                f"stderr:\n{preflight.stderr}"
            )
        subprocess.run(
            [str(NGINX), "-p", str(cls.root), "-c", str(cls.config)],
            check=True,
            env=env,
            capture_output=True,
            text=True,
        )
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", cls.nginx_port), 0.1):
                    break
            except OSError:
                time.sleep(0.02)
        else:
            raise RuntimeError("NGINX did not start")

    @classmethod
    def tearDownClass(cls) -> None:
        pid_path = cls.root / "nginx.pid"
        if pid_path.exists():
            subprocess.run(
                [
                    str(NGINX),
                    "-s",
                    "quit",
                    "-p",
                    str(cls.root),
                    "-c",
                    str(cls.config),
                ],
                env=cls.env,
                capture_output=True,
                text=True,
            )
        cls.backend.shutdown()
        cls.backend.server_close()
        cls.backend_thread.join(timeout=2)
        cls.temp.cleanup()

    def request(
        self,
        method: str,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes, dict[str, str]]:
        request_headers = {
            "Host": "body-test.example",
            "User-Agent": "lumina-body-integration",
        }
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.nginx_port, timeout=5
        )
        connection.request(method, "/echo", body=body, headers=request_headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
        return response.status, payload, response_headers

    def request_h2(
        self,
        body: bytes,
        content_type: str,
        *,
        omit_content_length: bool = False,
    ) -> tuple[int, bytes]:
        if CURL is None:
            self.skipTest("curl is absent")
        headers = [
            "--header",
            "Host: body-test.example",
            "--header",
            "User-Agent: lumina-body-integration",
            "--header",
            f"Content-Type: {content_type}",
        ]
        if omit_content_length:
            headers.extend(["--header", "Content-Length:"])
        completed = subprocess.run(
            [
                CURL,
                "--silent",
                "--show-error",
                "--http2-prior-knowledge",
                "--request",
                "POST",
                *headers,
                "--data-binary",
                "@-",
                "--write-out",
                "\n%{http_code}",
                f"http://127.0.0.1:{self.nginx_h2_port}/echo",
            ],
            input=body,
            check=True,
            capture_output=True,
        )
        payload, status = completed.stdout.rsplit(b"\n", 1)
        return int(status), payload

    def request_h2_multiplexed(
        self,
        bodies: list[bytes],
    ) -> dict[int, tuple[int, bytes]]:
        if not H2_AVAILABLE:
            self.skipTest("python-h2 is absent")

        configuration = h2.config.H2Configuration(
            client_side=True, header_encoding="ascii"
        )
        connection = h2.connection.H2Connection(config=configuration)
        sock = socket.create_connection(("127.0.0.1", self.nginx_h2_port), 1.0)
        sock.settimeout(5.0)
        connection.initiate_connection()
        sock.sendall(connection.data_to_send())

        stream_ids: list[int] = []
        for body in bodies:
            stream_id = connection.get_next_available_stream_id()
            stream_ids.append(stream_id)
            connection.send_headers(
                stream_id,
                [
                    (":method", "POST"),
                    (":scheme", "http"),
                    (":authority", "body-test.example"),
                    (":path", "/echo"),
                    ("user-agent", "lumina-body-integration"),
                    ("content-type", "application/json"),
                ],
            )
            connection.send_data(stream_id, body, end_stream=True)
        sock.sendall(connection.data_to_send())

        statuses: dict[int, int] = {}
        payloads = {stream_id: bytearray() for stream_id in stream_ids}
        ended: set[int] = set()
        while len(ended) != len(stream_ids):
            received = sock.recv(64 * 1024)
            if not received:
                self.fail("HTTP/2 connection closed before every stream ended")
            for event in connection.receive_data(received):
                if isinstance(event, h2.events.ResponseReceived):
                    headers = dict(event.headers)
                    statuses[event.stream_id] = int(headers[":status"])
                elif isinstance(event, h2.events.DataReceived):
                    payloads[event.stream_id].extend(event.data)
                    connection.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.StreamEnded):
                    ended.add(event.stream_id)
                elif isinstance(event, h2.events.ConnectionTerminated):
                    self.fail(
                        f"HTTP/2 connection terminated: error={event.error_code}"
                    )
            pending = connection.data_to_send()
            if pending:
                sock.sendall(pending)
        sock.close()

        return {
            stream_id: (statuses[stream_id], bytes(payloads[stream_id]))
            for stream_id in stream_ids
        }

    def test_bodyless_fast_path(self) -> None:
        status, payload, headers = self.request("GET")
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(b"").hexdigest().encode("ascii"))
        self.assertIn("x-luminawaf-id", headers)

    def test_known_length_capture_preserves_body(self) -> None:
        body = b'{"payload":"' + (b"a" * 19_980) + b'"}'
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_known_length_direct_buffer_preserves_body(self) -> None:
        body = b'{"payload":"small-clean-value"}'
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_body_with_twenty_additional_headers_is_inspected(self) -> None:
        body = b'{"payload":"header-capacity"}'
        headers = {
            "Content-Type": "application/json",
            **{f"X-Lumina-Test-{index:02d}": "clean" for index in range(20)},
        }
        status, payload, _ = self.request("POST", body, headers)
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_bundle_capacity_overflow_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        headers = {
            "Content-Type": "application/octet-stream",
            **{f"X-Lumina-Test-{index:02d}": "clean" for index in range(40)},
        }
        status, _, _ = self.request("POST", b"bounded", headers)
        # NGINX maps its internal 494 "request header too large" code to the
        # standards-facing 400 response.
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_exact_limit_body_is_accepted(self) -> None:
        body = b'{"payload":"' + (b"a" * (128 * 1024 - 14)) + b'"}'
        self.assertEqual(len(body), 128 * 1024)
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_chunked_capture_preserves_body(self) -> None:
        chunks = [b"alpha=", b"clean-value", b"&beta=42"]
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.nginx_port, timeout=5
        )
        connection.putrequest("POST", "/echo", skip_host=True)
        connection.putheader("Host", "body-test.example")
        connection.putheader("User-Agent", "lumina-body-integration")
        connection.putheader("Content-Type", "application/x-www-form-urlencoded")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.endheaders()
        for chunk in chunks:
            connection.send(f"{len(chunk):x}\r\n".encode("ascii"))
            connection.send(chunk + b"\r\n")
        connection.send(b"0\r\n\r\n")
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        self.assertEqual(response.status, 200)
        self.assertEqual(
            payload, hashlib.sha256(b"".join(chunks)).hexdigest().encode("ascii")
        )

    def test_slow_body_read_does_not_block_bodyless_request(self) -> None:
        slow = socket.create_connection(("127.0.0.1", self.nginx_port), 1.0)
        slow.sendall(
            b"POST /echo HTTP/1.1\r\n"
            b"Host: body-test.example\r\n"
            b"User-Agent: lumina-body-integration\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 20000\r\n"
            b"\r\n"
            b"{"
        )
        time.sleep(0.02)
        status, payload, _ = self.request("GET")
        slow.close()
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(b"").hexdigest().encode("ascii"))

    def test_client_abort_during_body_read_does_not_kill_worker(self) -> None:
        aborted = socket.create_connection(("127.0.0.1", self.nginx_port), 1.0)
        aborted.sendall(
            b"POST /echo HTTP/1.1\r\n"
            b"Host: body-test.example\r\n"
            b"User-Agent: lumina-body-integration\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 20000\r\n"
            b"\r\n"
            b'{"partial":'
        )
        aborted.close()
        time.sleep(0.02)
        status, payload, _ = self.request("GET")
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(b"").hexdigest().encode("ascii"))

    def test_body_with_embedded_nul_is_scanned_by_length(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"clean\x00binary"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_body_only_attack_is_blocked(self) -> None:
        before = BodyEchoHandler.requests
        status, _, headers = self.request(
            "POST",
            b'{"payload":"<script>alert(document.domain)</script>"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertIn("x-lumina-rule-id", headers)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_get_body_attack_is_blocked_before_backend(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "GET",
            b'{"payload":"<script>alert(document.domain)</script>"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_form_urlencoded_percent_decoding_blocks_attack(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"first=clean&payload=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"
            b"&first=second",
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_post_form_without_content_type_uses_bounded_fallback(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"payload=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_json_escape_projection_blocks_attack(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_json_raw_request_body_collection_blocks_attack(self) -> None:
        before = BodyEchoHandler.requests
        status, _, headers = self.request(
            "POST",
            b'{"payload":"appserv_root=http://raw-body.example"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)
        self.assertIsNotNone(headers.get("x-lumina-rule-id"))
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_vendor_json_media_type_blocks_attack(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"<script>alert(1)</script>"}',
            {"Content-Type": "application/problem+json; charset=utf-8"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_malformed_json_attack_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"<script>alert(1)</script>',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_clean_malformed_json_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        body = b'{"payload":"clean-value"'
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_json_surrogate_pair_is_decoded(self) -> None:
        body = b'{"payload":"clean-\\ud83d\\ude80-value"}'
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_json_unpaired_surrogate_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"clean-\\ud83d-value"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_json_invalid_escape_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'{"payload":"clean-\\x41-value"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_json_depth_limit_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        body = (b"[" * 65) + b"0" + (b"]" * 65)
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/json"}
        )
        self.assertEqual(status, 413)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_depth_limit_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        body = (b"<node>" * 129) + (b"</node>" * 129)
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 413)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_body_attack_is_blocked(self) -> None:
        before = BodyEchoHandler.requests
        status, _, headers = self.request(
            "POST",
            b'<?xml version="1.0"?><root><payload><script>alert(1)</script>'
            b"</payload></root>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 403)
        self.assertNotEqual(headers.get("x-lumina-rule-id"), "920420")
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_mismatched_tags_fail_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"<root><item>clean</root>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_unknown_entity_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"<root>clean&unknown;</root>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_numeric_unicode_entity_is_accepted(self) -> None:
        body = b"<root>clean-&#x1f680;-value</root>"
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_xml_attribute_entity_is_decoded_before_inspection(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'<root payload="&lt;script&gt;alert(1)&lt;/script&gt;"/>',
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_invalid_element_name_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"<1root>clean</1root>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_root_only_doctype_is_accepted(self) -> None:
        body = b"<!DOCTYPE root><root>clean-value</root>"
        status, payload, _ = self.request(
            "POST",
            body,
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_xml_root_only_doctype_does_not_bypass_attack_projection(self) -> None:
        bodies = (
            b'<root payload="&lt;script&gt;alert(1)&lt;/script&gt;"/>',
            b'<!DOCTYPE root><root payload="'
            b"&lt;script&gt;alert(1)&lt;/script&gt;"
            b'"/>',
            b"<!DOCTYPE root><root><padding>"
            + (b"q" * (64 * 1024))
            + b"</padding><payload>&lt;script&gt;alert(1)"
            b"&lt;/script&gt;</payload></root>",
        )
        for body in bodies:
            with self.subTest(length=len(body)):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 403)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_internal_text_entity_is_expanded(self) -> None:
        body = (
            b'<!DOCTYPE root [<!ENTITY first "clean">'
            b'<!ENTITY second "&first;-value">]>'
            b"<root>&second;</root>"
        )
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_xml_dtd_comment_and_forward_reference_are_accepted(self) -> None:
        body = (
            b"<!DOCTYPE root [<!-- bounded internal entities -->"
            b'<!ENTITY first "&second;-value"><!ENTITY second "clean">]>'
            b"<root>&first;</root>"
        )
        status, payload, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_xml_internal_entity_attack_is_inspected_after_expansion(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'<!DOCTYPE root [<!ENTITY payload '
            b'"&lt;script&gt;alert(1)&lt;/script&gt;">]>'
            b"<root>&payload;</root>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_internal_entity_attack_in_attribute_is_inspected(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'<!DOCTYPE root [<!ENTITY payload '
            b'"&lt;script&gt;alert(1)&lt;/script&gt;">]>'
            b'<root value="&payload;"/>',
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_external_dtd_semantics_are_forbidden(self) -> None:
        bodies = (
            b'<!DOCTYPE root SYSTEM "file:///etc/passwd"><root/>',
            b'<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            b"<root>&x;</root>",
            b'<!DOCTYPE root [<!ENTITY % x "value">]><root/>',
            b'<!DOCTYPE root [<!ENTITY x "value">%x;]><root/>',
        )
        for body in bodies:
            with self.subTest(body=body):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 403)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_dtd_declarations_that_change_document_shape_are_unsupported(
        self,
    ) -> None:
        bodies = (
            b'<!DOCTYPE root [<!ATTLIST root role CDATA "admin">]><root/>',
            b"<!DOCTYPE root [<!ELEMENT root (#PCDATA)>]><root>clean</root>",
            b'<!DOCTYPE root [<!NOTATION image SYSTEM "image/png">]><root/>',
        )
        for body in bodies:
            with self.subTest(body=body):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 415)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_doctype_name_must_match_root(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"<!DOCTYPE expected><actual/>",
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_dtd_cycle_and_depth_limits_fail_closed(self) -> None:
        cases = (
            (
                b'<!DOCTYPE root [<!ENTITY a "&b;"><!ENTITY b "&a;">]>'
                b"<root>&a;</root>",
                400,
            ),
            (
                b'<!DOCTYPE root [<!ENTITY a "&b;"><!ENTITY b "&c;">'
                b'<!ENTITY c "&d;"><!ENTITY d "&e;"><!ENTITY e "value">]>'
                b"<root>&a;</root>",
                413,
            ),
        )
        for body, expected_status in cases:
            with self.subTest(expected_status=expected_status):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, expected_status)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_dtd_metadata_and_expansion_budgets_fail_closed(self) -> None:
        entity_count_body = (
            b"<!DOCTYPE root ["
            + b"".join(
                f'<!ENTITY e{index} "x">'.encode("ascii")
                for index in range(33)
            )
            + b"]><root/>"
        )
        long_name = b"x" * 65
        long_name_body = (
            b"<!DOCTYPE root [<!ENTITY "
            + long_name
            + b' "value">]><root/>'
        )
        expansion = b"a" * 4096
        expansion_body = (
            b'<!DOCTYPE root [<!ENTITY x "'
            + expansion
            + b'">]><root>&x;&x;&x;</root>'
        )
        for body in (entity_count_body, long_name_body, expansion_body):
            with self.subTest(length=len(body)):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 413)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_unused_undefined_entity_reference_is_malformed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b'<!DOCTYPE root [<!ENTITY x "&missing;">]><root>clean</root>',
            {"Content-Type": "application/xml"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_internal_entity_is_expanded(self) -> None:
        document = (
            '<!DOCTYPE root [<!ENTITY value "clean-\U0001f680-value">]>'
            "<root>&value;</root>"
        )
        for encoding, bom in (
            ("utf-16le", b"\xff\xfe"),
            ("utf-16be", b"\xfe\xff"),
        ):
            body = bom + document.encode(encoding)
            with self.subTest(encoding=encoding):
                status, payload, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    payload, hashlib.sha256(body).hexdigest().encode("ascii")
                )

    def test_xml_utf16_bom_variants_are_preserved(self) -> None:
        document = "<root>clean-\U0001f680-value</root>"
        variants = (
            b"\xff\xfe" + document.encode("utf-16le"),
            b"\xfe\xff" + document.encode("utf-16be"),
        )
        for body in variants:
            with self.subTest(bom=body[:2].hex()):
                status, payload, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    payload, hashlib.sha256(body).hexdigest().encode("ascii")
                )

    def test_xml_utf16_signature_without_bom_is_detected(self) -> None:
        document = (
            '<?xml version="1.0" encoding="UTF-16"?>'
            "<root>clean-value</root>"
        )
        for encoding in ("utf-16le", "utf-16be"):
            body = document.encode(encoding)
            with self.subTest(encoding=encoding):
                status, payload, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 200)
                self.assertEqual(
                    payload, hashlib.sha256(body).hexdigest().encode("ascii")
                )

    def test_xml_encoding_declaration_must_match_wire_encoding(self) -> None:
        malformed = (
            b"\xff\xfe"
            + (
                '<?xml version="1.0" encoding="UTF-16BE"?>'
                "<root>clean</root>"
            ).encode("utf-16le"),
            b"\xfe\xff"
            + (
                '<?xml version="1.0" encoding="UTF-16LE"?>'
                "<root>clean</root>"
            ).encode("utf-16be"),
            b"\xef\xbb\xbf"
            + (
                '<?xml version="1.0" encoding="UTF-16"?>'
                "<root>clean</root>"
            ).encode("utf-8"),
        )
        for body in malformed:
            with self.subTest(body=body):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 400)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_unsupported_declared_encoding_fails_closed(self) -> None:
        body = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>'
            "<root>clean</root>"
        ).encode("ascii")
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 415)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_attribute_attack_is_projected(self) -> None:
        before = BodyEchoHandler.requests
        document = (
            '<root payload="&lt;script&gt;alert(1)&lt;/script&gt;"/>'
        )
        body = b"\xff\xfe" + document.encode("utf-16le")
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_unpaired_surrogates_fail_closed(self) -> None:
        prefix = b"\xff\xfe" + "<root>".encode("utf-16le")
        suffix = "</root>".encode("utf-16le")
        malformed = (
            prefix + b"\x00\xd8" + suffix,
            prefix + b"\x00\xdc" + suffix,
        )
        for body in malformed:
            before = BodyEchoHandler.requests
            with self.subTest(unit=body[len(prefix):len(prefix) + 2].hex()):
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 400)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_odd_byte_count_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        body = b"\xff\xfe" + "<root>clean</root>".encode("utf-16le") + b"\x00"
        status, _, _ = self.request(
            "POST", body, {"Content-Type": "application/xml"}
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_forbidden_codepoints_fail_closed(self) -> None:
        malformed = (
            b"\xff\xfe"
            + "<root>".encode("utf-16le")
            + b"\x00\x00"
            + "</root>".encode("utf-16le"),
            b"\xfe\xff"
            + "<root>".encode("utf-16be")
            + b"\xff\xfe"
            + "</root>".encode("utf-16be"),
        )
        for body in malformed:
            with self.subTest(body=body):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 400)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_xml_utf16_bom_byte_order_mismatch_fails_closed(self) -> None:
        document = "<root>clean</root>"
        malformed = (
            b"\xff\xfe" + document.encode("utf-16be"),
            b"\xfe\xff" + document.encode("utf-16le"),
        )
        for body in malformed:
            with self.subTest(body=body):
                before = BodyEchoHandler.requests
                status, _, _ = self.request(
                    "POST", body, {"Content-Type": "application/xml"}
                )
                self.assertEqual(status, 400)
                self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_utf16_xml_is_detected_from_bom(self) -> None:
        boundary = b"lumina-utf16-xml-boundary"
        xml = b"\xfe\xff" + "<root><item>clean</root>".encode("utf-16be")
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="document"\r\n'
            b"\r\n"
            + xml + b"\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_body_attack_is_blocked(self) -> None:
        boundary = b"lumina-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"\r\n"
            b"<script>alert(1)</script>\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, headers = self.request(
            "POST",
            body,
            {
                "Content-Type": "multipart/form-data; boundary="
                + boundary.decode("ascii")
            },
        )
        self.assertEqual(status, 403)
        self.assertNotEqual(headers.get("x-lumina-rule-id"), "920420")
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_clean_multipart_body_is_preserved(self) -> None:
        boundary = b"lumina-clean-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="description"\r\n'
            b"\r\n"
            b"clean catalog value\r\n"
            b"--" + boundary + b"--\r\n"
        )
        status, payload, _ = self.request(
            "POST",
            body,
            {
                "Content-Type": "multipart/form-data; boundary="
                + boundary.decode("ascii")
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_multipart_base64_field_is_decoded_before_inspection(self) -> None:
        boundary = b"lumina-base64-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_quoted_printable_field_is_decoded_before_inspection(self) -> None:
        boundary = b"lumina-qp-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"=3Cscript=3Ealert(1)=3C/script=3E\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_extended_filename_is_projected(self) -> None:
        boundary = b"lumina-filename-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b"Content-Disposition: form-data; name=\"upload\"; "
            b"filename*=UTF-8''%2e%2e%2f%2e%2e%2fetc%2fpasswd\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
            b"clean file bytes\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_xml_media_type_with_parameters_is_parsed(self) -> None:
        boundary = b"lumina-xml-media-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="document"; filename="data.bin"\r\n'
            b"Content-Type: Application/XML; charset=UTF-8\r\n"
            b"\r\n"
            b'<root payload="&lt;script&gt;alert(1)&lt;/script&gt;"/>\r\n'
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_xml_external_entity_is_forbidden(self) -> None:
        boundary = b"lumina-xml-dtd-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="document"; filename="data.xml"\r\n'
            b"Content-Type: application/xml\r\n"
            b"\r\n"
            b'<!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            b"<root>&x;</root>\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_extended_xml_filename_selects_xml_parser(self) -> None:
        boundary = b"lumina-xml-filename-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b"Content-Disposition: form-data; name=\"document\"; "
            b"filename*=UTF-8''document%2eXML\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"\r\n"
            b"<root><item>clean</root>\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_nested_multipart_field_is_inspected(self) -> None:
        outer = b"lumina-outer-boundary"
        inner = b"lumina-inner-boundary"
        body = (
            b"--" + outer + b"\r\n"
            b'Content-Disposition: form-data; name="batch"\r\n'
            b"Content-Type: multipart/mixed; boundary=" + inner + b"\r\n"
            b"\r\n"
            b"--" + inner + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"\r\n"
            b"<script>alert(1)</script>\r\n"
            b"--" + inner + b"--\r\n"
            b"--" + outer + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={outer.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_without_closing_boundary_fails_closed(self) -> None:
        boundary = b"lumina-open-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"\r\n"
            b"clean value\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_multipart_missing_boundary_metadata_fails_closed(self) -> None:
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            b"not a framed multipart body",
            {"Content-Type": "multipart/form-data"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_unknown_multipart_transfer_encoding_is_unsupported(self) -> None:
        boundary = b"lumina-cte-boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"Content-Transfer-Encoding: x-custom\r\n"
            b"\r\n"
            b"clean value\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 415)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_invalid_multipart_part_header_name_is_blocked(self) -> None:
        boundary = b"lumina-invalid-part-header"
        body = (
            b"--" + boundary + b"\r\n"
            b"Bad\tName: value\r\n"
            b"\r\n"
            b"clean value\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, headers = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-lumina-rule-id"), "922130")
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_malformed_multipart_base64_fails_closed(self) -> None:
        boundary = b"lumina-invalid-base64"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="payload"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"not!base64\r\n"
            b"--" + boundary + b"--\r\n"
        )
        before = BodyEchoHandler.requests
        status, _, _ = self.request(
            "POST",
            body,
            {"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
        )
        self.assertEqual(status, 400)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_http2_exact_limit_body_is_preserved(self) -> None:
        body = b'{"payload":"' + (b"a" * (128 * 1024 - 14)) + b'"}'
        self.assertEqual(len(body), 128 * 1024)
        status, payload = self.request_h2(body, "application/json")
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_http2_body_only_attack_is_blocked(self) -> None:
        before = BodyEchoHandler.requests
        status, _ = self.request_h2(
            b'{"payload":"<script>alert(document.domain)</script>"}',
            "application/json",
        )
        self.assertEqual(status, 403)
        self.assertEqual(BodyEchoHandler.requests, before)

    def test_http2_without_content_length_preserves_body(self) -> None:
        body = b'{"payload":"' + (b"h" * 20_000) + b'"}'
        status, payload = self.request_h2(
            body, "application/json", omit_content_length=True
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload, hashlib.sha256(body).hexdigest().encode("ascii"))

    def test_http2_without_content_length_enforces_stream_limit(self) -> None:
        before = BodyEchoHandler.requests
        status, _ = self.request_h2(
            b"x" * (128 * 1024 + 1),
            "application/octet-stream",
            omit_content_length=True,
        )
        self.assertEqual(status, 413)
        self.assertEqual(BodyEchoHandler.requests, before)

    @unittest.skipUnless(H2_AVAILABLE, "python-h2 is absent")
    def test_http2_multiplexed_stream_contexts_are_isolated(self) -> None:
        clean = [
            b'{"payload":"clean-stream-' + str(index).encode("ascii") + b'"}'
            for index in range(7)
        ]
        attack = b'{"payload":"<script>alert(1)</script>"}'
        before = BodyEchoHandler.requests
        responses = self.request_h2_multiplexed([*clean, attack])

        stream_ids = sorted(responses)
        for stream_id, body in zip(stream_ids[:-1], clean):
            status, payload = responses[stream_id]
            self.assertEqual(status, 200)
            self.assertEqual(
                payload, hashlib.sha256(body).hexdigest().encode("ascii")
            )
        self.assertEqual(responses[stream_ids[-1]][0], 403)
        self.assertEqual(BodyEchoHandler.requests, before + len(clean))

    def test_unsupported_content_encoding_is_rejected(self) -> None:
        status, _, _ = self.request(
            "POST",
            b"not-compressed",
            {
                "Content-Type": "application/octet-stream",
                "Content-Encoding": "gzip",
            },
        )
        self.assertEqual(status, 415)

    def test_identity_content_encoding_reaches_crs_policy(self) -> None:
        body = b'{"payload":"identity"}'
        status, _, headers = self.request(
            "POST",
            body,
            {"Content-Type": "application/json", "Content-Encoding": "identity"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-lumina-rule-id"), "920450")

    def test_oversized_known_body_is_rejected(self) -> None:
        status, _, _ = self.request(
            "POST",
            b"x" * (128 * 1024 + 1),
            {"Content-Type": "application/octet-stream"},
        )
        self.assertEqual(status, 413)


if __name__ == "__main__":
    unittest.main()
