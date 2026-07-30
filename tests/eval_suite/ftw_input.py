#!/usr/bin/env python3
"""Byte-preserving helpers for OWASP CRS FTW request fixtures."""

from __future__ import annotations

import base64
from typing import Any


def body_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return str(value).encode("utf-8", "replace")


def normalize_encoded_input(inp: dict[str, Any]) -> dict[str, Any]:
    """Decode an FTW encoded request while preserving its body as exact bytes."""
    raw = inp.get("encoded_request")
    if not raw:
        return inp
    try:
        request = base64.b64decode(raw)
    except (TypeError, ValueError):
        return inp

    head, separator, body = request.partition(b"\r\n\r\n")
    if not separator:
        head, separator, body = request.partition(b"\n\n")
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    if not separator or not lines or not lines[0].strip():
        return inp

    request_line = lines[0].decode("iso-8859-1", "replace").split()
    if len(request_line) < 3:
        return inp

    out = dict(inp)
    out.pop("encoded_request", None)
    out["method"], out["uri"], out["version"] = request_line[:3]
    headers = dict(out.get("headers") or {})
    header_names = {str(name).lower(): name for name in headers}
    header_counts = {str(name).lower(): 1 for name in headers}
    for raw_line in lines[1:]:
        if not raw_line or b":" not in raw_line:
            continue
        raw_name, raw_value = raw_line.split(b":", 1)
        name = raw_name.decode("iso-8859-1", "replace").strip()
        value = raw_value.decode("iso-8859-1", "replace").strip()
        if not name:
            continue
        lower_name = name.lower()
        previous_name = header_names.get(lower_name)
        if previous_name is None:
            headers[name] = value
            header_names[lower_name] = name
        else:
            headers[previous_name] = f"{headers[previous_name]}, {value}"
        # Apache exposes duplicate headers as one comma-joined collection member.
        header_counts[lower_name] = 1

    out["headers"] = headers
    out["_header_counts"] = header_counts
    out["autocomplete_headers"] = False
    if body:
        out["data"] = body
    return out


def request_body_class(inp: dict[str, Any]) -> str:
    if not body_bytes(inp.get("data")):
        return "none"
    content_type = next(
        (
            str(value).lower()
            for name, value in (inp.get("headers") or {}).items()
            if str(name).lower() == "content-type"
        ),
        "",
    )
    media_type = content_type.split(";", 1)[0].strip()
    if media_type == "application/json" or media_type.endswith("+json"):
        return "json"
    if media_type in {"application/xml", "text/xml"} or media_type.endswith("+xml"):
        return "xml"
    if media_type == "multipart/form-data":
        return "multipart"
    if media_type == "application/x-www-form-urlencoded":
        return "urlencoded"
    return "opaque"
