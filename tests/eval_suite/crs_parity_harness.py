#!/usr/bin/env python3
"""
crs_parity_harness.py — Offline parity harness vs OWASP CRS regression suite.

Test classification (faithful to go-ftw / ModSecurity semantics):
  * expect_ids present  -> POSITIVE: the targeted detection rule should fire and
    ModSecurity blocks.  LuminaWAF strict pass = matched id is one of the expected ids.
    Block-level pass is reported separately as a diagnostic only.
  * no_expect_ids present -> NEGATIVE: the targeted rule must NOT fire.  We only
    assert the EXCLUDED rule did not trigger (ModSecurity may still block via
    other rules, which is correct behaviour, not a false positive).  Pass if the
    single matched id is not in no_expect_ids.
  * status present (403 vs 200/404) -> VERDICT: pass if LuminaWAF block matches.
  * status-only 400 -> TRANSPORT: Apache rejected the request before CRS; skip
    unless explicit expect_ids/no_expect_ids are present.

Metrics: positive_block_rate, positive_exact_rate, negative_excluded_rate, verdict_rate, overall.

Usage:
  python3 crs_parity_harness.py [--dir <regression tests dir>] [--limit N]
"""
import os, sys, glob, argparse, ctypes, signal, time, json, subprocess
from pathlib import Path

from ftw_input import body_bytes, normalize_encoded_input, request_body_class
from pl2_coverage_oracle import CoverageTracker, sha256_file, sha256_tree

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SO = os.environ.get("LUMINA_WAF_SO", os.path.join(ROOT, "build", "libluminawaf.so"))
DEFAULT_DIR = os.path.join(ROOT, "tests/eval_suite/coreruleset/tests/regression/tests")
DEFAULT_RULES_DIR = os.path.join(ROOT, "tests/eval_suite/coreruleset/rules")
DEFAULT_SETUP_CONF = None
LUMINA_BUNDLE_MAX_VARS = 32


def materialize_default_setup_conf():
    tools_dir = os.path.join(ROOT, "bench", "benchmark_harness")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    from generate_crs_setup import render
    source = os.path.join(
        ROOT, "tests/eval_suite/coreruleset/crs-setup.conf.example")
    target = os.path.join(
        ROOT, ".cache/benchmark_harness_v1/config/crs-setup.conf")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as stream:
        stream.write(render(Path(source)))
    return target

class BundleVar(ctypes.Structure):
    _fields_ = [("ptr", ctypes.POINTER(ctypes.c_ubyte)),
                ("len", ctypes.c_size_t), ("var_type", ctypes.c_uint8), ("scope", ctypes.c_uint32),
                ("header_mask", ctypes.c_uint32), ("collection_mask", ctypes.c_uint64),
                ("name", ctypes.POINTER(ctypes.c_ubyte)), ("name_len", ctypes.c_size_t)]
class LuminaBundle(ctypes.Structure):
    _fields_ = [("vars", BundleVar * LUMINA_BUNDLE_MAX_VARS), ("count", ctypes.c_int), ("hdr_presence_mask", ctypes.c_uint32),
                # C4 STRUCTURAL discrete CRS collections (mirror luminawaf.h LuminaBundle)
                ("req_method", ctypes.POINTER(ctypes.c_ubyte)), ("req_method_len", ctypes.c_size_t),
                ("req_line", ctypes.POINTER(ctypes.c_ubyte)), ("req_line_len", ctypes.c_size_t),
                ("user_agent", ctypes.POINTER(ctypes.c_ubyte)), ("user_agent_len", ctypes.c_size_t),
                ("req_protocol", ctypes.POINTER(ctypes.c_ubyte)), ("req_protocol_len", ctypes.c_size_t),
                ("req_filename", ctypes.POINTER(ctypes.c_ubyte)), ("req_filename_len", ctypes.c_size_t),
                ("req_basename", ctypes.POINTER(ctypes.c_ubyte)), ("req_basename_len", ctypes.c_size_t),
                ("reqbody_processor", ctypes.POINTER(ctypes.c_ubyte)), ("reqbody_processor_len", ctypes.c_size_t),
                ("hdr_host_count", ctypes.c_uint16), ("hdr_user_agent_count", ctypes.c_uint16),
                ("hdr_content_type_count", ctypes.c_uint16), ("hdr_request_range_count", ctypes.c_uint16),
                ("hdr_transfer_encoding_count", ctypes.c_uint16)]
class LuminaResult(ctypes.Structure):
    _fields_ = [("error_flag", ctypes.c_int), ("threat_level", ctypes.c_int),
                ("decoded_buffer", ctypes.c_char_p), ("decoded_length", ctypes.c_size_t)]
lib = ctypes.CDLL(SO)
lib.luminawaf_init_worker(256)
lib.luminawaf_rule_state_size.argtypes = []
lib.luminawaf_rule_state_size.restype = ctypes.c_size_t
RULE_STATE_SIZE = lib.luminawaf_rule_state_size()
lib.luminawaf_inspect_bundle.argtypes = [ctypes.POINTER(LuminaBundle), ctypes.c_void_p, ctypes.POINTER(LuminaResult)]
lib.luminawaf_inspect_bundle.restype = ctypes.c_int
lib.luminawaf_audit_bundle_matches.argtypes = [ctypes.POINTER(LuminaBundle), ctypes.c_void_p]
lib.luminawaf_audit_bundle_matches.restype = ctypes.c_int
lib.luminawaf_audit_bundle_rule.argtypes = [ctypes.POINTER(LuminaBundle), ctypes.c_void_p, ctypes.c_int]
lib.luminawaf_audit_bundle_rule.restype = ctypes.c_int
lib.luminawaf_rule_state_matched.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.luminawaf_rule_state_matched.restype = ctypes.c_int

SC_URI, SC_HDR, SC_BODY, SC_JSON = 1, 2, 4, 8
VT_URI, VT_ARGS, VT_COOKIE, VT_HDR, VT_BODY = 0, 1, 2, 3, 4
HEADER_MASKS = {
    "content-length": 1 << 0, "request-range": 1 << 1, "connection": 1 << 2,
    "host": 1 << 3, "user-agent": 1 << 4, "content-type": 1 << 5,
    "accept-encoding": 1 << 6, "accept": 1 << 7, "cookie": 1 << 8,
    "referer": 1 << 9, "x-filename": 1 << 10, "x_filename": 1 << 10,
    "x.filename": 1 << 10, "x-file-name": 1 << 10,
    "range": 1 << 11,
}

_keep = []
def _buf(s):
    if s is None:
        b = b""
    elif isinstance(s, bytes):
        b = s
    elif not isinstance(s, str):
        b = str(s).encode("utf-8", "replace")
    else:
        b = s.encode("utf-8", "replace")
    arr = (ctypes.c_ubyte * (len(b) or 1))(*(b if b else b"\x00"))
    _keep.append(arr)
    return arr, len(b)

def _decode_request_path(path):
    """Decode one URL-encoding layer without treating path '+' as a space."""
    raw = path.encode("utf-8", "replace")
    out = bytearray()
    i = 0
    while i < len(raw):
        if i + 2 < len(raw) and raw[i] == ord("%"):
            try:
                out.append(int(raw[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(raw[i])
        i += 1
    return bytes(out)

def normalize_input(inp):
    return normalize_encoded_input(inp)

def build_bundle(inp):
    del _keep[:]
    inp = dict(normalize_input(inp))
    method = inp.get("method") or "GET"
    version_value = inp.get("version")
    version = "HTTP/1.1" if version_value is None else str(version_value)
    data = inp.get("data")
    headers = dict(inp.get("headers", {}) or {})
    header_counts = dict(inp.get("_header_counts") or {
        name.lower(): 1 for name in headers
    })

    def header_key(name):
        return next((key for key in headers if key.lower() == name), None)

    transfer_encoding_key = header_key("transfer-encoding")
    content_length_key = header_key("content-length")
    content_type_key = header_key("content-type")

    if (inp.get("autocomplete_headers", True) and content_type_key is None and
            data is not None and str(data) != ""):
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        header_counts["content-type"] = 1

    if (transfer_encoding_key is not None and
            not inp.get("_preserve_conflicting_framing", False)):
        if content_length_key is not None:
            headers.pop(content_length_key)
        header_counts.pop("content-length", None)
    elif (inp.get("autocomplete_headers", True) and content_length_key is None and
          (data is not None or method.upper() in {"POST", "PUT", "PATCH"})):
        headers["Content-Length"] = str(len(body_bytes(data)))
        header_counts["content-length"] = 1

    if (data is not None and not inp.get("autocomplete_headers", True) and
            version.upper().startswith("HTTP/1.") and
            header_key("content-length") is None and
            header_key("transfer-encoding") is None):
        data = None

    inp["headers"] = headers
    inp["_header_counts"] = header_counts
    inp["method"] = method
    inp["data"] = data

    vars_ = []
    uri = inp.get("uri", "/") or "/"
    if "?" in uri:
        path, query = uri.split("?", 1)
    else:
        path, query = uri, ""
    if uri:
        p, pl = _buf(uri); vars_.append((p, pl, VT_URI, SC_URI, 0, 0, None, 0))
    if query:
        p, pl = _buf(query); vars_.append((p, pl, VT_ARGS, SC_URI, 0, (1<<0) | (1<<1), None, 0))

    for name, val in (inp.get("headers", {}) or {}).items():
        header_mask = HEADER_MASKS.get(name.lower(), 0)

        hb, hl = _buf(val)
        nb, nl = _buf(name)
        if name.lower() == "cookie":
            vars_.append((hb, hl, VT_COOKIE, SC_HDR, header_mask, (1<<2) | (1<<9), nb, nl))
            continue

        var_type = VT_HDR
        vars_.append((hb, hl, var_type, SC_HDR, header_mask, (1<<3), nb, nl))
    data = inp.get("data")
    if data:
        content_type = next(
            (str(value).lower() for key, value in headers.items()
             if key.lower() == "content-type"),
            "",
        )
        media_type = content_type.split(";", 1)[0].strip()
        is_json = media_type == "application/json" or media_type.endswith("+json")
        scope = SC_BODY | (SC_JSON if is_json else 0)
        collection_mask = (1 << 4) | ((1 << 6) if is_json else 0)
        d, dl = _buf(data)
        vars_.append((d, dl, VT_BODY, scope, 0, collection_mask, None, 0))
    if len(vars_) > LUMINA_BUNDLE_MAX_VARS:
        raise ValueError(
            f"request requires {len(vars_)} bundle variables; "
            f"capacity is {LUMINA_BUNDLE_MAX_VARS}"
        )
    b = LuminaBundle()
    b.count = len(vars_)
    for i, (p, pl, vt, sc, hm, cm, name_ptr, name_len) in enumerate(vars_):
        b.vars[i].ptr, b.vars[i].len = p, pl
        b.vars[i].var_type, b.vars[i].scope, b.vars[i].header_mask, b.vars[i].collection_mask = vt, sc, hm, cm
        b.vars[i].name, b.vars[i].name_len = name_ptr, name_len
        b.hdr_presence_mask |= hm
    # C4 STRUCTURAL: feed discrete CRS collections so the engine can run
    # 911100 (method), 920100 (request line), 913100 (scanner UA).
    method = inp.get("method")
    version_value = inp.get("version")
    version = "HTTP/1.1" if version_value is None else str(version_value)
    ua = next((v for k, v in (inp.get("headers") or {}).items() if k.lower() == "user-agent"), None)
    header_counts = inp.get("_header_counts") or {
        name.lower(): 1 for name in (inp.get("headers") or {})
    }
    if method:
        m, ml = _buf(method); b.req_method, b.req_method_len = m, ml
    if method and uri and version:
        line = f"{method} {uri} {version}"
        rl, rll = _buf(line); b.req_line, b.req_line_len = rl, rll
    if ua:
        ub, ubl = _buf(ua); b.user_agent, b.user_agent_len = ub, ubl
    vb, vbl = _buf(version); b.req_protocol, b.req_protocol_len = vb, vbl
    b.hdr_host_count = header_counts.get("host", 0)
    b.hdr_user_agent_count = header_counts.get("user-agent", 0)
    b.hdr_content_type_count = header_counts.get("content-type", 0)
    b.hdr_request_range_count = header_counts.get("request-range", 0)
    b.hdr_transfer_encoding_count = header_counts.get("transfer-encoding", 0)

    normalized_path = _decode_request_path(uri.split('?', 1)[0])
    fb, fbl = _buf(normalized_path)
    b.req_filename, b.req_filename_len = fb, fbl
    basename = normalized_path.rsplit(b'/', 1)[-1]
    bb, bbl = _buf(basename)
    b.req_basename, b.req_basename_len = bb, bbl
    content_type = next(
        (str(value).lower() for key, value in headers.items()
         if key.lower() == "content-type"),
        "",
    )
    media_type = content_type.split(";", 1)[0].strip()
    processor = None
    if media_type == "application/x-www-form-urlencoded":
        processor = "URLENCODED"
    elif media_type == "application/json" or media_type.endswith("+json"):
        processor = "JSON"
    elif media_type in {"application/xml", "text/xml"} or media_type.endswith("+xml"):
        processor = "XML"
    if processor:
        pb, pbl = _buf(processor)
        b.reqbody_processor, b.reqbody_processor_len = pb, pbl
    return b

def _scan(inp, audit_ids):
    b = build_bundle(inp)
    res = LuminaResult()
    state = ctypes.create_string_buffer(RULE_STATE_SIZE)
    lib.luminawaf_inspect_bundle(ctypes.byref(b), state, ctypes.byref(res))
    for rule_id in audit_ids:
        lib.luminawaf_audit_bundle_rule(ctypes.byref(b), state, rule_id)
    return res.threat_level, state

def scan(inp, audit_ids):
    """Scan with a 4s watchdog; return verdict ID, opaque match state, timeout."""
    def _handler(signum, frame):
        raise TimeoutError("scan timeout")
    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(4)
    try:
        matched, state = _scan(inp, audit_ids)
        return matched, state, False
    except TimeoutError:
        return 0, None, True
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)

def scan_direct(inp, expected_rule_id):
    """Run one production inspection without audit re-evaluation."""
    bundle = build_bundle(inp)
    result = LuminaResult()
    state = ctypes.create_string_buffer(RULE_STATE_SIZE)
    status = lib.luminawaf_inspect_bundle(
        ctypes.byref(bundle), state, ctypes.byref(result)
    )
    exact = bool(lib.luminawaf_rule_state_matched(state, expected_rule_id))
    return status, result.threat_level, exact

def supplemental_direct_cases():
    multipart_body = (
        b"--lumina-boundary\r\n"
        b"Bad\tName: value\r\n\r\n"
        b"clean value\r\n"
        b"--lumina-boundary--\r\n"
    )
    common_headers = {"Host": "localhost", "User-Agent": "lumina-coverage"}
    return [
        (
            "invalid-content-length",
            920160,
            {
                "uri": "/",
                "headers": {**common_headers, "Content-Length": "12x"},
                "autocomplete_headers": False,
            },
        ),
        (
            "conflicting-content-length-transfer-encoding",
            920181,
            {
                "uri": "/",
                "headers": {
                    **common_headers,
                    "Content-Length": "12",
                    "Transfer-Encoding": "chunked",
                },
                "autocomplete_headers": False,
                "_preserve_conflicting_framing": True,
            },
        ),
        (
            "raw-uri-fragment",
            920610,
            {"uri": "/path#fragment", "headers": common_headers},
        ),
        (
            "duplicate-content-type-count",
            920620,
            {
                "uri": "/",
                "headers": {**common_headers, "Content-Type": "text/plain"},
                "_header_counts": {
                    "host": 1,
                    "user-agent": 1,
                    "content-type": 2,
                },
            },
        ),
        (
            "multipart-invalid-part-header-name",
            922130,
            {
                "method": "POST",
                "uri": "/upload",
                "headers": {
                    **common_headers,
                    "Content-Type":
                        "multipart/form-data; boundary=lumina-boundary",
                },
                "data": multipart_body,
            },
        ),
    ]

def rid_of(doc):
    m = doc.get("meta", {}) or {}
    return str(m.get("rule_id") or doc.get("rule_id") or "?")

def _id_set(values):
    out = set()
    for v in values or []:
        try:
            out.add(int(str(v)))
        except ValueError:
            continue
    return out

def load_rule_paranoia(rules_dir):
    """Load the PL contract from the same ModSecurity .conf input as the translator."""
    tools_dir = os.path.join(ROOT, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    from sidecar_translator import parse_conf_files
    return {
        int(rule["id"]): int(rule["paranoia"])
        for rule in parse_conf_files(rules_dir)
        if rule.get("id") is not None and rule.get("paranoia") is not None
    }

def load_config_inactive_rule_ids(rules_dir, setup_conf):
    """Find chains gated by TX variables with no producer in active config.

    FTW contains positive tests for optional CRS policies that are commented
    out in the default setup. Counting those as misses would compare Lumina
    against a configuration ModSecurity is not running.
    """
    tools_dir = os.path.join(ROOT, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    from sidecar_translator import (parse_conf_files, group_rule_chains,
                                    _single_positive_binding,
                                    _raw_setvar_assignments)
    rule_statements = parse_conf_files(rules_dir)
    setup_statements = parse_conf_files(setup_conf) if setup_conf else []
    written_tx = {
        name.lower()
        for rule in setup_statements + rule_statements
        for name, _ in _raw_setvar_assignments(rule)
    }
    inactive = set()
    for rule in group_rule_chains(rule_statements):
        if not rule.get("id") or not rule.get("_chain_members"):
            continue
        binding = _single_positive_binding(rule)
        if (binding is None or not binding.count or binding.collection != "TX" or
                binding.selector_kind != "literal"):
            continue
        if binding.selector.lower() not in written_tx:
            inactive.add(int(rule["id"]))
    return inactive

def filter_ids_for_pl(values, rule_paranoia, target_pl):
    """Keep unknown IDs visible; exclude only IDs proven to be above target PL."""
    result = []
    for value in values:
        try:
            rule_id = int(str(value))
        except ValueError:
            result.append(value)
            continue
        if rule_paranoia.get(rule_id, target_pl) <= target_pl:
            result.append(value)
    return result

def filter_files_for_scope(files, root, scope):
    """Select request or response FTW files without hiding custom fixtures."""
    if scope == "all":
        return files
    selected = []
    root_name = os.path.basename(os.path.abspath(root))
    for path in files:
        rel = os.path.relpath(path, root)
        parts = (root_name,) + tuple(rel.split(os.sep))
        kind = next((
            "inbound" if part.startswith("REQUEST-") else "outbound"
            for part in parts
            if part.startswith("REQUEST-") or part.startswith("RESPONSE-")
        ), None)
        if kind is None or kind == scope:
            selected.append(path)
    return selected

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=DEFAULT_DIR)
    ap.add_argument("--rules-dir", default=DEFAULT_RULES_DIR)
    ap.add_argument("--setup-conf", default=DEFAULT_SETUP_CONF)
    ap.add_argument("--scope", choices=("inbound", "outbound", "all"), default="inbound")
    ap.add_argument("--pl", type=int, default=2)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--report-limit", type=int, default=2000)
    ap.add_argument("--json-output")
    ap.add_argument("--coverage-output")
    args = ap.parse_args()
    if args.setup_conf is None:
        args.setup_conf = materialize_default_setup_conf()
    import yaml
    files = sorted(glob.glob(os.path.join(args.dir, "**", "*.yaml"), recursive=True))
    files = filter_files_for_scope(files, args.dir, args.scope)
    rule_paranoia = load_rule_paranoia(args.rules_dir)
    config_inactive_ids = load_config_inactive_rule_ids(args.rules_dir, args.setup_conf)
    tools_dir = os.path.join(ROOT, "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    from audit_crs_mechanisms import audit_rules
    coverage_tracker = CoverageTracker(
        audit_rules(Path(args.rules_dir), args.pl, Path(ROOT) / "src"),
        config_inactive_rule_ids=config_inactive_ids,
    )

    C = dict(pos=0, pos_block=0, pos_exact=0, neg=0, neg_ok=0, verdict=0, verdict_ok=0,
             transport_skip=0, pl_skip=0, config_skip=0, timeout=0, err=0)
    failures = []
    count = 0
    t0 = time.time()
    for f in files:
        try:
            doc = yaml.safe_load(open(f))
        except Exception:
            continue
        if not doc or "tests" not in doc:
            continue
        rid = rid_of(doc)
        for t in doc["tests"]:
            for stage_index, stage in enumerate(t.get("stages", [])):
                inp = stage.get("input", {})
                out = stage.get("output", {}) or {}
                log = out.get("log", {}) or {}
                expect = log.get("expect_ids") or []
                no_expect = log.get("no_expect_ids") or []

                status = out.get("status")
                if not (expect or no_expect or status):
                    continue
                if expect:
                    expect = filter_ids_for_pl(expect, rule_paranoia, args.pl)
                    if not expect:
                        C["pl_skip"] += 1
                        continue
                    active_expect = [value for value in expect
                                     if int(str(value)) not in config_inactive_ids]
                    if not active_expect:
                        C["config_skip"] += 1
                        continue
                    expect = active_expect
                if no_expect:
                    no_expect = filter_ids_for_pl(no_expect, rule_paranoia, args.pl)
                    if not no_expect:
                        C["pl_skip"] += 1
                        continue
                # HTTP 400 is produced by the server parser before CRS sees a
                # transaction. An offline WAF engine cannot meaningfully run
                # expect/no-expect assertions over a rejected wire request.
                if status is not None and str(status) == "400":
                    C["transport_skip"] += 1
                    continue
                normalized_inp = normalize_input(inp)
                body_class = request_body_class(normalized_inp)
                test_ref = (
                    f"{os.path.relpath(f, args.dir)}::"
                    f"{t.get('test_id')}::{stage_index}"
                )
                if expect:
                    coverage_tracker.observe_reference_positive(
                        test_ref, _id_set(expect), body_class
                    )
                elif no_expect:
                    coverage_tracker.observe_negative(
                        test_ref, _id_set(no_expect), ()
                    )
                count += 1
                try:
                    audit_ids = _id_set(expect) | _id_set(no_expect)
                    matched, state, to = scan(normalized_inp, audit_ids)
                except Exception as e:
                    C["err"] += 1
                    failures.append((rid, t.get("test_id"), repr(e), inp.get("uri"), 0, "exception", f))
                    continue
                if to:
                    C["timeout"] += 1
                    failures.append((rid, t.get("test_id"), "timeout", inp.get("uri"), 0, "timeout", f))
                    continue
                blocked = (matched != 0)
                if expect:
                    expect_set = _id_set(expect)
                    exact_ids = {
                        rule_id
                        for rule_id in expect_set
                        if lib.luminawaf_rule_state_matched(state, rule_id)
                    }
                    coverage_tracker.observe_lumina_exact(
                        test_ref, exact_ids, body_class
                    )
                    C["pos"] += 1
                    if blocked:
                        C["pos_block"] += 1
                    exact_match = any(
                        lib.luminawaf_rule_state_matched(state, rule_id)
                        for rule_id in expect_set
                    )
                    if exact_match:
                        C["pos_exact"] += 1
                    elif blocked:
                        failures.append((rid, t.get("test_id"), t.get("desc"), inp.get("uri"), matched, "pos-wrong-rule", f))
                    else:
                        failures.append((rid, t.get("test_id"), t.get("desc"), inp.get("uri"), matched, "pos-miss", f))
                elif no_expect:
                    no_expect_set = _id_set(no_expect)
                    C["neg"] += 1
                    fired_ids = {
                        rule_id
                        for rule_id in no_expect_set
                        if lib.luminawaf_rule_state_matched(state, rule_id)
                    }
                    excluded_fired = bool(fired_ids)
                    coverage_tracker.observe_negative(
                        test_ref, no_expect_set, no_expect_set - fired_ids
                    )
                    if not excluded_fired:
                        C["neg_ok"] += 1
                    else:
                        failures.append((rid, t.get("test_id"), t.get("desc"), inp.get("uri"), matched, "neg-excluded-fired", f))
                elif status is not None:
                    C["verdict"] += 1
                    exp_block = str(status).startswith("403")
                    if blocked == exp_block:
                        C["verdict_ok"] += 1
                    else:
                        failures.append((rid, t.get("test_id"), t.get("desc"), inp.get("uri"), matched, f"verdict-exp{status}", f))
            if args.limit and count >= args.limit:
                break
        if args.limit and count >= args.limit:
            break

    supplemental_results = []
    if not args.limit:
        for name, rule_id, request in supplemental_direct_cases():
            try:
                status, threat, exact = scan_direct(request, rule_id)
            except Exception as error:
                status, threat, exact = -1, 0, False
                supplemental_results.append(
                    {
                        "name": name,
                        "rule_id": rule_id,
                        "status": status,
                        "threat": threat,
                        "exact": exact,
                        "exception": repr(error),
                    }
                )
            else:
                supplemental_results.append(
                    {
                        "name": name,
                        "rule_id": rule_id,
                        "status": status,
                        "threat": threat,
                        "exact": exact,
                    }
                )
            coverage_tracker.observe_supplemental_direct(
                f"supplemental::{name}", rule_id, exact
            )

    pos_rate = 100.0*C["pos_block"]/C["pos"] if C["pos"] else 0
    pos_exact_rate = 100.0*C["pos_exact"]/C["pos"] if C["pos"] else 0
    neg_rate = 100.0*C["neg_ok"]/C["neg"] if C["neg"] else 0
    verdict_rate = 100.0*C["verdict_ok"]/C["verdict"] if C["verdict"] else 0
    scored = C["pos"] + C["neg"] + C["verdict"]
    overall = 100.0*(C["pos_exact"]+C["neg_ok"]+C["verdict_ok"])/scored if scored else 0
    generated_manifest = Path(ROOT) / "src/generated/rule_manifest.json"
    library_path = Path(SO)
    setup_path = Path(args.setup_conf) if args.setup_conf else None
    corpus_root = Path(args.dir)
    rules_root = Path(args.rules_dir)
    try:
        crs_commit = subprocess.check_output(
            ["git", "-C", str(rules_root.parent), "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        crs_commit = "unavailable"
    coverage_report = coverage_tracker.report(
        {
            "scope": args.scope,
            "target_pl": args.pl,
            "complete_test_corpus": not bool(args.limit),
            "test_limit": args.limit or None,
            "evaluated_tests": count,
            "test_file_count": len(files),
            "test_corpus_sha256": sha256_tree(
                (Path(path) for path in files), corpus_root
            ),
            "rules_sha256": sha256_tree(
                (
                    path
                    for path in rules_root.rglob("*")
                    if path.is_file() and path.suffix in {".conf", ".data"}
                ),
                rules_root,
            ),
            "crs_commit": crs_commit,
            "generated_manifest_sha256": (
                sha256_file(generated_manifest)
                if generated_manifest.is_file()
                else "unavailable"
            ),
            "lumina_library_sha256": (
                sha256_file(library_path)
                if library_path.is_file()
                else "unavailable"
            ),
            "setup_config_sha256": (
                sha256_file(setup_path)
                if setup_path is not None and setup_path.is_file()
                else "unavailable"
            ),
        }
    )
    reference_coverage = coverage_report["coverage"]["reference_positive"]
    active_reference_coverage = coverage_report["coverage"][
        "config_resolved_reference_positive"
    ]
    implementation_coverage = coverage_report["coverage"]["lumina_exact_rule"]
    supplemental_coverage = coverage_report["coverage"][
        "supplemental_direct_exact"
    ]
    combined_internal_coverage = coverage_report["coverage"][
        "combined_internal_active_implementation"
    ]
    print(f"elapsed: {time.time()-t0:.1f}s  tests={count}")
    print(f"scope={args.scope} files={len(files)}")
    print(f"positive(block) : {pos_rate:.2f}%  ({C['pos_block']}/{C['pos']})")
    print(f"positive(exact) : {pos_exact_rate:.2f}%  ({C['pos_exact']}/{C['pos']})")
    print(f"negative(excl)  : {neg_rate:.2f}%  ({C['neg_ok']}/{C['neg']})")
    print(f"verdict(status) : {verdict_rate:.2f}%  ({C['verdict_ok']}/{C['verdict']})")
    print(f"transport_skipped={C['transport_skip']}")
    print(f"pl_skipped={C['pl_skip']} target_pl={args.pl}")
    print(f"config_skipped={C['config_skip']}")
    print(f"timeouts={C['timeout']} exceptions={C['err']}")
    print(f"OVERALL PARITY  : {overall:.2f}%")
    print(
        "PL2 REFERENCE RULE COVERAGE: "
        f"{reference_coverage['percent']:.2f}% "
        f"({reference_coverage['matched']}/{reference_coverage['total']})"
    )
    print(
        "PL2 CONFIG-RESOLVED RULE COVERAGE: "
        f"{active_reference_coverage['percent']:.2f}% "
        f"({active_reference_coverage['matched']}/"
        f"{active_reference_coverage['total']})"
    )
    print(
        "LUMINA EXACT RULE COVERAGE: "
        f"{implementation_coverage['percent']:.2f}% "
        f"({implementation_coverage['matched']}/{implementation_coverage['total']})"
    )
    print(
        "SUPPLEMENTAL DIRECT EXACT COVERAGE: "
        f"{supplemental_coverage['percent']:.2f}% "
        f"({supplemental_coverage['matched']}/{supplemental_coverage['total']})"
    )
    print(
        "COMBINED INTERNAL ACTIVE IMPLEMENTATION COVERAGE: "
        f"{combined_internal_coverage['percent']:.2f}% "
        f"({combined_internal_coverage['matched']}/"
        f"{combined_internal_coverage['total']})"
    )
    print("PL2 COVERAGE REFERENCE: internal FTW expectations; ModSecurity runtime verified=false")
    from collections import Counter
    fc = Counter(f[0] for f in failures)
    kc = Counter(f[5] for f in failures)
    wc = Counter((f[0], f[5], f[4]) for f in failures)
    print("\nfailure kinds:")
    for kind, c in kc.most_common():
        print(f"  {kind}: {c}")
    print(f"\nfailures={len(failures)} top rules:")
    for r, c in fc.most_common(30):
        print(f"  rule {r}: {c}")
    print("\ntop rule/kind/matched triples:")
    for (r, kind, matched), c in wc.most_common(30):
        print(f"  rule {r} kind={kind} matched={matched}: {c}")
    if args.json_output:
        payload = {
            "schema": 1,
            "oracle": "ModSecurity-compatible pinned CRS PL2 expectations",
            "scope": args.scope,
            "target_pl": args.pl,
            "files": len(files),
            "tests": count,
            "scored_tests": scored,
            "overall_parity": overall,
            "metrics": {
                "positive_block": {"matched": C["pos_block"], "total": C["pos"], "percent": pos_rate},
                "positive_exact": {"matched": C["pos_exact"], "total": C["pos"], "percent": pos_exact_rate},
                "negative_exclusion": {"matched": C["neg_ok"], "total": C["neg"], "percent": neg_rate},
                "verdict_status": {"matched": C["verdict_ok"], "total": C["verdict"], "percent": verdict_rate},
            },
            "skips": {
                "transport": C["transport_skip"],
                "paranoia_level": C["pl_skip"],
                "configuration": C["config_skip"],
            },
            "timeouts": C["timeout"],
            "exceptions": C["err"],
            "failure_count": len(failures),
            "failure_kinds": dict(kc),
            "pl2_rule_coverage": coverage_report,
            "supplemental_direct_results": supplemental_results,
            "failures": [
                {
                    "rule_id": r, "test_id": tid, "description": desc, "uri": uri,
                    "matched_rule_id": matched, "kind": kind, "source": path,
                }
                for r, tid, desc, uri, matched, kind, path in failures[:args.report_limit]
            ],
        }
        output = os.path.abspath(args.json_output)
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
    if args.coverage_output:
        output = os.path.abspath(args.coverage_output)
        os.makedirs(os.path.dirname(output), exist_ok=True)
        with open(output, "w", encoding="utf-8") as fh:
            json.dump(coverage_report, fh, indent=2, sort_keys=True, default=str)
            fh.write("\n")
    with open(os.path.join(HERE, "crs_parity_report.txt"), "w") as fh:
        fh.write(f"OVERALL PARITY: {overall:.2f}%\nscope={args.scope} files={len(files)}\n"
                 f"pos_block={pos_rate:.2f} pos_exact={pos_exact_rate:.2f} "
                 f"neg={neg_rate:.2f} verdict={verdict_rate:.2f}\n")
        fh.write(f"transport_skipped={C['transport_skip']} pl_skipped={C['pl_skip']} target_pl={args.pl} timeouts={C['timeout']} exceptions={C['err']}\n")
        fh.write(
            f"pl2_reference_rule_coverage={reference_coverage['percent']:.2f} "
            f"({reference_coverage['matched']}/{reference_coverage['total']}) "
            f"lumina_exact_rule_coverage={implementation_coverage['percent']:.2f} "
            f"({implementation_coverage['matched']}/{implementation_coverage['total']}) "
            "modsecurity_runtime_verified=false\n"
        )
        for r, tid, desc, uri, matched, kind, path in failures[:args.report_limit]:
            fh.write(f"rule={r} test={tid} kind={kind} matched={matched} uri={uri!r} file={path!r} desc={desc!r}\n")

if __name__ == "__main__":
    main()
