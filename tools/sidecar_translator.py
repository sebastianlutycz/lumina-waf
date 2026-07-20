#!/usr/bin/env python3
"""
sidecar_translator.py  (LuminaWAF v0.4 — canonical CRS -> native compiler)

Compiles the OWASP CRS ruleset into branchless, first-byte-bitmask-routed
native C (Atomic Branchless Bitmask philosophy). Per IMPORTANT.md the engine is
a WAF *compiler*, not an interpreter: zero runtime .conf parsing.

Design (ABB):
  * Each detection rule -> `lumina_scan_rule_<id>(data,len,offset)` compiled from
    the regex AST into `match &= (cur<len && cond); cur += match;` (no per-rule
    branch, single terminal return).
  * O(1) first-byte routing: `g_short_rule_mask[256][2]` maps a byte to the
    bitmask of rule indices whose pattern can start with that byte. The runtime
    scans set bits via `__builtin_ctzll` (no branch per rule) -> flat p99.
  * O(1) dedup + scalar anomaly scoring in the runtime (luminawaf.cpp).

v9 additions vs the legacy translator:
  G1  Do NOT skip `pass,`/`nolog,` rules. Real CRS detection rules ARE pass rules
      that setvar:tx.anomaly_score. We classify detection vs gating vs blocking-eval.
  G2  Paranoia gating: only emit rules with rule_pl <= --pl (default 2). Gating is
      resolved at COMPILE TIME -> zero runtime cost (flat p99 preserved).
  G3  `t:` transforms emitted as a per-rule transform_mask; runtime applies only the
      transforms the rule needs.
  G4  `@pmFromFile` -> generated branchless phrase scanner (first-byte bitmask +
      memcmp over the data-file literal set).
  G5  `chain` rules -> sequential AND of link matchers.
  G6  Emits the enriched metadata the runtime expects:
      g_short_rule_mask/scope/table/paranoia/category/hdr_mask/var_type/score.
  G7  Score = ModSecurity severity model (critical_anomaly_score=5 default).

Outputs (self-contained, compiled by the public CMake build):
  * src/parser_rules_*.c   — chunks: per-rule matchers + phrase scanners + tables
  * src/parser_input.c     — lumina_waf_scan (delegates to the table scan) + helpers
  * src/generated/crs_short_rules.h — declarations + self-contained CAT/SCOPE/VAR bits

Usage:
  sidecar_translator.py <crs_rules_dir> <out_dir> [--pl N] [--out-src SRC_DIR]
"""
import sys
import os
import re
import glob
import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
_TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
if _TOOLS_DIR not in sys.path:
    sys.path.insert(0, _TOOLS_DIR)
from regex_dfa import (UnsupportedRegex as DfaUnsupportedRegex,
                       compile_bitset_nfa,
                       compile_mandatory_seed_cover,
                       compile_seeded_fast_accept_branches, compile_dfa_ast,
                       emit_dfa_c, emit_bitset_nfa_c, inline_flag_enabled,
                       parse_regex_ast, requires_dfa)


_GENERATED_CONST_ARRAY_RE = re.compile(
    r"static const\s+"
    r"(?P<type>uint(?:8|16|32|64)_t|unsigned char)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"\[(?P<count>[0-9]+)\]\s*=\s*"
    r"\{(?P<body>.*?)\};",
    re.DOTALL,
)


def intern_generated_const_arrays(chunks, min_array_bytes=1024):
    """Intern byte-identical generated arrays without adding runtime dispatch.

    Type and element count are part of the identity. Small arrays remain local
    so the compiler can propagate their values inside one translation unit.
    Shared symbols use hidden ELF visibility so PIC code can address them
    directly on x86_64 and AArch64 instead of loading an interposable address
    through the GOT.
    """
    records = []
    groups = {}
    type_sizes = {
        'uint8_t': 1,
        'unsigned char': 1,
        'uint16_t': 2,
        'uint32_t': 4,
        'uint64_t': 8,
    }
    for chunk_index, code in enumerate(chunks):
        for match in _GENERATED_CONST_ARRAY_RE.finditer(code):
            element_type = match.group('type')
            count = int(match.group('count'))
            normalized_body = re.sub(r'\s+', '', match.group('body'))
            identity = (element_type, count, normalized_body)
            record = {
                'chunk_index': chunk_index,
                'start': match.start(),
                'end': match.end(),
                'name': match.group('name'),
                'type': element_type,
                'count': count,
                'body': match.group('body'),
                'bytes': count * type_sizes[element_type],
            }
            records.append(record)
            groups.setdefault(identity, []).append(record)

    selected = []
    for identity, members in groups.items():
        if len(members) < 2 or members[0]['bytes'] < min_array_bytes:
            continue
        digest_input = (
            f'{identity[0]}\0{identity[1]}\0{identity[2]}'.encode('ascii'))
        digest = hashlib.sha256(digest_input).hexdigest()[:24]
        type_tag = identity[0].replace(' ', '_').replace('_t', '')
        selected.append((
            f'lumina_shared_{type_tag}_{digest}',
            members,
        ))

    removals = [[] for _ in chunks]
    replacements = [{} for _ in chunks]
    declarations = []
    definitions = []
    reclaimed_bytes = 0
    for shared_name, members in sorted(selected, key=lambda item: item[0]):
        representative = members[0]
        element_type = representative['type']
        count = representative['count']
        declarations.append(
            f'extern const {element_type} {shared_name}[{count}] '
            f'__attribute__((visibility("hidden")));')
        definitions.append(
            f'const {element_type} {shared_name}[{count}] '
            f'__attribute__((visibility("hidden"))) = '
            f'{{{representative["body"]}}};')
        reclaimed_bytes += (len(members) - 1) * representative['bytes']
        for member in members:
            chunk_index = member['chunk_index']
            removals[chunk_index].append((member['start'], member['end']))
            replacements[chunk_index][member['name']] = shared_name

    rewritten = []
    for chunk_index, original in enumerate(chunks):
        code = original
        for start, end in sorted(removals[chunk_index], reverse=True):
            code = code[:start] + code[end:]
        mapping = replacements[chunk_index]
        if mapping:
            names = sorted(mapping, key=len, reverse=True)
            symbol_re = re.compile(
                r'\b(?:' + '|'.join(re.escape(name) for name in names) + r')\b')
            code = symbol_re.sub(lambda match: mapping[match.group(0)], code)
            include = '#include "generated/crs_shared_tables.h"\n'
            if include not in code:
                code = include + code
        rewritten.append(code)

    guard = 'LUMINA_CRS_SHARED_TABLES_H'
    header = (
        f'#ifndef {guard}\n#define {guard}\n'
        '#include <stdint.h>\n\n' +
        '\n'.join(declarations) +
        f'\n\n#endif /* {guard} */\n'
    )
    source = (
        '#include <stdint.h>\n'
        '#include "generated/crs_shared_tables.h"\n\n' +
        '\n\n'.join(definitions) + '\n'
    )
    stats = {
        'input_arrays': len(records),
        'shared_arrays': len(selected),
        'replaced_arrays': sum(len(members) for _, members in selected),
        'reclaimed_bytes': reclaimed_bytes,
    }
    return rewritten, header, source, stats


def regex_matches_empty(pattern):
    """Return whether the native byte-language accepts an empty value.

    This is evaluated once while translating. Runtime uses the resulting bitset
    to avoid routing a present-but-empty collection through every generated
    predicate.
    """
    try:
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
        dfa = compile_dfa_ast(ast, ignore_case, dot_all, state_budget=4096)
    except (DfaUnsupportedRegex, ValueError, OverflowError):
        return False
    # Empty input starts at offset zero: previous_word=0 and bol=1.
    return bool(dfa['eof_accept'][0][2])

LUMINA_MARKER_REGISTRY_VERSION = "v0.4-clean"
LUMINA_MARKER_BUILD_TAG = "a4e12f09bc8736d5"
LUMINA_MARKER_GENERATOR_FINGERPRINT = "lumina-waf/v0.4/generator/a4e12f09bc8736d5"

# ---------------------------------------------------------------------------
# Category / scope / var bitmaps (self-contained; mirrors runtime expectations)
# ---------------------------------------------------------------------------
CAT = {
    'SQLI':   1 << 0,
    'XSS':    1 << 1,
    'RCE':    1 << 2,
    'LFI':    1 << 3,
    'RFI':    1 << 4,
    'PHP':    1 << 5,
    'GEN':    1 << 6,
    'PROTO':  1 << 7,
}
SCOPE_URI     = 1 << 0
SCOPE_HEADERS = 1 << 1
SCOPE_BODY    = 1 << 2
VAR_ANY = 0xFF
VAR_TYPE_SLOTS = 15
HEADER_MASKS = {
    'CONTENT-LENGTH':  1 << 0,
    'REQUEST-RANGE':   1 << 1,
    'CONNECTION':      1 << 2,
    'HOST':            1 << 3,
    'USER-AGENT':      1 << 4,
    'CONTENT-TYPE':    1 << 5,
    'ACCEPT-ENCODING': 1 << 6,
    'ACCEPT':          1 << 7,
    'COOKIE':          1 << 8,
    'REFERER':         1 << 9,
    'X-FILENAME':      1 << 10,
    'X_FILENAME':      1 << 10,
    'X.FILENAME':      1 << 10,
    'X-FILE-NAME':     1 << 10,
    'RANGE':           1 << 11,
}
HEADER_SELECTOR_SLOTS = 1 + max(mask.bit_length() for mask in HEADER_MASKS.values())

# Counted request-header collections exposed by LuminaBundle. A header without
# a dedicated counter can still implement `@eq 0` through hdr_presence_mask,
# but no other numeric comparison is exact and therefore must remain rejected.
HEADER_COUNT_FIELDS = {
    'HOST':              'hdr_host_count',
    'USER-AGENT':        'hdr_user_agent_count',
    'CONTENT-TYPE':      'hdr_content_type_count',
    'REQUEST-RANGE':     'hdr_request_range_count',
    'TRANSFER-ENCODING': 'hdr_transfer_encoding_count',
}

REQUEST_METADATA_FIELDS = {
    'REQUEST_METHOD': ('req_method', 'req_method_len'),
    'REQUEST_PROTOCOL': ('req_protocol', 'req_protocol_len'),
    'REQBODY_PROCESSOR': ('reqbody_processor', 'reqbody_processor_len'),
}

COLLECTION_SPECS = {
    'REQUEST_URI':          ('REQUEST_URI', SCOPE_URI, 1 << 0, 0),
    'REQUEST_URI_RAW':      ('REQUEST_URI_RAW', SCOPE_URI, 1 << 0, 0),
    'REQUEST_FILENAME':     ('REQUEST_FILENAME', SCOPE_URI, 1 << 11, "LUMINA_COL_REQUEST_FILENAME"),
    'REQUEST_BASENAME':     ('REQUEST_BASENAME', SCOPE_URI, 1 << 12, "LUMINA_COL_REQUEST_BASENAME"),
    'PATH_INFO':            ('PATH_INFO', SCOPE_URI, 1 << 0, 0),
    'REQUEST_LINE':         ('REQUEST_LINE', SCOPE_URI, 1 << 0, 0),
    'ARGS':                 ('ARGS', SCOPE_URI | SCOPE_BODY, 1 << 1, "LUMINA_COL_ARGS"),
    'ARGS_NAMES':           ('ARGS_NAMES', SCOPE_URI | SCOPE_BODY, 1 << 6, "LUMINA_COL_ARGS_NAMES"),
    'ARGS_GET':             ('ARGS_GET', SCOPE_URI, 1 << 1, "LUMINA_COL_ARGS"),
    'ARGS_GET_NAMES':       ('ARGS_GET_NAMES', SCOPE_URI, 1 << 6, "LUMINA_COL_ARGS_NAMES"),
    'ARGS_POST':            ('ARGS_POST', SCOPE_BODY, 1 << 1, "LUMINA_COL_ARGS"),
    'ARGS_POST_NAMES':      ('ARGS_POST_NAMES', SCOPE_BODY, 1 << 6, "LUMINA_COL_ARGS_NAMES"),
    'QUERY_STRING':         ('QUERY_STRING', SCOPE_URI, 1 << 8, 0),
    'REQUEST_COOKIES':      ('REQUEST_COOKIES', SCOPE_HEADERS, 1 << 2, "LUMINA_COL_REQUEST_COOKIES"),
    'REQUEST_COOKIES_NAMES':('REQUEST_COOKIES_NAMES', SCOPE_HEADERS, 1 << 9, "LUMINA_COL_REQUEST_COOKIES_NAMES"),
    'REQUEST_HEADERS':      ('REQUEST_HEADERS', SCOPE_HEADERS, 1 << 3, "LUMINA_COL_REQUEST_HEADERS"),
    'REQUEST_HEADERS_NAMES':('REQUEST_HEADERS_NAMES', SCOPE_HEADERS, 1 << 3, 0),
    'REQUEST_BODY':         ('REQUEST_BODY', SCOPE_BODY, 1 << 4, "LUMINA_COL_REQUEST_BODY"),
    'XML':                  ('XML', SCOPE_BODY, (1 << 13) | (1 << 14), "LUMINA_COL_XML"),
    'JSON':                 ('JSON', SCOPE_BODY, 1 << 4, "LUMINA_COL_JSON"),
    'FILES':                ('FILES', SCOPE_BODY, 1 << 7, "LUMINA_COL_FILES"),
    'FILES_NAMES':          ('FILES_NAMES', SCOPE_BODY, 1 << 10, "LUMINA_COL_FILES_NAMES"),
    'REQBODY_PROCESSOR':    ('REQBODY_PROCESSOR', 0, 0, 0),
    'REQUEST_METHOD':       ('REQUEST_METHOD', 0, 0, 0),
    'REQUEST_PROTOCOL':     ('REQUEST_PROTOCOL', 0, 0, 0),
    'REQUEST_BODY_LENGTH':  ('REQUEST_BODY_LENGTH', 0, 0, 0),
    'TX':                   ('TX', 0, 0, 0),
}


@dataclass(frozen=True)
class VariableBinding:
    raw: str
    collection: str
    selector: str | None
    selector_kind: str
    excluded: bool
    count: bool
    recognized: bool


def split_variable_expression(expression):
    """Split ModSecurity variable lists without breaking `/regex|selectors/`."""
    if not expression:
        return []
    out = []
    cur = []
    in_regex = False
    escaped = False
    for ch in expression:
        if escaped:
            cur.append(ch)
            escaped = False
            continue
        if ch == '\\':
            cur.append(ch)
            escaped = True
            continue
        if ch == '/':
            cur.append(ch)
            in_regex = not in_regex
            continue
        if ch == '|' and not in_regex:
            token = ''.join(cur).strip()
            if token:
                out.append(token)
            cur = []
            continue
        cur.append(ch)
    token = ''.join(cur).strip()
    if token:
        out.append(token)
    return out


def parse_variable_bindings(expression):
    bindings = []
    for raw_token in split_variable_expression(expression):
        token = raw_token.strip()
        excluded = False
        count = False
        while token and token[0] in '!&':
            excluded |= token[0] == '!'
            count |= token[0] == '&'
            token = token[1:].lstrip()
        base, sep, selector = token.partition(':')
        collection = base.strip().upper()
        selector = selector.strip() if sep else None
        selector_kind = 'none'
        if selector:
            selector_kind = 'regex' if len(selector) >= 2 and selector.startswith('/') and selector.endswith('/') else 'literal'
        bindings.append(VariableBinding(
            raw=raw_token,
            collection=collection,
            selector=selector,
            selector_kind=selector_kind,
            excluded=excluded,
            count=count,
            recognized=collection in COLLECTION_SPECS,
        ))
    return bindings


def compile_binding_contract(bindings):
    scope = 0
    var_type_mask = 0
    header_mask = 0
    collection_mask_str = []
    has_generic_headers = False
    unsupported = []
    for binding in bindings:
        spec = COLLECTION_SPECS.get(binding.collection)
        if spec is None:
            unsupported.append(f"unknown-collection:{binding.collection}")
            continue
        _, binding_scope, binding_var_mask, binding_col_mask = spec
        if not binding.excluded:
            scope |= binding_scope
            var_type_mask |= binding_var_mask
            if binding_col_mask:
                collection_mask_str.append(binding_col_mask)
        if binding.collection == 'REQUEST_HEADERS':
            if binding.selector_kind == 'none' and not binding.excluded:
                has_generic_headers = True
            elif binding.selector_kind == 'literal' and not binding.excluded:
                mask = HEADER_MASKS.get(binding.selector.upper(), 0)
                if mask:
                    header_mask |= mask
                else:
                    unsupported.append(f"unbound-header:{binding.selector}")
            elif binding.selector_kind == 'regex':
                unsupported.append(f"regex-selector:{binding.selector}")
        if binding.count:
            unsupported.append(f"count-collection:{binding.collection}")
    if has_generic_headers:
        header_mask = 0
    return {
        'scope': scope,
        'var_type_mask': var_type_mask,
        'header_mask': header_mask,
        'collection_mask': " | ".join(sorted(set(collection_mask_str))) if collection_mask_str else "0",
        'unsupported': sorted(set(unsupported)),
        'recognized': bool(bindings) and all(b.recognized for b in bindings),
    }

# CRS file-number -> (paranoia_level, category) for the default 3.x/4.x layout.
FILE_MAP = {
    '911': (1, 'PROTO'), '913': (1, 'PROTO'), '920': (1, 'PROTO'),
    '921': (1, 'PROTO'),
    '930': (2, 'LFI'), '931': (2, 'RFI'), '932': (2, 'RCE'),
    '933': (2, 'PHP'), '934': (2, 'RCE'),
    '941': (2, 'XSS'), '942': (2, 'SQLI'), '943': (2, 'GEN'),
    '944': (2, 'RCE'), '946': (2, 'RCE'), '947': (2, 'RCE'), '948': (2, 'RCE'),
    '949': (2, 'PROTO'), '950': (3, 'GEN'), '951': (3, 'GEN'),
    '952': (3, 'GEN'), '953': (3, 'GEN'), '954': (3, 'GEN'),
}

# ---------------------------------------------------------------------------
# Config / action tokeniser (quote-aware)
# ---------------------------------------------------------------------------
def tokenize_actions(actions_str):
    """Split a SecRule actions string on commas, respecting ' and " quotes."""
    out = []
    cur = ''
    quote = None
    i = 0
    while i < len(actions_str):
        c = actions_str[i]
        if quote:
            cur += c
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ('"', "'"):
            quote = c
            cur += c
        elif c == ',':
            out.append(cur.strip())
            cur = ''
        else:
            cur += c
        i += 1
    if cur.strip():
        out.append(cur.strip())
    return out

def parse_action_kv(actions):
    """Return dict of action -> value (value None if bare)."""
    kv = {}
    for a in actions:
        m = re.match(r'^([a-zA-Z_]+):(.*)$', a, re.S)
        if m:
            kv[m.group(1)] = m.group(2).strip()
        else:
            kv[a] = None
    return kv

# ---------------------------------------------------------------------------
# Quote scanner (escape-aware: skips \")
# ---------------------------------------------------------------------------
def scan_quote(text, i):
    """text[i] == '\"'. Return (content_without_quotes, index_after_closing_quote)."""
    assert text[i] == '"'
    i += 1
    out = []
    while i < len(text):
        c = text[i]
        if c == '\\' and i + 1 < len(text):
            out.append(c)
            out.append(text[i + 1])
            i += 2
            continue
        if c == '"':
            return ''.join(out), i + 1
        out.append(c)
        i += 1
    return ''.join(out), i

# ---------------------------------------------------------------------------
# SecRule / SecAction parser (multi-line, backslash continuations)
# ---------------------------------------------------------------------------
def parse_conf_files(data_dir):
    """Yield parsed rule dicts from all *.conf under data_dir (recursive-ish)."""
    rules = []
    if os.path.isfile(data_dir):
        files = [data_dir]
    else:
        files = glob.glob(os.path.join(data_dir, '*.conf'))
        files += glob.glob(os.path.join(data_dir, 'rules', '*.conf'))
    for filepath in sorted(set(files)):
        fname = os.path.basename(filepath)
        fm = re.match(r'REQUEST-(\d{3})-', fname)
        file_prefix = fm.group(1) if fm else None
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as conf_file:
                raw = conf_file.read()
        except OSError:
            continue
        # join backslash continuations
        lines = []
        buf = ''
        for ln in raw.splitlines():
            # ModSecurity comments are line-oriented. Removing complete
            # comment lines before continuation folding prevents documented,
            # commented-out SecAction examples from becoming active compiler
            # input while preserving '#' inside quoted regexes and values.
            if ln.lstrip().startswith('#'):
                continue
            if ln.endswith('\\'):
                buf += ln[:-1] + ' '
            else:
                buf += ln
                lines.append(buf)
                buf = ''
        if buf:
            lines.append(buf)
        text = '\n'.join(lines)

        # Split into logical SecRule/SecAction statements.
        # A statement spans from its `SecRule`/`SecAction` keyword to the start of
        # the NEXT such keyword (or EOF). BOUNDING IS ESSENTIAL: the previous loop
        # let `full` bleed into every following rule in the file, so `raw` (used by
        # the anomaly_score discriminator to skip pass/sampling setup rules) would
        # false-positive on later rules' actions and leak degenerate matchers
        # (e.g. 901420 DURATION @rx (..)$ -> "match any 2 chars") into the AOT.
        matches = list(re.finditer(r'\b(SecRule|SecAction)\b', text))
        for idx, m in enumerate(matches):
            kind = m.group(1)
            end = len(text)
            if idx + 1 < len(matches):
                end = matches[idx + 1].start()
            stmt = text[m.start():end]
            # capture quoted regions WITHIN this statement only
            # (SecRule: operator + actions; SecAction: actions)
            quotes = []
            qi = stmt.find('"')
            while qi != -1:
                content, qi = scan_quote(stmt, qi)
                quotes.append(content)
                qi = stmt.find('"', qi)
            full = stmt
            rules.append(parse_statement(kind, full, quotes, file_prefix))
    return rules

def parse_statement(kind, full, quotes, file_prefix):
    """Parse one SecRule/SecAction statement into a dict.
    `quotes` = list of unquoted regions (SecRule: [operator, actions]; SecAction: [actions])."""
    d = {'kind': kind, 'file_prefix': file_prefix,
         'variables': None, 'operator': None, 'pattern': None, 'id': None,
         'actions': {}, 'chain': False, 'is_gating': False,
         'is_blocking_eval': False, 'score': 5, 'paranoia': None,
         'category': None, 'transforms': [], 'pm_datafile': None,
         'negated': False, 'phase': None,
         'raw': full}
    if kind == 'SecRule':
        op_block = quotes[0] if len(quotes) >= 1 else ''
        actions_str = quotes[1] if len(quotes) >= 2 else ''
        q1 = full.find('"')
        d['variables'] = full[len('SecRule'):q1].strip() if q1 != -1 else None
    else:  # SecAction: only one quoted region (actions)
        op_block = ''
        actions_str = quotes[0] if quotes else ''
    actions = tokenize_actions(actions_str)
    kv = parse_action_kv(actions)
    d['actions'] = kv
    d['action_tokens'] = actions
    d['bindings'] = parse_variable_bindings(d['variables'])
    d['binding_contract'] = compile_binding_contract(d['bindings'])

    # operator + pattern
    if op_block:
        ob = op_block.strip()
        # K4 fix: a leading '!' is ModSecurity operator *negation*
        # (e.g. `!@rx`, `!@pm`, `!@eq`). Previously the `@\w+` regex silently
        # swallowed the '!' and emitted the rule as POSITIVE -> guaranteed
        # false-positive block on whole-buffer scan. Capture it as `negated`
        # and defer all negated rules to Phase 1b (need per-variable
        # execution context to invert soundly).
        if ob.startswith('!'):
            d['negated'] = True
            ob = ob[1:].strip()
        om = re.match(r'(@\w+)\s*(.*)', ob, re.S)
        if om:
            d['operator'] = om.group(1)
            d['pattern'] = om.group(2).strip()
        else:
            d['operator'] = ob

    # id
    if 'id' in kv:
        d['id'] = kv['id'].strip().strip("'").strip('"')

    # chain
    if 'chain' in kv:
        d['chain'] = True

    # phase
    if 'phase' in kv:
        try:
            d['phase'] = int(kv['phase'])
        except ValueError:
            d['phase'] = None

    # transforms
    for a in actions:
        if a.startswith('t:'):
            d['transforms'].append(a[2:].strip())

    # multiMatch
    d['multimatch'] = any(a.lower() == 'multimatch' for a in actions)

    # score from setvar:tx.anomaly_score=+%{tx.xxx_anomaly_score} or severity
    score = 5
    for a in actions:
        if a.startswith('setvar:') and 'anomaly_score' in a:
            if 'critical' in a: score = 5
            elif 'error' in a: score = 4
            elif 'warning' in a: score = 3
            elif 'notice' in a: score = 2
            else: score = 5
    if 'severity' in kv:
        sv = kv['severity'].strip().strip("'").upper()
        score = {'CRITICAL': 5, 'ERROR': 4, 'WARNING': 3, 'NOTICE': 2,
                 'EMERGENCY': 5, 'ALERT': 5, 'CRIT': 5, 'ERR': 4,
                 'WARN': 3, 'NOTICE': 2, 'INFO': 1, 'DEBUG': 1}.get(sv, 5)
    d['score'] = score

    # gating rule (sets detection paranoia level)
    for a in actions:
        if a.startswith('setvar:') and 'detection_paranoia_level' in a:
            d['is_gating'] = True
    # blocking eval rule (checks anomaly score)
    if d['variables'] and 'TX:' in d['variables']:
        d['is_blocking_eval'] = True
    if d['operator'] in ('@ge', '@gt', '@lt', '@eq', '@pm', '@rx') and d['variables'] and 'TX:' in d['variables']:
        d['is_blocking_eval'] = True

    # @pmFromFile
    if d['operator'] == '@pmFromFile':
        d['pm_datafile'] = d['pattern']

    # category from tag
    for a in actions:
        if a.startswith("tag:'") or a.startswith('tag:"'):
            tag = a[5:].strip().strip("'").strip('"').upper()
            pl_tag = re.search(r'PARANOIA-LEVEL/(\d+)', tag)
            if pl_tag:
                d['paranoia'] = int(pl_tag.group(1))
            if 'XSS' in tag: d['category'] = 'XSS'
            elif 'SQLI' in tag or 'SQL' in tag: d['category'] = 'SQLI'
            elif 'RCE' in tag or 'COMMAND' in tag: d['category'] = 'RCE'
            elif 'LFI' in tag or 'TRAVERSAL' in tag: d['category'] = 'LFI'
            elif 'RFI' in tag: d['category'] = 'RFI'
            elif 'PHP' in tag: d['category'] = 'PHP'

    # file-based defaults
    if file_prefix in FILE_MAP:
        pl, cat = FILE_MAP[file_prefix]
        if d['paranoia'] is None:
            d['paranoia'] = pl
        if d['category'] is None:
            d['category'] = cat
    else:
        if d['paranoia'] is None:
            d['paranoia'] = 2
        if d['category'] is None:
            d['category'] = 'GEN'

    # explicit Paranoia Level comment override
    plm = re.search(r'Paranoia\s*Level:\s*(\d)', full)
    if plm:
        d['paranoia'] = int(plm.group(1))

    return d

# ---------------------------------------------------------------------------
# Regex AST -> branchless C (reused/extended from legacy compiler)
# ---------------------------------------------------------------------------
import re as _re
try:
    import re._parser as reparser
except Exception:
    reparser = None

def build_bitmask_for_in(in_nodes, ignore_case):
    mask = [0, 0, 0, 0]
    def set_bit(c_code):
        # Byte scanner sees only uint8_t (0..255). Codepoints >=256 can never
        # match a single byte, so drop them — otherwise 1<<(c_code-192) overflows
        # uint64_t and the emitted C literal fails to compile.
        if c_code >= 256:
            return
        if ignore_case and 65 <= c_code <= 90:
            c_code |= 32
        if c_code < 64: mask[0] |= (1 << c_code)
        elif c_code < 128: mask[1] |= (1 << (c_code - 64))
        elif c_code < 192: mask[2] |= (1 << (c_code - 128))
        else: mask[3] |= (1 << (c_code - 192))
        if ignore_case and 97 <= c_code <= 122:
            upper = c_code & ~32
            if upper < 64: mask[0] |= (1 << upper)
            elif upper < 128: mask[1] |= (1 << (upper - 64))
            elif upper < 192: mask[2] |= (1 << (upper - 128))
            else: mask[3] |= (1 << (upper - 192))
    negate = False
    if in_nodes and in_nodes[0][0].name == 'NEGATE':
        negate = True
        in_nodes = in_nodes[1:]
    for node_type, val in in_nodes:
        if node_type.name == 'LITERAL':
            set_bit(val)
        elif node_type.name == 'RANGE':
            for c in range(val[0], val[1] + 1):
                set_bit(c)
        elif node_type.name == 'CATEGORY':
            if val == reparser.CATEGORY_SPACE:
                for c in b" \t\r\n\v\f": set_bit(c)
            elif val == reparser.CATEGORY_DIGIT:
                for c in range(48, 58): set_bit(c)
            elif val == reparser.CATEGORY_WORD:
                for c in range(48, 58): set_bit(c)
                for c in range(65, 91): set_bit(c)
                for c in range(97, 123): set_bit(c)
                set_bit(95)
    if negate:
        mask = [~m & 0xFFFFFFFFFFFFFFFF for m in mask]
    # Defensive: guarantee each field fits in uint64_t. Codepoints >=256 are
    # dropped above, but clamp anyway so a malformed shift can never emit a
    # literal larger than any integer type (which breaks the C compile).
    return [m & 0xFFFFFFFFFFFFFFFF for m in mask]

def compile_ast(nodes, ignore_case):
    lines = []
    for i, (node_type, val) in enumerate(nodes):
        name = getattr(node_type, 'name', str(node_type))
        
        if name in ('MIN_REPEAT', 'MAX_REPEAT'):
            mn, mx, inner = val[0], val[1], val[2]
            inner_name = getattr(inner[0][0], 'name', str(inner[0][0])) if inner else ''
            
            if inner_name == 'ANY' and int(mx) < 0xFFFFFFFF:
                suffix_nodes = nodes[i+1:]
                lines.append("    if (match) {")
                lines.append(f"        size_t _bg_min = {int(mn)};")
                lines.append(f"        size_t _bg_max = {int(mx)};")
                lines.append("        size_t _bg_begin = cur + _bg_min;")
                lines.append("        size_t _bg_end = cur + _bg_max;")
                lines.append("        if (_bg_end > len) _bg_end = len;")
                lines.append("        bool _bg_matched = false;")
                lines.append("        size_t _bg_final_cur = cur;")
                
                if suffix_nodes:
                    next_node_name = getattr(suffix_nodes[0][0], 'name', str(suffix_nodes[0][0]))
                    if next_node_name == 'LITERAL':
                        next_char = suffix_nodes[0][1]
                        if ignore_case and chr(next_char).isalpha():
                            lines.append(f"        // First-byte routing for case-insensitive '{chr(next_char)}'")
                            lines.append("        for (size_t _candidate = _bg_begin; _candidate <= _bg_end && _candidate < len; _candidate++) {")
                            lines.append(f"            uint8_t _c = data[_candidate] | 32;")
                            lines.append(f"            if (_c != 0x{next_char|32:02x}) continue;")
                        else:
                            lines.append(f"        // First-byte routing for literal '{chr(next_char)}'")
                            lines.append("        for (size_t _candidate = _bg_begin; _candidate <= _bg_end && _candidate < len; _candidate++) {")
                            lines.append(f"            if (data[_candidate] != 0x{next_char:02x}) continue;")
                    elif next_node_name == 'IN':
                        mask = build_bitmask_for_in(suffix_nodes[0][1], ignore_case)
                        lines.append(f"        // First-byte routing for IN class")
                        lines.append("        for (size_t _candidate = _bg_begin; _candidate <= _bg_end && _candidate < len; _candidate++) {")
                        lines.append(f"            uint8_t bv = data[_candidate];")
                        lines.append(f"            uint64_t bit = 1ULL << (bv % 64); bool _fb = false;")
                        lines.append(f"            uint64_t m0={mask[0]}ULL,m1={mask[1]}ULL,m2={mask[2]}ULL,m3={mask[3]}ULL;")
                        lines.append("            if (bv<64) _fb=(m0&bit); else if (bv<128) _fb=(m1&bit); else if (bv<192) _fb=(m2&bit); else _fb=(m3&bit);")
                        lines.append("            if (!_fb) continue;")
                    else:
                        lines.append("        for (size_t _candidate = _bg_begin; _candidate <= _bg_end; _candidate++) {")
                else:
                    lines.append("        for (size_t _candidate = _bg_begin; _candidate <= _bg_end; _candidate++) {")
                
                lines.append("            bool match = true; size_t cur = _candidate;")
                lines.extend(["            " + l for l in compile_ast(suffix_nodes, ignore_case)])
                lines.append("            if (match) {")
                lines.append("                _bg_matched = true;")
                lines.append("                _bg_final_cur = cur;")
                if name == 'MIN_REPEAT':
                    lines.append("                break;")
                lines.append("            }")
                lines.append("        }")
                
                lines.append("        match = _bg_matched; cur = _bg_final_cur;")
                lines.append("    }")
                break

        if name == 'LITERAL':
            c = chr(val)
            if ignore_case and c.isalpha():
                lv = val | 32
                lines.append(f"    if (match) {{ bool cm = (cur < len) && ((data[cur]|32) == 0x{lv:02x}); match &= cm; cur += match; }}")
            else:
                lines.append(f"    if (match) {{ bool cm = (cur < len) && (data[cur] == 0x{val:02x}); match &= cm; cur += match; }}")
        elif name == 'NOT_LITERAL':
            c = chr(val)
            if ignore_case and c.isalpha():
                lv = val | 32
                lines.append(f"    if (match) {{ bool cm = (cur < len) && ((data[cur]|32) != 0x{lv:02x}); match &= cm; cur += match; }}")
            else:
                lines.append(f"    if (match) {{ bool cm = (cur < len) && (data[cur] != 0x{val:02x}); match &= cm; cur += match; }}")
        elif name == 'ANY':
            lines.append("    if (match) { bool cm = (cur < len); match &= cm; cur += match; }")
        elif name == 'AT':
            at_name = getattr(val, 'name', str(val))
            if at_name == 'AT_BEGINNING':
                lines.append("    if (match) { match &= (cur == 0); }")
            elif at_name in ('AT_END', 'AT_END_STRING'):
                lines.append("    if (match) { match &= (cur == len); }")
            elif at_name == 'AT_BOUNDARY':
                # \b : position where exactly one side is a word char
                # [A-Za-z0-9_]. Out-of-bounds sides are treated as non-word.
                # Branchless: evaluate on data[cur-1] / data[cur].
                lines.append("    if (match) {")
                lines.append("        uint8_t _lb = (cur == 0) ? 0 : data[cur-1];")
                lines.append("        uint8_t _rb = (cur < len) ? data[cur] : 0;")
                lines.append("        bool _lw = (_lb>='0'&&_lb<='9')||(_lb>='A'&&_lb<='Z')||(_lb>='a'&&_lb<='z')||_lb=='_';")
                lines.append("        bool _rw = (_rb>='0'&&_rb<='9')||(_rb>='A'&&_rb<='Z')||(_rb>='a'&&_rb<='z')||_rb=='_';")
                lines.append("        match &= (_lw != _rw);")
                lines.append("    }")
            elif at_name == 'AT_NON_BOUNDARY':
                # \B : negation of \b
                lines.append("    if (match) {")
                lines.append("        uint8_t _lb = (cur == 0) ? 0 : data[cur-1];")
                lines.append("        uint8_t _rb = (cur < len) ? data[cur] : 0;")
                lines.append("        bool _lw = (_lb>='0'&&_lb<='9')||(_lb>='A'&&_lb<='Z')||(_lb>='a'&&_lb<='z')||_lb=='_';")
                lines.append("        bool _rw = (_rb>='0'&&_rb<='9')||(_rb>='A'&&_rb<='Z')||(_rb>='a'&&_rb<='z')||_rb=='_';")
                lines.append("        match &= (_lw == _rw);")
                lines.append("    }")
            else:
                raise NotImplementedError(f"AT {val}")
        elif name == 'IN':
            mask = build_bitmask_for_in(val, ignore_case)
            lines.append("    if (match) {")
            lines.append("        bool cm = (cur < len);")
            lines.append("        if (cm) {")
            lines.append("            uint8_t bv = data[cur];")
            lines.append("            uint64_t bit = 1ULL << (bv % 64);")
            lines.append(f"            uint64_t m0={mask[0]}ULL,m1={mask[1]}ULL,m2={mask[2]}ULL,m3={mask[3]}ULL;")
            lines.append("            if (bv<64) cm=(m0&bit); else if (bv<128) cm=(m1&bit); else if (bv<192) cm=(m2&bit); else cm=(m3&bit);")
            lines.append("        }")
            lines.append("        match &= cm; cur += match;")
            lines.append("    }")
        elif name == 'SUBPATTERN':
            _grp = val[0]
            if _grp is None:
                # non-capturing (?:...) — transparent
                lines.extend(compile_ast(val[3], ignore_case))
            else:
                # capturing group: record (start,len) of the last successful match
                lines.append("    if (match) {")
                lines.append("        size_t _sc = cur;")
                lines.extend(["    " + l for l in compile_ast(val[3], ignore_case)])
                lines.append("        if (match) { _cap[%d].start = _sc; _cap[%d].len = cur - _sc; }" % (_grp, _grp))
                lines.append("    }")
        elif name == 'BRANCH':
            lines.append("    if (match) {")
            lines.append("        bool gm = false; size_t nc = cur;")
            for p in val[1]:
                lines.append("        { size_t sc = cur; bool sm = match;")
                lines.extend(["        " + l for l in compile_ast(p, ignore_case)])
                lines.append("            gm |= match; nc = match ? cur : nc; cur = sc; match = sm; }")
            lines.append("        match &= gm; cur = nc;")
            lines.append("    }")
        elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            mn, mx, inner = val[0], val[1], val[2]
            unbounded = mx == reparser.MAXREPEAT or int(mx) >= 0xFFFFFFFF
            lines.append("    if (match) {")
            lines.append("        size_t _rep_count = 0; bool _rep_outer = match;")
            loop_cond = "cur < len" if unbounded else f"_rep_count < {int(mx)}u"
            lines.append(f"        while ({loop_cond}) {{")
            lines.append("            size_t _rep_start = cur; bool _rep_item;")
            lines.append("            { bool match = true;")
            lines.extend(["            " + l for l in compile_ast(inner, ignore_case)])
            lines.append("                _rep_item = match && cur > _rep_start;")
            lines.append("            }")
            lines.append("            if (!_rep_item) { cur = _rep_start; break; }")
            lines.append("            _rep_count++;")
            lines.append("        }")
            if int(mn) == 0:
                lines.append("        match = _rep_outer;")
            else:
                lines.append(f"        match = _rep_outer && (_rep_count >= {int(mn)}u);")
            lines.append("    }")
        elif name == 'GROUPREF':
            # Backreference \1 .. \9. Consumes `len` bytes equal to group's text.
            g = val
            lines.append("    if (match) {")
            if ignore_case:
                lines.append("        size_t _g=(size_t)(%d); size_t _l=_cap[_g].len;" % g)
                lines.append("        bool _bm = (_l>0) && (cur+_l<=len);")
                lines.append("        if (_bm) { for (size_t _k=0;_k<_l;_k++) { uint8_t a=data[cur+_k]|32,b=data[_cap[_g].start+_k]|32; if (a!=b){_bm=false;break;} } }")
            else:
                lines.append("        size_t _g=(size_t)(%d); size_t _l=_cap[_g].len;" % g)
                lines.append("        bool _bm = (_l>0) && (cur+_l<=len);")
                lines.append("        if (_bm) { for (size_t _k=0;_k<_l;_k++) { if (data[cur+_k]!=data[_cap[_g].start+_k]){_bm=false;break;} } }")
            lines.append("        match &= _bm; cur += match;")
            lines.append("    }")
        elif name in ('ASSERT', 'ASSERT_NOT'):
            # Lookaround. Zero-width: the outer cursor is restored after the
            # sub-match. dir==1 => forward lookahead (?= / (?!); dir==-1 =>
            # backward lookbehind (?<= / (?<!), implemented as a bounded reverse
            # scan (variable-width safe, cost bounded by 32 bytes per position).
            _dir = val[0]
            _inner = val[1]
            if _dir == 1:
                lines.append("    if (match) {")
                lines.append("        size_t _oc = cur; bool _am;")
                lines.append("        { bool match = true; size_t cur = _oc;")
                lines.extend(["        " + l for l in compile_ast(_inner, ignore_case)])
                lines.append("            _am = match; }")
                lines.append("        cur = _oc;")
                lines.append("        match &= " + ("!_am;" if name == 'ASSERT_NOT' else "_am;"))
                lines.append("    }")
            else:
                lines.append("    if (match) {")
                lines.append("        size_t _oc = cur; bool _hit = false;")
                lines.append("        for (size_t _j = (_oc>32?_oc-32:0); _j < _oc && !_hit; _j++) {")
                lines.append("            bool _im; size_t _end;")
                lines.append("            { bool match = true; size_t cur = _j;")
                lines.extend(["            " + l for l in compile_ast(_inner, ignore_case)])
                lines.append("                _im = match; _end = cur; }")
                lines.append("            if (_im && _end == _oc) { _hit = true; }")
                lines.append("        }")
                lines.append("        match &= " + ("!_hit;" if name == 'ASSERT_NOT' else "_hit;"))
                lines.append("    }")
        else:
            raise NotImplementedError(f"node {name}")
    return lines

def regex_to_c(rule_id, pattern):
    """Compile a CRS @rx pattern to a branchless matcher function body."""
    # Case-insensitive scope may be flagged as (?i) OR a leading (?i:...) group.
    # A (?i:...) at the start of the pattern applies to the whole expression,
    # which is the common CRS shape (e.g. 942130 `(?i:[...]`).
    ignore_case = inline_flag_enabled(pattern, 'i')
    pattern = re.sub(r'\(\?[a-zA-Z-]*\)', '', pattern)
    # python re doesn't support \x{HH} unicode escapes the same way; normalise
    pattern = re.sub(r'\\x\{([0-9a-fA-F]{1,4})\}', lambda m: chr(int(m.group(1), 16)), pattern)
    pattern = pattern.replace(r'\z', r'\Z')
    ast = reparser.parse(pattern)
    code = compile_ast(ast, ignore_case)
    if not code:
        raise ValueError("empty matcher")
    return (
        f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
        f"    size_t cur = offset; bool match = true;\n"
        f"    struct {{ size_t start; size_t len; }} _cap[16];\n"
        f"    for (int _ci=0;_ci<16;_ci++) {{ _cap[_ci].start=0; _cap[_ci].len=0; }}\n"
        + "\n".join(code) + "\n"
        f"    if (match) return {rule_id};\n    return 0;\n}}\n"
    )


def emit_procedural_fallback(rule_id, pattern):
    """Augment the scalar AST matcher with selective semantic microkernels.

    The procedural backend is intentionally non-backtracking. A recognized
    lazy-gap branch is therefore lowered to a direct bounded view scan instead
    of turning the whole expression into a large DFA table.
    """
    procedural = regex_to_c(rule_id, pattern)
    signature = pattern.lower()
    if not (r"overlay\b" in signature and r"\(.*?\b" in signature and
            r"[^0-9a-z_a-z]*?plac" in signature and "ing" in signature):
        return procedural

    helper = f"lumina_overlay_placing_{rule_id}"
    code = f"""static inline bool {helper}(const unsigned char *data, size_t len, size_t offset) {{
    static const unsigned char OVERLAY[] = "overlay";
    static const unsigned char PLACING[] = "placing";
    if (offset + sizeof(OVERLAY) - 1 > len) return false;
    if (offset && ((data[offset - 1] >= '0' && data[offset - 1] <= '9') ||
                   (data[offset - 1] >= 'A' && data[offset - 1] <= 'Z') ||
                   (data[offset - 1] >= 'a' && data[offset - 1] <= 'z') ||
                   data[offset - 1] == '_')) return false;
    for (size_t i = 0; i < sizeof(OVERLAY) - 1; i++)
        if ((data[offset + i] | 0x20) != OVERLAY[i]) return false;
    size_t pos = offset + sizeof(OVERLAY) - 1;
    if (pos < len && ((data[pos] >= '0' && data[pos] <= '9') ||
                      (data[pos] >= 'A' && data[pos] <= 'Z') ||
                      (data[pos] >= 'a' && data[pos] <= 'z') || data[pos] == '_')) return false;
    while (pos < len && !((data[pos] >= '0' && data[pos] <= '9') ||
                          (data[pos] >= 'A' && data[pos] <= 'Z') ||
                          (data[pos] >= 'a' && data[pos] <= 'z') || data[pos] == '_') &&
           data[pos] != '(') pos++;
    if (pos == len || data[pos++] != '(') return false;
    for (; pos + sizeof(PLACING) - 1 <= len; pos++) {{
        bool left_word = pos && ((data[pos - 1] >= '0' && data[pos - 1] <= '9') ||
            (data[pos - 1] >= 'A' && data[pos - 1] <= 'Z') ||
            (data[pos - 1] >= 'a' && data[pos - 1] <= 'z') || data[pos - 1] == '_');
        bool right_word = (data[pos] >= '0' && data[pos] <= '9') ||
            (data[pos] >= 'A' && data[pos] <= 'Z') ||
            (data[pos] >= 'a' && data[pos] <= 'z') || data[pos] == '_';
        if (left_word == right_word) continue;
        size_t candidate = pos;
        while (candidate < len && !((data[candidate] >= '0' && data[candidate] <= '9') ||
               (data[candidate] >= 'A' && data[candidate] <= 'Z') ||
               (data[candidate] >= 'a' && data[candidate] <= 'z') || data[candidate] == '_')) candidate++;
        if (candidate + sizeof(PLACING) - 1 > len) continue;
        size_t i = 0;
        for (; i < sizeof(PLACING) - 1; i++)
            if ((data[candidate + i] | 0x20) != PLACING[i]) break;
        if (i != sizeof(PLACING) - 1) continue;
        size_t end = candidate + sizeof(PLACING) - 1;
        if (end == len || !((data[end] >= '0' && data[end] <= '9') ||
                            (data[end] >= 'A' && data[end] <= 'Z') ||
                            (data[end] >= 'a' && data[end] <= 'z') || data[end] == '_')) return true;
    }}
    return false;
}}
"""
    marker = (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, "
              "size_t len, size_t offset) {\n")
    return code + procedural.replace(
        marker, marker + f"    if ({helper}(data, len, offset)) return {rule_id};\n", 1)


def _ast_first_byte_set(nodes, ignore_case):
    """Return a conservative first-byte set for an already parsed AST fragment."""
    result = set()

    def add(byte):
        byte &= 0xff
        result.add(byte)
        if ignore_case and 65 <= byte <= 90:
            result.add(byte + 32)
        elif ignore_case and 97 <= byte <= 122:
            result.add(byte - 32)

    def collect(sequence):
        for node_type, value in sequence:
            name = getattr(node_type, 'name', str(node_type))
            if name == 'LITERAL':
                add(value)
                return False
            if name == 'IN':
                masks = build_bitmask_for_in(value, ignore_case)
                for byte in range(256):
                    if masks[byte // 64] & (1 << (byte % 64)):
                        result.add(byte)
                return False
            if name in ('ANY', 'NOT_LITERAL'):
                result.update(range(256))
                return False
            if name == 'AT':
                continue
            if name == 'SUBPATTERN':
                if collect(value[3]):
                    continue
                return False
            if name == 'BRANCH':
                nullable = False
                for alternative in value[1]:
                    nullable |= collect(alternative)
                if nullable:
                    continue
                return False
            if name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
                inner_nullable = collect(value[2])
                if int(value[0]) == 0 or inner_nullable:
                    continue
                return False
            result.update(range(256))
            return True
        return True

    collect(nodes)
    return result or set(range(256))


def _ast_uses_capture(nodes):
    for node_type, value in nodes:
        name = getattr(node_type, 'name', str(node_type))
        if name == 'GROUPREF':
            return True
        if name == 'SUBPATTERN':
            if value[0] is not None or _ast_uses_capture(value[3]):
                return True
        elif name == 'BRANCH':
            if any(_ast_uses_capture(alt) for alt in value[1]):
                return True
        elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            if _ast_uses_capture(value[2]):
                return True
        elif name in ('ASSERT', 'ASSERT_NOT') and _ast_uses_capture(value[1]):
            return True
    return False


def _expand_linear_ast_alternatives(nodes, limit=64):
    """Expand finite choices into branch-free procedural paths.

    This is deliberately bounded. A choice nested under a repeat with more than
    one iteration is not expanded because choosing one alternative for all
    iterations would change the language; such patterns stay on another backend.
    """
    def cross(prefixes, suffixes):
        if len(prefixes) * len(suffixes) > limit:
            return None
        return [prefix + suffix for prefix in prefixes for suffix in suffixes]

    def expand_node(node):
        node_type, value = node
        name = getattr(node_type, 'name', str(node_type))
        if name == 'BRANCH':
            variants = []
            for alternative in value[1]:
                expanded = expand_sequence(alternative)
                if expanded is None or len(variants) + len(expanded) > limit:
                    return None
                variants.extend(expanded)
            return variants
        if name == 'SUBPATTERN':
            expanded = expand_sequence(value[3])
            if expanded is None:
                return None
            if value[0] is None:
                return expanded
            return [[(node_type, (value[0], value[1], value[2], alternative))]
                    for alternative in expanded]
        if name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            minimum, maximum, inner = value
            expanded = expand_sequence(inner)
            if expanded is None:
                return None
            if int(minimum) == 0 and int(maximum) == 1:
                return [[]] + expanded
            if len(expanded) != 1:
                return None
            return [[(node_type, (minimum, maximum, expanded[0]))]]
        if name in ('ASSERT', 'ASSERT_NOT'):
            expanded = expand_sequence(value[1])
            if expanded is None or len(expanded) != 1:
                return None
            return [[(node_type, (value[0], expanded[0]))]]
        return [[node]]

    def expand_sequence(sequence):
        variants = [[]]
        for node in sequence:
            node_variants = expand_node(node)
            if node_variants is None:
                return None
            variants = cross(variants, node_variants)
            if variants is None:
                return None
        return variants

    return expand_sequence(nodes)


def crlf_command_grammar_plan(pattern):
    """Recognize a line-local command grammar suitable for direct native lowering.

    The accepted language is structurally equivalent to::

        CR LF .*? WORD_BOUNDARY (ALT_0 | ... | ALT_N)

    Alternatives must have selective first bytes. The restriction keeps the
    generated dispatcher compact and makes this peephole a predictable attack-path
    microkernel rather than another general regex runtime.
    """
    try:
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
    except Exception:
        return None
    if dot_all or len(ast) != 5:
        return None
    if (getattr(ast[0][0], 'name', '') != 'LITERAL' or ast[0][1] != 13 or
            getattr(ast[1][0], 'name', '') != 'LITERAL' or ast[1][1] != 10):
        return None
    repeat_type, repeat_value = ast[2]
    if getattr(repeat_type, 'name', '') != 'MIN_REPEAT':
        return None
    repeat_min, repeat_max, repeat_inner = repeat_value
    if (int(repeat_min) != 0 or repeat_max != reparser.MAXREPEAT or
            len(repeat_inner) != 1 or
            getattr(repeat_inner[0][0], 'name', '') != 'ANY'):
        return None
    if (getattr(ast[3][0], 'name', '') != 'AT' or
            getattr(ast[3][1], 'name', '') != 'AT_BOUNDARY'):
        return None
    if getattr(ast[4][0], 'name', '') != 'BRANCH':
        return None
    root_alternatives = list(ast[4][1][1])
    if not 2 <= len(root_alternatives) <= 32:
        return None
    alternatives = []
    for alternative in root_alternatives:
        expanded = _expand_linear_ast_alternatives(alternative, limit=64)
        if expanded is None or len(alternatives) + len(expanded) > 64:
            return None
        alternatives.extend(expanded)
    routes = []
    for alternative in alternatives:
        first_bytes = _ast_first_byte_set(alternative, ignore_case)
        if not first_bytes or len(first_bytes) > 16:
            return None
        routes.append(first_bytes)
    return {
        'ignore_case': ignore_case,
        'alternatives': alternatives,
        'routes': routes,
    }


def emit_crlf_command_grammar(rule_id, pattern):
    """Emit a zero-allocation, first-byte-routed CRLF command matcher."""
    plan = crlf_command_grammar_plan(pattern)
    if plan is None:
        raise ValueError('pattern is not a supported CRLF command grammar')
    ignore_case = plan['ignore_case']
    helpers = []
    code = []
    route_map = {}

    def route_key(byte):
        if ignore_case and 65 <= byte <= 90:
            return byte + 32
        if ignore_case and 97 <= byte <= 122:
            return byte
        return byte

    for index, (alternative, first_bytes) in enumerate(
            zip(plan['alternatives'], plan['routes'])):
        helper = f'lumina_crlf_command_{rule_id}_{index}'
        helpers.append(helper)
        body = compile_ast(alternative, ignore_case)
        capture_state = ''
        if _ast_uses_capture(alternative):
            capture_state = (
                "    struct { size_t start; size_t len; } _cap[16];\n"
                "    for (int i = 0; i < 16; i++) { _cap[i].start = 0; _cap[i].len = 0; }\n"
            )
        code.append(
            f"static int {helper}(const unsigned char *data, size_t len, size_t offset) {{\n"
            "    size_t cur = offset; bool match = true;\n" + capture_state +
            "\n".join(body) + "\n"
            "    return match ? 1 : 0;\n"
            "}\n"
        )
        for byte in first_bytes:
            route_map.setdefault(route_key(byte), []).append(helper)

    cases = []
    for key in sorted(route_map):
        predicates = ' || '.join(
            f'{helper}(data, line_end, candidate)'
            for helper in dict.fromkeys(route_map[key]))
        cases.append(
            f"        case 0x{key:02x}:\n"
            f"            if ({predicates}) return {rule_id};\n"
            "            break;"
        )
    normalize = (
        "        if (route >= 'A' && route <= 'Z') route |= 0x20;\n"
        if ignore_case else ""
    )
    code.append(
        f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
        "    if (offset + 2 > len || data[offset] != '\\r' || data[offset + 1] != '\\n') return 0;\n"
        "    size_t line_end = offset + 2;\n"
        "    while (line_end < len && data[line_end] != '\\n') line_end++;\n"
        "    for (size_t candidate = offset + 2; candidate < line_end; candidate++) {\n"
        "        uint8_t left = candidate ? data[candidate - 1] : 0;\n"
        "        uint8_t right = data[candidate];\n"
        "        bool left_word = (left >= '0' && left <= '9') ||\n"
        "            (left >= 'A' && left <= 'Z') || (left >= 'a' && left <= 'z') || left == '_';\n"
        "        bool right_word = (right >= '0' && right <= '9') ||\n"
        "            (right >= 'A' && right <= 'Z') || (right >= 'a' && right <= 'z') || right == '_';\n"
        "        if (left_word == right_word) continue;\n"
        "        uint8_t route = right;\n" + normalize +
        "        switch (route) {\n" + "\n".join(cases) +
        "\n        default: break;\n"
        "        }\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    return '\n'.join(code)


def _fixed_token_sequences(nodes, limit=64, max_width=4):
    variants = [b'']
    for node_type, value in nodes:
        name = getattr(node_type, 'name', str(node_type))
        if name == 'LITERAL':
            choices = [value & 0xff]
        elif name == 'IN':
            masks = build_bitmask_for_in(value, False)
            choices = [byte for byte in range(256)
                       if masks[byte // 64] & (1 << (byte % 64))]
        else:
            return None
        if len(variants) * len(choices) > limit:
            return None
        variants = [prefix + bytes((byte,))
                    for prefix in variants for byte in choices]
        if variants and len(variants[0]) > max_width:
            return None
    return variants


def repeated_token_threshold_plan(pattern):
    """Recognize a fixed threshold of variable-width byte tokens."""
    try:
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
    except Exception:
        return None
    if ignore_case or dot_all or len(ast) != 1:
        return None
    root_type, root_value = ast[0]
    if getattr(root_type, 'name', '') == 'SUBPATTERN':
        nodes = list(root_value[3])
    else:
        nodes = list(ast)
    if len(nodes) != 1:
        return None
    repeat_type, repeat_value = nodes[0]
    if getattr(repeat_type, 'name', '') not in ('MIN_REPEAT', 'MAX_REPEAT'):
        return None
    minimum, maximum, inner = repeat_value
    if int(minimum) != int(maximum) or not 2 <= int(minimum) <= 255 or len(inner) != 2:
        return None
    token_type, token_value = inner[0]
    filler_type, filler_value = inner[1]
    if getattr(token_type, 'name', '') != 'BRANCH':
        return None
    if getattr(filler_type, 'name', '') not in ('MIN_REPEAT', 'MAX_REPEAT'):
        return None
    filler_min, filler_max, filler_inner = filler_value
    if (int(filler_min) != 0 or filler_max != reparser.MAXREPEAT or
            len(filler_inner) != 1 or
            getattr(filler_inner[0][0], 'name', '') != 'IN'):
        return None
    filler_class = list(filler_inner[0][1])
    if not filler_class or getattr(filler_class[0][0], 'name', '') != 'NEGATE':
        return None
    sequences = []
    for alternative in token_value[1]:
        expanded = _fixed_token_sequences(alternative)
        if expanded is None or len(sequences) + len(expanded) > 64:
            return None
        sequences.extend(expanded)
    sequences = sorted(set(sequences), key=lambda value: (len(value), value))
    if not sequences:
        return None
    one_byte = {value[0] for value in sequences if len(value) == 1}
    excluded_masks = build_bitmask_for_in(filler_class[1:], False)
    excluded = {byte for byte in range(256)
                if excluded_masks[byte // 64] & (1 << (byte % 64))}
    if excluded != one_byte:
        return None
    return {'threshold': int(minimum), 'tokens': sequences}


def emit_repeated_token_threshold(rule_id, pattern):
    """Emit one linear scan for a fixed token-count threshold."""
    plan = repeated_token_threshold_plan(pattern)
    if plan is None:
        raise ValueError('pattern is not a repeated token threshold')
    one_byte = {value[0] for value in plan['tokens'] if len(value) == 1}
    words = [0, 0, 0, 0]
    for byte in one_byte:
        words[byte >> 6] |= 1 << (byte & 63)
    multi = [value for value in plan['tokens'] if len(value) > 1]
    route_map = {}
    for token in multi:
        route_map.setdefault(token[0], []).append(token)
    cases = []
    for first in sorted(route_map):
        tests = []
        for token in route_map[first]:
            suffix = ' && '.join(
                f'data[pos + {index}] == 0x{byte:02x}'
                for index, byte in enumerate(token[1:], start=1)
            )
            tests.append(
                f"if (pos + {len(token)} <= len && {suffix}) {{ width = {len(token)}; break; }}"
            )
        cases.append(
            f"        case 0x{first:02x}:\n            " +
            "\n            ".join(tests) +
            "\n            break;"
        )
    return (
        f"static const uint64_t lumina_token_threshold_{rule_id}_single[4] = {{\n"
        f"    0x{words[0]:016x}ULL, 0x{words[1]:016x}ULL, "
        f"0x{words[2]:016x}ULL, 0x{words[3]:016x}ULL\n}};\n"
        f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
        "    if (offset != 0) return 0;\n"
        "    unsigned count = 0;\n"
        "    for (size_t pos = 0; pos < len;) {\n"
        "        uint8_t byte = data[pos];\n"
        "        size_t width = 0;\n"
        f"        if (lumina_token_threshold_{rule_id}_single[byte >> 6] & "
        "(1ULL << (byte & 63))) width = 1;\n"
        "        else switch (byte) {\n" + '\n'.join(cases) +
        "\n        default: break;\n"
        "        }\n"
        "        if (width) {\n"
        f"            if (++count >= {plan['threshold']}u) return {rule_id};\n"
        "            pos += width;\n"
        "        } else {\n"
        "            pos++;\n"
        "        }\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )

def first_bytes_of(pattern):
    """First-byte set for routing.

    Conservative by design: this mask only GATES which rules are *candidates*
    at a given start byte. Over-inclusion only costs a cheap matcher call;
    UNDER-inclusion (dropping a real first byte) is a silent false negative.
    Therefore any case we cannot analyse precisely falls back to all 256.

    Key correctness fix (v9.1): zero-width anchors (^ $ \\b \\B \\A \\Z \\z,
    named AT) are transparent — they do NOT begin the match, so we must keep
    scanning the node list for the first *consuming* byte. The previous
    implementation `return`ed on the first AT node, which silently dropped
    every anchored rule (e.g. 931100 `(?i)^(f|https?|ssh)://...`) from routing.
    """
    ignore_case = inline_flag_enabled(pattern, 'i')
    pattern = re.sub(r'\(\?[a-zA-Z-]*\)', '', pattern)
    pattern = re.sub(r'\\x\{([0-9a-fA-F]{1,4})\}', lambda m: chr(int(m.group(1), 16)), pattern)
    try:
        ast = reparser.parse(pattern)
    except Exception:
        return set(range(256))
    result = set()

    def add(b):
        b &= 0xFF
        result.add(b)
        if ignore_case:
            if 0x41 <= b <= 0x5A:
                result.add(b + 32)
            elif 0x61 <= b <= 0x7A:
                result.add(b - 32)

    def collect(nodes):
        """Walk a node list. Returns True if this sequence can match EMPTY
        (so a following element may legally be the first consuming byte)."""
        for nt, v in nodes:
            name = getattr(nt, 'name', str(nt))
            if name == 'LITERAL':
                add(v); return False
            elif name == 'NOT_LITERAL':
                for i in range(256):
                    if i != v and not (ignore_case and i == (v ^ 32)):
                        add(i)
                return False
            elif name == 'IN':
                m = build_bitmask_for_in(v, ignore_case)
                for i in range(256):
                    if (m[i // 64] >> (i % 64)) & 1:
                        add(i)
                return False
            elif name == 'ANY':
                for i in range(256):
                    add(i)
                return False
            elif name == 'AT':            # zero-width assertion: transparent
                continue
            elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
                lo = v[0]
                inner_empty = collect(v[2])   # v[2] = inner sub-pattern nodes
                # a repeat with min 0 (?, *) can vanish -> next node may start match
                if lo == 0 or inner_empty:
                    continue
                return False
            elif name == 'SUBPATTERN':
                if collect(v[3]):
                    continue
                return False
            elif name == 'BRANCH':
                branch_empty = False
                for alt in v[1]:
                    if collect(alt):
                        branch_empty = True
                if branch_empty:
                    continue
                return False
            elif name in ('ASSERT', 'ASSERT_NOT', 'GROUPREF',
                          'REPEAT_ONE', 'REPEAT', 'SUCCESS', 'FAILURE',
                          'CATEGORY', 'IN', 'RANGE'):
                # lookaround / unsupported -> conservative
                for i in range(256):
                    add(i)
                return True
            else:
                for i in range(256):
                    add(i)
                return True
        return True   # empty node list matches empty

    collect(ast)
    if not result:
        return set(range(256))
    return result


def transform_aware_first_bytes(pattern, transforms):
    """Conservative raw-input candidates for a matcher executed after transforms."""
    result = set(first_bytes_of(pattern))
    normalized = {str(t).lower().replace('_', '').replace('t:', '') for t in (transforms or [])}
    if normalized & {'lowercase', 'cmdline'}:
        for byte in list(result):
            if 65 <= byte <= 90 or 97 <= byte <= 122:
                result.add(byte ^ 32)
    if normalized & {'urldecode', 'urldecodeuni'}:
        result.add(ord('%'))
    if 'htmlentitydecode' in normalized:
        result.add(ord('&'))
    if normalized & {'jsdecode', 'cssdecode'}:
        result.add(ord('\\'))
    if 'removenulls' in normalized:
        result.add(0)
    return result


def transform_requires_offset_zero(transforms):
    """Return true when transformed first bytes cannot be derived from raw bytes."""
    normalized = {
        str(transform).lower().replace('_', '').replace('t:', '')
        for transform in (transforms or [])
    }
    return bool(normalized & {'base64decode', 'length', 'utf8tounicode'})

# ---------------------------------------------------------------------------
# Transform mask
# ---------------------------------------------------------------------------
TFLAGS = ['none','lowercase','url_decode','url_decode_uni','compress_whitespace',
          'remove_nulls','remove_comments','html_entity_decode','js_decode',
          'cmd_line','normalize_path','trim']

def transform_mask(transforms):
    """Map CRS transform list -> bitmask. Order is not enforced here; the runtime
    applies in CRS order. We only record WHICH are needed."""
    bit = 0
    # bit positions align with TFLAGS order; runtime helper applies by name.
    for t in transforms:
        t = t.lower().replace(' ', '')
        # normalise a few aliases
        if t in ('none',): bit |= (1 << 0)
        elif t in ('lowercase', 'lower'): bit |= (1 << 1)
        elif t in ('urldecode',): bit |= (1 << 2)
        elif t in ('urldecodeuni',): bit |= (1 << 3)
        elif t in ('compresswhitespace',): bit |= (1 << 4)
        elif t in ('removenulls',): bit |= (1 << 5)
        elif t in ('removecomments',): bit |= (1 << 6)
        elif t in ('htmlentitydecode',): bit |= (1 << 7)
        elif t in ('jsdecode',): bit |= (1 << 8)
        elif t in ('cmdline',): bit |= (1 << 9)
        elif t in ('normalizepath',): bit |= (1 << 10)
        elif t in ('trim',): bit |= (1 << 11)
    return bit

# ---------------------------------------------------------------------------
# @pmFromFile phrase scanner generator
# ---------------------------------------------------------------------------
def gen_phrase_scanner(name, literals):
    """Compact, flat-p99 phrase scanner for @pmFromFile data sets.

    Literals are emitted as a SINGLE hex-byte buffer (no C-string escaping, so
    parentheses/quotes in data never break compilation) plus offset/length
    tables. A compact two-stage bucket index routes each candidate byte pair
    only to literals with the same lowercased first and second byte. This avoids
    the old O(len * all_literals) behavior for benign candidate-heavy paths.
    Case-insensitive via (a|32)==(b|32), matching the historical generated
    scanner semantics."""
    safe = re.sub(r'[^0-9a-zA-Z]', '_', name)
    entries = []
    for lit in literals:
        if not lit:
            continue
        b = lit.encode('utf-8', 'replace')
        entries.append(b)
    pair_buckets = [dict() for _ in range(256)]
    single_mask = [0, 0, 0, 0]
    for idx, e in enumerate(entries):
        first = e[0] & 0xFF
        hot_key = (first | 32) & 0xFF
        current_keys = {first}
        if 65 <= first <= 90:
            current_keys.add(first + 32)
        elif 97 <= first <= 122:
            current_keys.add(first - 32)
        # Preserve the previous scanner's first-byte semantics: the hot loop
        # lowercases the input byte before consulting the mask. If that lowered
        # byte was not in the old mask, the literal was unreachable before and
        # remains unreachable here.
        if hot_key in current_keys:
            if len(e) == 1:
                if hot_key < 64:
                    single_mask[0] |= (1 << hot_key)
                elif hot_key < 128:
                    single_mask[1] |= (1 << (hot_key - 64))
                elif hot_key < 192:
                    single_mask[2] |= (1 << (hot_key - 128))
                else:
                    single_mask[3] |= (1 << (hot_key - 192))
            else:
                second_key = (e[1] | 32) & 0xFF
                pair_buckets[hot_key].setdefault(second_key, []).append(idx)
    fbmask = [0, 0, 0, 0]
    for key, bucket in enumerate(pair_buckets):
        if not bucket and not (
            ((single_mask[0] >> key) & 1) if key < 64 else
            ((single_mask[1] >> (key - 64)) & 1) if key < 128 else
            ((single_mask[2] >> (key - 128)) & 1) if key < 192 else
            ((single_mask[3] >> (key - 192)) & 1)
        ):
            continue
        if key < 64:
            fbmask[0] |= (1 << key)
        elif key < 128:
            fbmask[1] |= (1 << (key - 64))
        elif key < 192:
            fbmask[2] |= (1 << (key - 128))
        else:
            fbmask[3] |= (1 << (key - 192))
    buf = bytearray()
    offs = []
    lens = []
    for e in entries:
        offs.append(len(buf))
        lens.append(len(e))
        buf.extend(e)
        buf.append(0)  # NUL separator (literals must not contain NUL)
    hexrows = []
    for i in range(0, len(buf), 16):
        hexrows.append(", ".join("0x%02x" % x for x in buf[i:i+16]))
    data_init = ",\n        ".join(hexrows) if hexrows else "0x00"
    off_init = ", ".join(str(o) for o in offs) if offs else "0"
    len_init = ", ".join(str(l) for l in lens) if lens else "0"
    n = len(entries)
    first_rows = []
    second_keys = []
    pair_starts = []
    bucket_index = []
    for first in range(256):
        first_rows.append(len(second_keys))
        for second in sorted(pair_buckets[first]):
            second_keys.append(second)
            pair_starts.append(len(bucket_index))
            bucket_index.extend(pair_buckets[first][second])
    first_rows.append(len(second_keys))
    pair_starts.append(len(bucket_index))
    first_init = ", ".join(str(x) for x in first_rows)
    second_init = ", ".join(str(x) for x in second_keys) if second_keys else "0"
    pair_init = ", ".join(str(x) for x in pair_starts)
    index_init = ", ".join(str(x) for x in bucket_index) if bucket_index else "0"
    pair_n = len(second_keys) if second_keys else 1
    index_n = len(bucket_index) if bucket_index else 1
    lines = []
    lines.append(f"int lumina_pm_{safe}(const unsigned char *data, size_t len) {{")
    lines.append(f"    static const unsigned char D[] = {{ {data_init} }};")
    # O[] holds byte offsets into D[]; data files can exceed 64 KiB
    # (e.g. php-errors.data ~75 KiB) so offsets MUST be uint32_t, not uint16_t
    # (a uint16_t would silently truncate the offset and break the scanner).
    lines.append(f"    static const uint32_t O[{n}] = {{ {off_init} }};")
    lines.append(f"    static const uint16_t L[{n}] = {{ {len_init} }};")
    lines.append(f"    static const uint32_t F[257] = {{ {first_init} }};")
    lines.append(f"    static const uint16_t S[{pair_n}] = {{ {second_init} }};")
    lines.append(f"    static const uint32_t B[{pair_n + 1}] = {{ {pair_init} }};")
    lines.append(f"    static const uint32_t K[{index_n}] = {{ {index_init} }};")
    lines.append(f"    static const uint64_t M0={fbmask[0]}ULL,M1={fbmask[1]}ULL,M2={fbmask[2]}ULL,M3={fbmask[3]}ULL;")
    lines.append(f"    static const uint64_t U0={single_mask[0]}ULL,U1={single_mask[1]}ULL,U2={single_mask[2]}ULL,U3={single_mask[3]}ULL;")
    lines.append("    for (size_t i = 0; i < len; i++) {")
    lines.append("        uint8_t bv = data[i] | 32;")
    lines.append("        uint64_t bit = 1ULL << (bv % 64);")
    # CRITICAL: `has` must be a BOOLEAN, not the raw 64-bit mask value.
    # M0..M3 are uint64_t; for (bv%64) >= 32 the masked value is > INT_MAX and
    # assigning it to `int has` overflows to 0, so every lowercase-starting
    # literal (a-z -> bit 33..58) would never match. Compare against 0 instead.
    lines.append("        uint64_t w = (bv<64)?M0:(bv<128)?M1:(bv<192)?M2:M3;")
    lines.append("        if (!(w & bit)) continue;")
    lines.append("        uint64_t uw = (bv<64)?U0:(bv<128)?U1:(bv<192)?U2:U3;")
    lines.append("        if (uw & bit) return 1;")
    lines.append("        if (i + 1 >= len) continue;")
    lines.append("        uint16_t sv = (uint16_t)(data[i + 1] | 32);")
    lines.append("        for (uint32_t ri = F[bv]; ri < F[(uint16_t)bv + 1]; ri++) {")
    lines.append("            if (S[ri] != sv) continue;")
    lines.append("            for (uint32_t bi = B[ri]; bi < B[ri + 1]; bi++) {")
    lines.append("                uint32_t k = K[bi];")
    lines.append("            const unsigned char *p = D + O[k]; uint16_t pl = L[k];")
    lines.append("            if (pl == 0) continue;")
    lines.append("            if (i + pl <= len) {")
    lines.append("                int eq = 1; for (uint16_t q = 2; q < pl; q++) { if ((data[i+q]|32) != (p[q]|32)) { eq = 0; break; } }")
    lines.append("                if (eq) return 1;")
    lines.append("            }")
    lines.append("            }")
    lines.append("            break;")
    lines.append("        }")
    lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines), safe

# ---------------------------------------------------------------------------
# K4 Phase-1 native scalar / phrase / scanner-bridge emitters
# ---------------------------------------------------------------------------
# All emitters below produce `lumina_scan_rule_<id>(data,len,offset)`.
# They are WHOLE-BUFFER-SAFE POSITIVE operators (no per-variable TX capture,
# no numeric length check) and are marked "anywhere" (first-byte = all-256) so
# the runtime dispatches them ONCE at offset 0 over the canonicalized variable
# buffer. Negated / numeric / @eq-@gt-@within operators are deferred (Phase 1b).
# A shared substring helper is emitted once into the tables chunk.

def _c_bytes_literal(s):
    b = s.encode('utf-8', 'replace')
    if not b:
        return "0x00"
    return ", ".join("0x%02x" % x for x in b)

def emit_inline_pm(rule_id, literals):
    """@pm inline (phrase set). Reuses the branchless phrase scanner."""
    name = f"inline_{rule_id}"
    code, _ = gen_phrase_scanner(name, literals)
    fn = (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
          f"    if (lumina_pm_{name}(data + offset, len - offset)) return {rule_id};\n    return 0;\n}}\n")
    return code + "\n" + fn

def emit_contains(rule_id, needle):
    L = len(needle.encode('utf-8', 'replace'))
    lit = _c_bytes_literal(needle)
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    static const unsigned char P[] = {{ {lit} }}; const int L = {L};\n"
            f"    (void)offset;\n"
            f"    if (len >= (size_t)L) {{ for (size_t i = 0; i + L <= len; i++) {{ int eq = 1; "
            f"for (int q = 0; q < L; q++) if (data[i+q] != P[q]) {{ eq = 0; break; }} if (eq) return {rule_id}; }} }}\n"
            f"    return 0;\n}}\n")

def emit_detect(rule_id, scanner):
    """@detectXSS/@detectSQLi -> bridge to the existing precise C7 scanner.
    Returns the EXACT CRS id (the runtime scanner returns 1000xxx, which fails
    harness expect_ids for the specific CRS rule). Scope passed as all-1 so the
    scanner never self-gates on a scope it was not given."""
    return (f"extern int {scanner}(const unsigned char*, size_t, uint32_t);\n"
            f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    (void)offset;\n"
            f"    if ({scanner}(data, len, 0xFFFFFFFFu)) return {rule_id};\n    return 0;\n}}\n")

def emit_detect_sqli(rule_id):
    """Emit @detectSQLi through the Lumina-owned verdict-only classifier."""
    return (
        "extern int lumina_sqli_detect(const unsigned char*, size_t);\n"
        f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
        "    (void)offset;\n"
        f"    if (lumina_sqli_detect(data, len)) return {rule_id};\n"
        "    return 0;\n}\n"
    )

def parse_byte_range(pattern):
    """Parse @validateByteRange arg ('1-255' or '9,10,13,32-126,128-255') -> 256-bit allowed mask."""
    allowed = [False] * 256
    for tok in pattern.replace(' ', '').split(','):
        if not tok:
            continue
        if '-' in tok:
            lo, hi = tok.split('-', 1)
            try:
                lo, hi = int(lo), int(hi)
            except ValueError:
                continue
            for c in range(max(0, lo), min(255, hi) + 1):
                allowed[c] = True
        else:
            try:
                c = int(tok)
            except ValueError:
                continue
            if 0 <= c <= 255:
                allowed[c] = True
    return allowed

def emit_validate_byte_range(rule_id, pattern):
    allowed = parse_byte_range(pattern)
    m = [0, 0, 0, 0]
    for c in range(256):
        if allowed[c]:
            m[c // 64] |= (1 << (c % 64))
    m0, m1, m2, m3 = (x & 0xFFFFFFFFFFFFFFFF for x in m)
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    (void)offset;\n"
            f"    static const uint64_t A0={m0}ULL,A1={m1}ULL,A2={m2}ULL,A3={m3}ULL;\n"
            f"    for (size_t i = 0; i < len; i++) {{ uint8_t b = data[i]; uint64_t bit = 1ULL << (b % 64);\n"
            f"        uint64_t w = (b<64)?A0:(b<128)?A1:(b<192)?A2:A3;\n"
            f"        if (!(w & bit)) return {rule_id}; }}\n"
            f"    return 0;\n}}\n")

def emit_validate_utf8(rule_id):
    """@validateUtf8Encoding: block if the buffer is NOT valid UTF-8.
    Conservative decoder: only rejects genuinely malformed sequences (so valid
    multibyte benign traffic passes — parity-safe)."""
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    (void)offset;\n"
            f"    size_t i = 0;\n"
            f"    while (i < len) {{ uint8_t b = data[i];\n"
            f"        if (b < 0x80) {{ i++; continue; }}\n"
            f"        int n = (b>=0xC0&&b<=0xDF)?1:(b>=0xE0&&b<=0xEF)?2:(b>=0xF0&&b<=0xF4)?3:0;\n"
            f"        if (n == 0) return {rule_id};\n"
            f"        if (i + (size_t)n >= len) return {rule_id};\n"
            f"        for (int k = 1; k <= n; k++) {{ uint8_t c = data[i+k]; if (c < 0x80 || c > 0xBF) return {rule_id}; }}\n"
            f"        i += (size_t)n + 1; }}\n"
            f"    return 0;\n}}\n")

def emit_validate_url_encoding(rule_id):
    """@validateUrlEncoding: block on malformed %-encoding (a '%' not followed
    by exactly two hex digits, incl. %00 which canonicalize would strip)."""
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    (void)offset;\n"
            f"    for (size_t i = 0; i < len; i++) {{ if (data[i] == '%') {{\n"
            f"        if (i + 2 >= len) return {rule_id};\n"
            f"        int h1 = data[i+1], h2 = data[i+2];\n"
            f"        int ok = ((h1>='0'&&h1<='9')||(h1>='a'&&h1<='f')||(h1>='A'&&h1<='F')) &&\n"
            f"                ((h2>='0'&&h2<='9')||(h2>='a'&&h2<='f')||(h2>='A'&&h2<='F'));\n"
            f"        if (!ok) return {rule_id}; i += 2; }} }}\n"
            f"    return 0;\n}}\n")

def is_score_bearing_detection(r):
    """Inbound CRS detection rules increment tx.inbound_anomaly_score_plN by +score."""
    return (
        r.get('kind') == 'SecRule' and
        re.search(r"setvar\s*:\s*['\"]?tx\.inbound_anomaly_score_pl[0-9]+\s*=\s*\+", r.get('raw') or '', re.I)
    )


def group_rule_chains(rules):
    """Collapse each syntactic SecRule chain into its head compilation unit.

    Chain children intentionally have no rule ID. Grouping must happen before
    detection filtering because CRS commonly puts the anomaly-score action on
    the final child rather than on the ID-bearing head.
    """
    grouped = []
    index = 0
    while index < len(rules):
        head = rules[index]
        if not head.get('chain'):
            grouped.append(head)
            index += 1
            continue
        members = [head]
        index += 1
        while index < len(rules):
            member = rules[index]
            members.append(member)
            index += 1
            if not member.get('chain'):
                break
        unit = dict(head)
        unit['_chain_members'] = members
        scoring = next((member for member in members if is_score_bearing_detection(member)), None)
        if scoring is not None:
            unit['score'] = scoring.get('score', unit.get('score', 5))
        grouped.append(unit)
    return grouped


def chain_is_score_bearing(rule):
    return any(is_score_bearing_detection(member)
               for member in rule.get('_chain_members', [rule]))


def _single_positive_binding(member):
    bindings = [binding for binding in member.get('bindings', [])
                if not binding.excluded]
    return bindings[0] if len(bindings) == 1 else None


def _raw_setvar_assignments(rule):
    """Return complete TX assignments from quote-aware action tokens.

    Values may contain spaces and punctuation. Parsing them from `raw` with a
    whitespace-delimited regex truncated policy collections such as charset
    allowlists and silently changed `@within` semantics.
    """
    assignments = []
    for action in rule.get('action_tokens', []):
        if not action.lower().startswith('setvar:'):
            continue
        payload = action.split(':', 1)[1].strip()
        if len(payload) >= 2 and payload[0] == payload[-1] and payload[0] in "'\"":
            payload = payload[1:-1]
        match = re.fullmatch(r'tx\.([^=]+)=(.*)', payload, re.I | re.S)
        if match:
            assignments.append((match.group(1), match.group(2)))
    return assignments


def _setvar_assignments(rule):
    """Return literal-name TX assignments suitable for static resolution."""
    return [
        (name, value) for name, value in _raw_setvar_assignments(rule)
        if re.fullmatch(r'[A-Za-z0-9_.-]+', name)
    ]


def _rule_remove_by_id_targets(rule):
    """Return static numeric targets from ctl:ruleRemoveById actions.

    Numeric ranges are expanded only later against the generated inventory, so
    a broad range never allocates an attacker-controlled or unbounded table.
    Dynamic macro targets are deliberately rejected at translation time.
    """
    targets = []
    for action in rule.get('action_tokens', []):
        match = re.fullmatch(r'ctl\s*:\s*ruleRemoveById\s*=\s*(.+)', action,
                             re.I | re.S)
        if not match:
            continue
        payload = match.group(1).strip().strip("'\"")
        parts = [part for part in re.split(r'[\s,;]+', payload) if part]
        if not parts or any(not re.fullmatch(r'\d+(?:-\d+)?', part) for part in parts):
            return None
        for part in parts:
            if '-' in part:
                start, end = (int(value) for value in part.split('-', 1))
                if start > end:
                    return None
                targets.append(('range', start, end))
            else:
                value = int(part)
                targets.append(('id', value, value))
    return targets


def _rule_tags(rule):
    tags = []
    for action in rule.get('action_tokens', []):
        match = re.fullmatch(r'tag\s*:\s*(.+)', action, re.I | re.S)
        if not match:
            continue
        value = match.group(1).strip().strip("'\"")
        if value:
            tags.append(value)
    return tags


def _rule_remove_target_by_tag_actions(rule):
    actions = []
    for action in rule.get('action_tokens', []):
        match = re.fullmatch(
            r'ctl\s*:\s*ruleRemoveTargetByTag\s*=\s*([^;]+)\s*;\s*(.+)',
            action, re.I | re.S)
        if not match:
            continue
        tag = match.group(1).strip().strip("'\"")
        target = match.group(2).strip().strip("'\"").upper()
        actions.append((tag, target))
    return actions


def collect_rule_removal_controls(parsed_rules, detection):
    """Lower supported ModSecurity rule-removal controls to typed AOT IR."""
    id_to_idx = {int(rule['id']): idx for idx, rule in enumerate(detection)}
    controls = []
    unsupported = []
    for rule in parsed_rules:
        targets = _rule_remove_by_id_targets(rule)
        if targets == []:
            continue
        binding = _single_positive_binding(rule)
        transforms = {item.lower() for item in (rule.get('transforms') or [])}
        supported = (
            rule.get('kind') == 'SecRule' and
            rule.get('phase') in {1, 2} and
            not rule.get('chain') and
            not rule.get('negated') and
            rule.get('operator') == '@streq' and
            binding is not None and
            binding.selector_kind == 'none' and
            not binding.count and
            binding.collection in REQUEST_METADATA_FIELDS and
            transforms <= {'none', 'lowercase'} and
            targets is not None
        )
        if not supported:
            unsupported.append({
                'rule_id': rule.get('id'),
                'reason': 'unsupported-rule-removal-control',
                'operator': rule.get('operator'),
            })
            continue

        resolved_ids = []
        for target_kind, start, end in targets:
            if target_kind == 'id':
                if start in id_to_idx:
                    resolved_ids.append(start)
                else:
                    unsupported.append({
                        'rule_id': rule.get('id'),
                        'reason': 'rule-removal-target-not-generated',
                        'target_rule_id': start,
                    })
                continue
            matched = [rule_id for rule_id in id_to_idx if start <= rule_id <= end]
            resolved_ids.extend(matched)
            if not matched:
                unsupported.append({
                    'rule_id': rule.get('id'),
                    'reason': 'rule-removal-range-empty',
                    'target_range': f'{start}-{end}',
                })
        resolved_ids = sorted(set(resolved_ids))
        if not resolved_ids:
            continue
        ptr_field, len_field = REQUEST_METADATA_FIELDS[binding.collection]
        controls.append({
            'source_rule_id': int(rule['id']) if rule.get('id') else None,
            'phase': int(rule['phase']),
            'kind': 'typed-streq-rule-removal',
            'collection': binding.collection,
            'ptr_field': ptr_field,
            'len_field': len_field,
            'value': rule.get('pattern') or '',
            'lowercase_value': 'lowercase' in transforms,
            'target_rule_ids': resolved_ids,
            'target_engine_indices': [id_to_idx[rule_id] for rule_id in resolved_ids],
        })
    return controls, unsupported


def collect_rule_target_removal_controls(parsed_rules, detection):
    """Lower collection-local ruleRemoveTargetByTag controls to typed AOT IR."""
    controls = []
    unsupported = []
    detection_tags = [set(_rule_tags(rule)) for rule in detection]
    collection_fields = {
        'REQUEST_FILENAME': ('req_filename', 'req_filename_len',
                             'LUMINA_COL_REQUEST_FILENAME', 10),
        'REQUEST_BASENAME': ('req_basename', 'req_basename_len',
                             'LUMINA_COL_REQUEST_BASENAME', 11),
    }
    for rule in parsed_rules:
        actions = _rule_remove_target_by_tag_actions(rule)
        if not actions:
            continue
        binding = _single_positive_binding(rule)
        transforms = {item.lower() for item in (rule.get('transforms') or [])}
        allowed = (parse_byte_range(rule.get('pattern') or '')
                   if rule.get('operator') == '@validateByteRange' else None)
        for tag, target_collection in actions:
            target_spec = collection_fields.get(target_collection)
            source_spec = collection_fields.get(
                binding.collection if binding is not None else '')
            supported = (
                rule.get('kind') == 'SecRule' and
                rule.get('phase') in {1, 2} and
                not rule.get('chain') and
                rule.get('operator') == '@validateByteRange' and
                binding is not None and
                binding.selector_kind == 'none' and
                not binding.count and
                source_spec is not None and
                target_spec is not None and
                transforms <= {'none'} and
                allowed is not None
            )
            if not supported:
                unsupported.append({
                    'rule_id': rule.get('id'),
                    'reason': 'unsupported-rule-remove-target-by-tag-control',
                    'operator': rule.get('operator'),
                    'tag': tag,
                    'target_collection': target_collection,
                })
                continue
            target_indices = [
                idx for idx, tags in enumerate(detection_tags) if tag in tags
            ]
            if not target_indices:
                unsupported.append({
                    'rule_id': rule.get('id'),
                    'reason': 'rule-remove-target-tag-empty',
                    'tag': tag,
                    'target_collection': target_collection,
                })
                continue
            source_ptr, source_len, source_mask, _ = source_spec
            _, _, target_mask, target_slot = target_spec
            words = [0, 0, 0, 0]
            for byte, accepted in enumerate(allowed):
                if accepted:
                    words[byte >> 6] |= 1 << (byte & 63)
            controls.append({
                'source_rule_id': int(rule['id']) if rule.get('id') else None,
                'phase': int(rule['phase']),
                'kind': 'typed-byte-range-rule-remove-target-by-tag',
                'source_collection': binding.collection,
                'source_ptr_field': source_ptr,
                'source_len_field': source_len,
                'source_collection_mask': source_mask,
                'operator_negated': bool(rule.get('negated')),
                'allowed_words': words,
                'tag': tag,
                'target_collection': target_collection,
                'target_collection_mask': target_mask,
                'target_collection_slot': target_slot,
                'target_rule_ids': [int(detection[idx]['id']) for idx in target_indices],
                'target_engine_indices': target_indices,
            })
    return controls, unsupported


def collect_static_tx_values(rules):
    """Resolve literal TX initialization visible in the compiler input.

    Only unconditional SecAction assignments and the common "initialize when
    missing" SecRule shape are accepted. Dynamic assignments invalidate the
    value so a transaction lowering cannot silently assume a runtime setting.
    """
    values = {}
    for rule in rules:
        assignments = _setvar_assignments(rule)
        if not assignments:
            continue
        binding = _single_positive_binding(rule)
        is_missing_initializer = (
            rule.get('kind') == 'SecRule' and binding is not None and binding.count and
            binding.collection == 'TX' and binding.selector_kind == 'literal' and
            not rule.get('negated') and rule.get('operator') == '@eq' and
            (rule.get('pattern') or '').strip() == '0'
        )
        for name, value in assignments:
            key = name.lower()
            if value.startswith(('+', '-')) or '%{' in value:
                values.pop(key, None)
                continue
            if rule.get('kind') == 'SecAction':
                values[key] = value
            elif is_missing_initializer and binding.selector.lower() == key:
                values.setdefault(key, value)
            else:
                values.pop(key, None)
    return values


def _split_terminal_capture(pattern):
    """Split `prefix(capture)` when group 1 ends the consuming regex.

    The scanner is syntax-aware for escapes and character classes. It does not
    reinterpret the regex; both returned fragments are compiled by the native
    DFA backend, so unsupported constructs still fail explicitly. A trailing
    absolute end assertion is attached to the capture matcher because it does
    not consume bytes and therefore does not change the captured endpoint.
    """
    stack = []
    in_class = False
    escaped = False
    capture_number = 0
    terminal = None
    for index, char in enumerate(pattern):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if in_class:
            if char == ']':
                in_class = False
            continue
        if char == '[':
            in_class = True
            continue
        if char == '(':
            extension = pattern[index + 1:index + 2] == '?'
            named_capture = pattern[index + 1:index + 4] == '?P<'
            capturing = not extension or named_capture
            if capturing:
                capture_number += 1
            stack.append((index, capturing, capture_number if capturing else 0))
            continue
        if char == ')':
            if not stack:
                return None
            start, capturing, number = stack.pop()
            suffix = pattern[index + 1:]
            if (not stack and capturing and number == 1 and
                    suffix in ('', '$', r'\Z', r'\z')):
                terminal = (pattern[:start], pattern[start + 1:index] + suffix)
    if stack:
        return None
    return terminal


def _tx_match_assignment(member):
    """Resolve one literal `tx.name=prefix%{tx.N}suffix` assignment.

    Only TX.0 (the complete regex match) and TX.1 (the first capture group)
    are lowered here. Additional or mixed expansions require a multi-capture
    transaction ABI and remain explicit compiler gaps.
    """
    matches = []
    for name, value in _setvar_assignments(member):
        markers = list(re.finditer(r'%\{tx\.([01])\}', value, re.I))
        if len(markers) != 1:
            continue
        marker = markers[0]
        prefix, suffix = value[:marker.start()], value[marker.end():]
        if '%{' in prefix or '%{' in suffix:
            continue
        matches.append((name, prefix, suffix, int(marker.group(1))))
    return matches[0] if len(matches) == 1 else None


def _tx_dynamic_name_match_assignment(member):
    """Resolve one dynamic-name TX assignment fed by the same match capture.

    The supported form is `tx.name_%{tx.N}=prefix%{tx.N}suffix`. Requiring a
    single identical capture expansion on both sides makes the producer and
    consumer link statically provable without materializing a runtime TX map.
    """
    matches = []
    for name_template, value in _raw_setvar_assignments(member):
        name_markers = list(re.finditer(r'%\{tx\.([01])\}', name_template, re.I))
        value_markers = list(re.finditer(r'%\{tx\.([01])\}', value, re.I))
        if (len(name_markers) != 1 or len(value_markers) != 1 or
                name_markers[0].group(1) != value_markers[0].group(1)):
            continue
        name_marker = name_markers[0]
        value_marker = value_markers[0]
        name_prefix = name_template[:name_marker.start()]
        name_suffix = name_template[name_marker.end():]
        value_prefix = value[:value_marker.start()]
        value_suffix = value[value_marker.end():]
        if any('%{' in item for item in (
                name_prefix, name_suffix, value_prefix, value_suffix)):
            continue
        matches.append({
            'capture_group': int(name_marker.group(1)),
            'name_prefix': name_prefix,
            'name_suffix': name_suffix,
            'value_prefix': value_prefix,
            'value_suffix': value_suffix,
            'representative_names': (
                name_prefix + 'a' + name_suffix,
                name_prefix + 'header-name' + name_suffix,
            ),
        })
    return matches[0] if len(matches) == 1 else None


def _has_absolute_start_anchor(pattern):
    """Return true when a regex match necessarily starts at byte zero.

    TX.0 extraction currently reports a match endpoint but not a start offset.
    Restricting this lowering to BOL/absolute-start patterns keeps the emitted
    slice exact instead of guessing where an unanchored match began.
    """
    remaining = pattern
    while True:
        global_flags = re.match(r'^\(\?[aiLmsux-]+\)', remaining)
        if not global_flags:
            break
        remaining = remaining[global_flags.end():]
    if remaining.startswith(r'\A'):
        return True
    return remaining.startswith('^') and not inline_flag_enabled(pattern, 'm')


def collect_dynamic_tx_collection_producers(rules):
    """Collect bounded collection producers represented by dynamic TX names.

    A producer captures one value from a typed ModSecurity collection and stores
    it under a TX name containing one runtime expansion. Consumers can then be
    linked structurally through their TX selector regex without relying on CRS
    IDs, filenames or hard-coded variable names.
    """
    producers = []
    for rule in rules:
        binding = _single_positive_binding(rule)
        if (binding is None or binding.collection != 'MULTIPART_PART_HEADERS' or
                binding.selector_kind != 'none' or rule.get('negated') or
                rule.get('operator') != '@rx' or
                'capture' not in (rule.get('actions') or {})):
            continue
        transforms = {item.lower() for item in (rule.get('transforms') or [])}
        if not transforms <= {'none', 'lowercase'}:
            continue
        capture_parts = _split_terminal_capture(rule.get('pattern') or '')
        if capture_parts is None:
            continue
        for name_template, value in _raw_setvar_assignments(rule):
            expansions = list(re.finditer(r'%\{tx\.[^}]+\}', name_template, re.I))
            if len(expansions) != 1 or value.lower() != '%{tx.1}':
                continue
            expansion = expansions[0]
            name_prefix = name_template[:expansion.start()]
            name_suffix = name_template[expansion.end():]
            if '%{' in name_prefix or '%{' in name_suffix:
                continue
            producers.append({
                'collection': binding.collection,
                'name_prefix': name_prefix,
                'name_suffix': name_suffix,
                'representative_names': (
                    name_prefix + '0' + name_suffix,
                    name_prefix + '1' + name_suffix,
                ),
                'prefix_pattern': capture_parts[0],
                'capture_pattern': capture_parts[1],
                'lowercase_value': 'lowercase' in transforms,
            })
    return producers


def _tx_selector_matches_names(selector, names):
    if len(selector) < 2 or selector[0] != '/' or selector[-1] != '/':
        return False
    try:
        compiled = re.compile(selector[1:-1], re.I)
    except re.error:
        return False
    return all(compiled.search(name) is not None for name in names)


def _classify_request_metadata_member(member):
    """Lower one scalar request-metadata predicate to typed transaction IR."""
    binding = _single_positive_binding(member)
    if binding is None:
        return None
    transforms = {item.lower() for item in (member.get('transforms') or [])}
    if not transforms <= {'none', 'lowercase', 'urldecodeuni'}:
        return None
    lowercase = 'lowercase' in transforms
    operator = member.get('operator')
    pattern = member.get('pattern') or ''
    negated = bool(member.get('negated'))

    if (binding.collection in {'REQUEST_METHOD', 'REQUEST_PROTOCOL'} and
            binding.selector_kind == 'none' and not binding.count and
            transforms <= {'none', 'lowercase'}):
        if operator == '@rx':
            return {
                'type': 'scalar-rx',
                'collection': binding.collection,
                'pattern': pattern,
                'negated': negated,
                'lowercase': lowercase,
            }
        if operator == '@streq':
            return {
                'type': 'scalar-streq',
                'collection': binding.collection,
                'value': pattern,
                'negated': negated,
                'lowercase': lowercase,
            }
        if operator == '@within' and '%{' not in pattern:
            return {
                'type': 'scalar-within',
                'collection': binding.collection,
                'allowed': pattern,
                'negated': negated,
                'lowercase': lowercase,
            }
        return None

    if (binding.collection == 'REQUEST_BODY_LENGTH' and
            binding.selector_kind == 'none' and not binding.count and
            transforms <= {'none'} and
            operator in {'@eq', '@gt', '@ge', '@lt'} and
            re.fullmatch(r'[0-9]+', pattern.strip())):
        return {
            'type': 'body-length-compare',
            'operator': operator,
            'expected': int(pattern.strip()),
            'negated': negated,
        }

    if (binding.collection == 'REQUEST_BASENAME' and
            binding.selector_kind == 'none' and not binding.count and
            operator == '@endsWith'):
        return {
            'type': 'request-basename-endswith',
            'value': pattern,
            'negated': negated,
            'lowercase': lowercase,
            'transforms': [item.lower() for item in (member.get('transforms') or [])
                           if item.lower() != 'none'],
        }

    if (binding.collection == 'REQUEST_URI_RAW' and
            binding.selector_kind == 'none' and not binding.count and
            transforms <= {'none'} and operator == '@contains'):
        return {
            'type': 'raw-uri-contains',
            'value': pattern,
            'negated': negated,
        }

    if (binding.collection != 'REQUEST_HEADERS' or
            not transforms <= {'none', 'lowercase'} or
            binding.selector_kind != 'literal'):
        return None
    header_name = binding.selector.upper()
    if binding.count:
        if operator != '@eq' or not re.fullmatch(r'[0-9]+', pattern.strip()):
            return None
        expected = int(pattern.strip())
        count_field = HEADER_COUNT_FIELDS.get(header_name)
        presence_mask = HEADER_MASKS.get(header_name, 0)
        if count_field is None and not (expected == 0 and presence_mask):
            return None
        return {
            'type': 'header-count-eq',
            'header_name': binding.selector,
            'count_field': count_field,
            'presence_mask': presence_mask if count_field is None else 0,
            'expected': expected,
            'negated': negated,
        }

    header_mask = HEADER_MASKS.get(header_name, 0)
    if not header_mask:
        return None
    if operator == '@rx':
        return {
            'type': 'named-header-rx',
            'header_name': binding.selector,
            'header_mask': header_mask,
            'pattern': pattern,
            'negated': negated,
            'lowercase': lowercase,
        }
    if operator == '@pm':
        literals = [phrase for phrase in pattern.split() if phrase]
        if not literals:
            return None
        return {
            'type': 'named-header-pm',
            'header_name': binding.selector,
            'header_mask': header_mask,
            'literals': literals,
            'negated': negated,
            # The generated phrase microkernel is ASCII case-insensitive,
            # matching ModSecurity @pm without a per-request lowercase copy.
            'lowercase': lowercase,
        }
    return None


def classify_request_metadata_chain(rule):
    """Classify an all-metadata chain without relying on rule IDs or CRS files."""
    members = rule.get('_chain_members') or []
    if len(members) < 2 or len(members) > 8:
        return None
    predicates = []
    for member in members:
        predicate = _classify_request_metadata_member(member)
        if predicate is None:
            return None
        predicates.append(predicate)
    return {'kind': 'request-metadata-chain', 'predicates': predicates}


def classify_named_header_decimal_capture_chain(rule):
    """Lower two decimal captures plus a TX numeric comparison to one scan."""
    members = rule.get('_chain_members') or []
    if len(members) != 2:
        return None
    head, child = members
    head_binding = _single_positive_binding(head)
    child_binding = _single_positive_binding(child)
    if (head_binding is None or head_binding.count or
            head_binding.collection != 'REQUEST_HEADERS' or
            head_binding.selector_kind != 'literal' or
            head.get('operator') != '@rx' or head.get('negated') or
            'capture' not in (head.get('actions') or {}) or
            not _only_none_transforms(head)):
        return None
    header_mask = HEADER_MASKS.get(head_binding.selector.upper(), 0)
    if not header_mask:
        return None
    if (child_binding is None or child_binding.count or
            child_binding.collection != 'TX' or
            child_binding.selector_kind != 'literal' or
            child_binding.selector != '2' or child.get('negated') or
            child.get('operator') not in {'@lt', '@gt', '@ge', '@eq'} or
            not _only_none_transforms(child) or
            not re.fullmatch(r'%\{tx\.1\}', (child.get('pattern') or '').strip(), re.I)):
        return None
    shape = re.fullmatch(r'\(\\d\+\)([^\\])\(\\d\+\)', head.get('pattern') or '')
    if shape is None:
        return None
    return {
        'kind': 'named-header-decimal-capture-compare',
        'header_mask': header_mask,
        'header_name': head_binding.selector,
        'separator': ord(shape.group(1)),
        'operator': child.get('operator'),
    }


def _single_byte_search_mask(pattern):
    """Return a 256-bit mask for a regex that consumes exactly one byte."""
    try:
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
    except Exception:
        return None
    if dot_all or len(ast) != 1:
        return None
    node_type, value = ast[0]
    name = getattr(node_type, 'name', str(node_type))
    if name == 'LITERAL':
        masks = [0, 0, 0, 0]
        values = {int(value) & 0xff}
        if ignore_case:
            byte = int(value) & 0xff
            if 65 <= byte <= 90:
                values.add(byte + 32)
            elif 97 <= byte <= 122:
                values.add(byte - 32)
        for byte in values:
            masks[byte >> 6] |= 1 << (byte & 63)
        return masks
    if name == 'IN':
        return build_bitmask_for_in(value, ignore_case)
    if name == 'ANY':
        masks = [(1 << 64) - 1] * 4
        masks[10 >> 6] &= ~(1 << (10 & 63))
        return masks
    if name == 'NOT_LITERAL':
        masks = [(1 << 64) - 1] * 4
        byte = int(value) & 0xff
        masks[byte >> 6] &= ~(1 << (byte & 63))
        return masks
    return None


def _header_capture_view(pattern):
    """Recognize a zero-copy full-match view with one byte boundary."""
    try:
        ast, _, dot_all = parse_regex_ast(pattern)
    except Exception:
        return None
    nodes = list(ast)
    if dot_all or len(nodes) != 2:
        return None
    first_name = getattr(nodes[0][0], 'name', str(nodes[0][0]))
    second_name = getattr(nodes[1][0], 'name', str(nodes[1][0]))
    if first_name == 'AT' and second_name in {'MAX_REPEAT', 'MIN_REPEAT'}:
        minimum, maximum, inner = nodes[1][1]
        if (getattr(nodes[0][1], 'name', str(nodes[0][1])) in
                {'AT_BEGINNING', 'AT_BEGINNING_STRING'} and int(minimum) == 1 and
                maximum == reparser.MAXREPEAT and len(inner) == 1 and
                getattr(inner[0][0], 'name', str(inner[0][0])) == 'NOT_LITERAL'):
            return {'mode': 'prefix-before-byte', 'boundary': int(inner[0][1]) & 0xff}
    if first_name == 'LITERAL' and second_name in {'MAX_REPEAT', 'MIN_REPEAT'}:
        minimum, maximum, inner = nodes[1][1]
        if (int(minimum) == 0 and maximum == reparser.MAXREPEAT and len(inner) == 1 and
                getattr(inner[0][0], 'name', str(inner[0][0])) == 'ANY'):
            return {'mode': 'suffix-from-byte', 'boundary': int(nodes[0][1]) & 0xff}
    return None


def classify_named_header_capture_view_chain(rule):
    """Lower bounded TX.N/MATCHED_VAR chains to views over one header buffer."""
    members = rule.get('_chain_members') or []
    if len(members) not in {4, 5}:
        return None
    head = members[0]
    head_binding = _single_positive_binding(head)
    transforms = [item.lower() for item in (head.get('transforms') or [])
                  if item.lower() != 'none']
    if (head_binding is None or head_binding.count or
            head_binding.collection != 'REQUEST_HEADERS' or
            head_binding.selector_kind != 'literal' or head.get('negated') or
            head.get('operator') != '@rx' or 'capture' not in (head.get('actions') or {}) or
            set(transforms) > {'lowercase', 'urldecodeuni'}):
        return None
    header_mask = HEADER_MASKS.get(head_binding.selector.upper(), 0)
    view = _header_capture_view(head.get('pattern') or '')
    if not header_mask or view is None:
        return None
    if any(not _only_none_transforms(member) for member in members[1:]):
        return None

    child = members[1]
    child_binding = _single_positive_binding(child)
    if (child_binding is None or child_binding.count or
            child_binding.collection != 'TX' or child_binding.selector != '0' or
            child.get('negated') or child.get('operator') != '@rx'):
        return None

    if len(members) == 4:
        capture_parts = _split_terminal_capture(child.get('pattern') or '')
        if capture_parts is None or 'capture' not in (child.get('actions') or {}):
            return None
        masks = []
        for member in members[2:]:
            binding = _single_positive_binding(member)
            mask = _single_byte_search_mask(member.get('pattern') or '')
            if (binding is None or binding.collection != 'TX' or binding.selector != '1' or
                    member.get('negated') or member.get('operator') != '@rx' or mask is None):
                return None
            masks.append(mask)
        return {
            'kind': 'named-header-capture-view-chain',
            'mode': 'terminal-capture',
            'header_mask': header_mask,
            'header_name': head_binding.selector,
            'view': view,
            'transforms': transforms,
            'child_prefix_pattern': capture_parts[0],
            'child_capture_pattern': capture_parts[1],
            'byte_masks': masks,
        }

    masks = []
    for member in members[2:4]:
        binding = _single_positive_binding(member)
        mask = _single_byte_search_mask(member.get('pattern') or '')
        if (binding is None or binding.collection != 'MATCHED_VAR' or
                member.get('negated') or member.get('operator') != '@rx' or mask is None):
            return None
        masks.append(mask)
    terminal = members[4]
    terminal_binding = _single_positive_binding(terminal)
    if (terminal_binding is None or terminal_binding.collection != 'MATCHED_VAR' or
            not terminal.get('negated') or terminal.get('operator') != '@beginsWith' or
            '%{' in (terminal.get('pattern') or '')):
        return None
    return {
        'kind': 'named-header-capture-view-chain',
        'mode': 'matched-var',
        'header_mask': header_mask,
        'header_name': head_binding.selector,
        'view': view,
        'transforms': transforms,
        'child_pattern': child.get('pattern') or '',
        'byte_masks': masks,
        'forbidden_prefix': terminal.get('pattern') or '',
    }


def classify_transaction_chain(rule, static_tx_values=None, dynamic_tx_producers=None):
    """Classify supported cross-collection chains from typed ModSecurity IR.

    The classifier is intentionally structural: rule IDs and CRS filenames are
    irrelevant. Unsupported chain shapes remain explicit manifest gaps.
    """
    dynamic_tx_producers = dynamic_tx_producers or []
    decimal_capture = classify_named_header_decimal_capture_chain(rule)
    if decimal_capture is not None:
        return decimal_capture
    capture_view = classify_named_header_capture_view_chain(rule)
    if capture_view is not None:
        return capture_view
    metadata_descriptor = classify_request_metadata_chain(rule)
    if metadata_descriptor is not None:
        return metadata_descriptor
    direct_binding = _single_positive_binding(rule)
    direct_transforms = {item.lower() for item in (rule.get('transforms') or [])}
    if (not rule.get('_chain_members') and direct_binding is not None and
            direct_binding.collection == 'TX' and
            direct_binding.selector_kind == 'regex' and rule.get('negated') and
            rule.get('operator') == '@rx' and
            direct_transforms <= {'none', 'lowercase'}):
        matches = [
            producer for producer in dynamic_tx_producers
            if producer['collection'] == 'MULTIPART_PART_HEADERS' and
            _tx_selector_matches_names(
                direct_binding.selector, producer['representative_names'])
        ]
        if len(matches) == 1:
            producer = matches[0]
            return {
                'kind': 'multipart-header-capture-negated-rx',
                'producer_prefix_pattern': producer['prefix_pattern'],
                'producer_capture_pattern': producer['capture_pattern'],
                'producer_lowercase_value': producer['lowercase_value'],
                'consumer_pattern': rule.get('pattern') or '',
                'consumer_lowercase_value': 'lowercase' in direct_transforms,
            }

    members = rule.get('_chain_members') or []
    if len(members) not in (2, 3):
        return None

    static_tx_values = static_tx_values or {}

    if len(members) == 2:
        head, child = members
        head_binding = _single_positive_binding(head)
        child_binding = _single_positive_binding(child)
        assignments = _raw_setvar_assignments(head)
        expansion = None
        if len(assignments) == 1:
            expansion = re.fullmatch(
                r'([^%]*)%\{ARGS\.([^}]+)\}([^%]*)', assignments[0][1], re.I)
        allowed_expansion = re.fullmatch(
            r'%\{tx\.([A-Za-z0-9_.-]+)\}', (child.get('pattern') or '').strip(), re.I)
        if (head_binding is not None and head_binding.count and
                head_binding.collection == 'MULTIPART_PART_HEADERS' and
                head_binding.selector_kind == 'literal' and head.get('negated') and
                head.get('operator') == '@eq' and (head.get('pattern') or '').strip() == '0' and
                _only_none_transforms(head) and expansion and
                expansion.group(2).lower() == head_binding.selector.lower() and
                child_binding is not None and not child_binding.count and
                child_binding.collection == 'TX' and
                child_binding.selector_kind == 'literal' and
                child_binding.selector.lower() == assignments[0][0].lower() and
                child.get('negated') and child.get('operator') == '@within' and
                allowed_expansion and
                allowed_expansion.group(1).lower() in static_tx_values and
                {item.lower() for item in (child.get('transforms') or [])} <=
                    {'none', 'lowercase'}):
            return {
                'kind': 'multipart-field-not-within-static-tx',
                'field_name': head_binding.selector,
                'value_prefix': expansion.group(1),
                'value_suffix': expansion.group(3),
                'allowed_value': static_tx_values[allowed_expansion.group(1).lower()],
                'lowercase_value': 'lowercase' in {
                    item.lower() for item in (child.get('transforms') or [])},
            }

    if len(members) == 3:
        head, method_member, value_member = members
        head_binding = _single_positive_binding(head)
        method_binding = _single_positive_binding(method_member)
        value_binding = _single_positive_binding(value_member)
        if (head_binding is not None and method_binding is not None and
                value_binding is not None and
                head_binding.collection == 'REQBODY_PROCESSOR' and
                head_binding.selector_kind == 'none' and
                not head.get('negated') and head.get('operator') == '@streq' and
                _only_none_transforms(head) and
                method_binding.collection == 'REQUEST_BODY' and
                method_binding.selector_kind == 'none' and
                not method_member.get('negated') and
                method_member.get('operator') == '@rx' and
                _only_none_transforms(method_member) and
                value_binding.collection == 'REQUEST_BODY' and
                value_binding.selector_kind == 'none' and
                not value_member.get('negated') and
                value_member.get('operator') == '@validateUrlEncoding' and
                _only_none_transforms(value_member)):
            return {
                'kind': 'request-body-processor-url-validator',
                'processor': head.get('pattern') or '',
                'body_precondition_pattern': method_member.get('pattern') or '',
            }
        expanded = re.fullmatch(
            r'%\{ARGS(?:_GET|_POST)?\.([^}]+)\}',
            (method_member.get('pattern') or '').strip(), re.I)
        if (head_binding is not None and method_binding is not None and
                value_binding is not None and expanded and
                head_binding.collection == 'TX' and
                head_binding.selector_kind == 'literal' and not head_binding.count and
                not head.get('negated') and head.get('operator') == '@eq' and
                static_tx_values.get(head_binding.selector.lower()) ==
                    (head.get('pattern') or '').strip() and
                method_binding.collection == 'REQUEST_METHOD' and
                method_binding.selector_kind == 'none' and method_member.get('negated') and
                method_member.get('operator') == '@streq' and
                value_binding.collection in {'ARGS', 'ARGS_GET', 'ARGS_POST'} and
                value_binding.selector_kind == 'literal' and
                value_binding.selector.lower() == expanded.group(1).lower() and
                not value_member.get('negated') and value_member.get('operator') == '@rx'):
            transforms = {item.lower() for item in (value_member.get('transforms') or [])}
            if transforms <= {'none', 'urldecodeuni', 'lowercase'}:
                return {
                    'kind': 'request-method-override-parameter',
                    'parameter_name': value_binding.selector,
                    'parameter_collection': value_binding.collection,
                    'value_pattern': value_member.get('pattern') or '',
                    'lowercase_value': 'lowercase' in transforms,
                }

    if len(members) == 2:
        head, suffix_member = members
        head_binding = _single_positive_binding(head)
        suffix_binding = _single_positive_binding(suffix_member)

        suffix_bindings = [
            binding for binding in suffix_member.get('bindings', [])
            if not binding.excluded
        ]
        head_transforms_set = {
            item.lower() for item in (head.get('transforms') or [])
        }
        suffix_transforms_set = {
            item.lower() for item in (suffix_member.get('transforms') or [])
        }
        dynamic_name_assignment = _tx_dynamic_name_match_assignment(head)
        header_policy_expansion = re.fullmatch(
            r'%\{tx\.([A-Za-z0-9_.-]+)\}',
            (suffix_member.get('pattern') or '').strip(), re.I)
        if (head_binding is not None and suffix_binding is not None and
                head_binding.collection == 'REQUEST_HEADERS_NAMES' and
                head_binding.selector_kind == 'none' and not head_binding.count and
                not head.get('negated') and head.get('operator') == '@rx' and
                'capture' in (head.get('actions') or {}) and
                _has_absolute_start_anchor(head.get('pattern') or '') and
                dynamic_name_assignment is not None and
                dynamic_name_assignment['capture_group'] == 0 and
                suffix_binding.collection == 'TX' and
                suffix_binding.selector_kind == 'regex' and
                _tx_selector_matches_names(
                    suffix_binding.selector,
                    dynamic_name_assignment['representative_names']) and
                not suffix_member.get('negated') and
                suffix_member.get('operator') == '@within' and
                header_policy_expansion and
                header_policy_expansion.group(1).lower() in static_tx_values and
                head_transforms_set <= {'none', 'lowercase'} and
                suffix_transforms_set <= {'none', 'lowercase'}):
            return {
                'kind': 'header-name-match-within-static-tx',
                'match_pattern': head.get('pattern') or '',
                'match_lowercase': 'lowercase' in head_transforms_set,
                'value_prefix': dynamic_name_assignment['value_prefix'],
                'value_suffix': dynamic_name_assignment['value_suffix'],
                'allowed_value': static_tx_values[
                    header_policy_expansion.group(1).lower()],
                'lowercase_value': (
                    'lowercase' in head_transforms_set or
                    'lowercase' in suffix_transforms_set),
            }

        utf8_collections = {'REQUEST_FILENAME', 'ARGS', 'ARGS_NAMES'}
        if (head_binding is not None and
                head_binding.collection == 'TX' and
                head_binding.selector_kind == 'literal' and not head_binding.count and
                not head.get('negated') and head.get('operator') == '@eq' and
                head_transforms_set <= {'none'} and
                static_tx_values.get(head_binding.selector.lower()) ==
                    (head.get('pattern') or '').strip() and
                suffix_bindings and all(
                    binding.recognized and not binding.count and
                    binding.selector_kind == 'none' and
                    binding.collection in utf8_collections
                    for binding in suffix_bindings) and
                not suffix_member.get('negated') and
                suffix_member.get('operator') == '@validateUtf8Encoding' and
                suffix_transforms_set <= {'none'}):
            return {
                'kind': 'static-tx-gated-utf8-validator',
                'collections': sorted({
                    binding.collection for binding in suffix_bindings
                }),
            }

        head_pattern = head.get('pattern') or ''
        capture_parts = _split_terminal_capture(head_pattern)
        capture_assignment = _tx_match_assignment(head)
        static_expansion = re.fullmatch(
            r'%\{tx\.([A-Za-z0-9_.-]+)\}',
            (suffix_member.get('pattern') or '').strip(), re.I)
        transforms = {item.lower() for item in (suffix_member.get('transforms') or [])}
        if (head_binding is not None and suffix_binding is not None and
                head_binding.collection == 'REQUEST_HEADERS' and
                head_binding.selector_kind == 'literal' and not head.get('negated') and
                head.get('operator') == '@rx' and 'capture' in (head.get('actions') or {}) and
                capture_assignment is not None and
                suffix_binding.collection == 'TX' and
                suffix_binding.selector_kind == 'literal' and
                suffix_binding.selector.lower() == capture_assignment[0].lower() and
                suffix_member.get('negated') and suffix_member.get('operator') == '@within' and
                static_expansion and static_expansion.group(1).lower() in static_tx_values and
                transforms <= {'none', 'lowercase'}):
            header_mask = HEADER_MASKS.get(head_binding.selector.upper(), 0)
            if header_mask:
                descriptor = {
                    'capture_header_mask': header_mask,
                    'capture_header_name': head_binding.selector,
                    'value_prefix': capture_assignment[1],
                    'value_suffix': capture_assignment[2],
                    'allowed_value': static_tx_values[static_expansion.group(1).lower()],
                    'lowercase_value': 'lowercase' in transforms,
                }
                capture_group = capture_assignment[3]
                if capture_group == 1 and capture_parts is not None:
                    descriptor.update({
                        'kind': 'named-header-capture-not-within-static-tx',
                        'prefix_pattern': capture_parts[0],
                        'capture_pattern': capture_parts[1],
                    })
                    return descriptor
                if capture_group == 0 and _has_absolute_start_anchor(head_pattern):
                    descriptor.update({
                        'kind': 'named-header-match-not-within-static-tx',
                        'match_pattern': head_pattern,
                    })
                    return descriptor

        head_transforms = [
            item.lower() for item in (head.get('transforms') or [])
            if item.lower() != 'none'
        ]
        suffix_transforms = {
            item.lower() for item in (suffix_member.get('transforms') or [])
        }
        if (head_binding is not None and suffix_binding is not None and
                head_binding.collection == 'REQUEST_BASENAME' and
                head_binding.selector_kind == 'none' and not head_binding.count and
                not head.get('negated') and head.get('operator') == '@rx' and
                'capture' in (head.get('actions') or {}) and
                capture_assignment is not None and capture_assignment[3] == 1 and
                capture_parts is not None and
                suffix_binding.collection == 'TX' and
                suffix_binding.selector_kind == 'literal' and
                suffix_binding.selector.lower() == capture_assignment[0].lower() and
                not suffix_member.get('negated') and
                suffix_member.get('operator') == '@within' and static_expansion and
                static_expansion.group(1).lower() in static_tx_values and
                set(head_transforms) <= {'urldecodeuni', 'lowercase'} and
                suffix_transforms <= {'none', 'lowercase'}):
            return {
                'kind': 'request-basename-capture-within-static-tx',
                'prefix_pattern': capture_parts[0],
                'capture_pattern': capture_parts[1],
                'value_prefix': capture_assignment[1],
                'value_suffix': capture_assignment[2],
                'allowed_value': static_tx_values[static_expansion.group(1).lower()],
                'head_transforms': head_transforms,
                'lowercase_value': 'lowercase' in suffix_transforms,
            }
        suffix_expansion = re.fullmatch(
            r'\.\%\{request_headers\.([^}]+)\}',
            (suffix_member.get('pattern') or '').strip(), re.I)
        pattern = head.get('pattern') or ''
        capture_suffix = '([^/]*)'
        has_capture_assignment = bool(re.search(
            r"setvar\s*:\s*['\"]?tx\.[^=,]+\s*=\s*\.\%\{tx\.1\}",
            head.get('raw') or '', re.I))
        if (head_binding is not None and suffix_binding is not None and
                head_binding.collection in {'ARGS', 'ARGS_GET', 'ARGS_POST'} and
                head_binding.selector_kind == 'none' and not head.get('negated') and
                head.get('operator') == '@rx' and 'capture' in (head.get('actions') or {}) and
                pattern.endswith(capture_suffix) and has_capture_assignment and
                suffix_binding.collection == 'TX' and
                suffix_binding.selector_kind == 'regex' and suffix_member.get('negated') and
                suffix_member.get('operator') == '@endsWith' and suffix_expansion):
            header_mask = HEADER_MASKS.get(suffix_expansion.group(1).upper(), 0)
            if header_mask:
                return {
                    'kind': 'arg-url-authority-off-domain',
                    'parameter_collection': head_binding.collection,
                    'prefix_pattern': pattern[:-len(capture_suffix)],
                    'suffix_header_mask': header_mask,
                    'suffix_header_name': suffix_expansion.group(1),
                }

    head = members[0]
    head_binding = _single_positive_binding(head)
    if (head_binding is None or
            head_binding.collection not in {'ARGS_NAMES', 'ARGS_GET_NAMES', 'ARGS_POST_NAMES'} or
            head_binding.selector_kind != 'none' or head.get('negated') or
            head.get('operator') != '@rx'):
        return None

    if len(members) == 2:
        child = members[1]
        binding = _single_positive_binding(child)
        if (binding is None or not binding.count or
                binding.collection != 'REQUEST_HEADERS' or
                binding.selector_kind != 'literal' or child.get('negated') or
                child.get('operator') != '@eq' or
                (child.get('pattern') or '').strip() != '0'):
            return None
        header_mask = HEADER_MASKS.get(binding.selector.upper(), 0)
        if not header_mask:
            return None
        return {
            'kind': 'arg-name-and-header-absent',
            'header_mask': header_mask,
            'header_name': binding.selector,
        }

    capture_member, suffix_member = members[1], members[2]
    capture_binding = _single_positive_binding(capture_member)
    suffix_binding = _single_positive_binding(suffix_member)
    if (capture_binding is None or suffix_binding is None):
        return None
    if (capture_binding.collection != 'REQUEST_HEADERS' or
            capture_binding.selector_kind != 'literal' or
            capture_member.get('negated') or capture_member.get('operator') != '@rx' or
            'capture' not in (capture_member.get('actions') or {})):
        return None
    # This lowering has an exact bounded authority extractor for this regular
    # language. Other capture expressions require a generated capture DFA ABI.
    if (capture_member.get('pattern') or '').strip() != r'^(?:ht|f)tps?://(.*?)/':
        return None
    if (suffix_binding.collection != 'TX' or suffix_binding.selector != '1' or
            not suffix_member.get('negated') or
            suffix_member.get('operator') != '@endsWith'):
        return None
    expanded = re.fullmatch(
        r'%\{request_headers\.([^}]+)\}',
        (suffix_member.get('pattern') or '').strip(), re.I)
    if not expanded:
        return None

    capture_mask = HEADER_MASKS.get(capture_binding.selector.upper(), 0)
    suffix_mask = HEADER_MASKS.get(expanded.group(1).upper(), 0)
    if not capture_mask or not suffix_mask:
        return None
    return {
        'kind': 'arg-name-and-off-domain-header',
        'capture_header_mask': capture_mask,
        'capture_header_name': capture_binding.selector,
        'suffix_header_mask': suffix_mask,
        'suffix_header_name': expanded.group(1),
    }


def _same_buffer_chain_child_mode(head, member):
    """Classify one child as same-value or positive global-XML."""
    member_bindings = member.get('bindings') or parse_variable_bindings(
        member.get('variables') or '')
    head_bindings = head.get('bindings') or parse_variable_bindings(
        head.get('variables') or '')
    positive = {binding.collection for binding in member_bindings
                if not binding.excluded}
    if positive == {'MATCHED_VARS'}:
        return 'same-value'
    head_collections = {binding.collection for binding in head_bindings
                        if not binding.excluded}
    if (positive == {'MATCHED_VARS', 'XML'} and 'XML' in head_collections and
            not member.get('negated')):
        return 'global-xml'
    return None


def same_buffer_rx_chain_reason(rule):
    """Return None only for chains safely reducible to one buffer predicate.

    MATCHED_VARS means the value matched by the preceding chain member. The
    current lowering supports positive @rx children over exactly that value.
    A `capture` action does not require runtime TX storage when no chain
    predicate reads TX.N; capture values used only by logging do not change the
    detection verdict. TX predicates, alternate collections and negation remain
    explicit typed-state gaps.
    """
    members = rule.get('_chain_members')
    if not members or len(members) < 2:
        return 'not-a-chain'
    if members[0].get('negated') or members[0].get('operator') != '@rx':
        return 'chain-head-operator-requires-state'
    if any(member.get('operator') != '@rx' for member in members[1:]):
        return 'chain-operator-requires-state'
    for member in members:
        if re.search(r'%\{tx\.[0-9]+\}', member.get('pattern') or '', re.I):
            return 'chain-pattern-tx-requires-state'
    for member in members[1:]:
        if _same_buffer_chain_child_mode(members[0], member) is None:
            return 'chain-collection-requires-state'
        if not _only_none_transforms(member):
            return 'chain-child-transform-requires-state'
    return None


def _terminal_capture_chain_plan(rule):
    """Build a proven AOT plan for a terminal group-1 TX chain.

    The parent regex is evaluated before the TX child in ModSecurity. A plain
    DFA recognizes the parent language but does not retain PCRE submatch
    priorities, so this lowering accepts only a root-level terminal group 1
    with a simple greedy one-byte repeat. An optional greedy one-byte bridge
    immediately before the capture is split into its own longest-end DFA.
    Disjoint bridge and capture alphabets make that split unambiguous.
    """
    members = rule.get('_chain_members') or []
    if len(members) != 2:
        return None, 'terminal-capture-chain-member-count'
    head, child = members
    if (head.get('negated') or head.get('operator') != '@rx' or
            'capture' not in (head.get('actions') or {})):
        return None, 'terminal-capture-chain-head'
    if not _has_absolute_start_anchor(head.get('pattern') or ''):
        return None, 'terminal-capture-chain-head-is-not-absolute-start'
    child_binding = _single_positive_binding(child)
    if (child_binding is None or child_binding.count or
            child_binding.collection != 'TX' or
            child_binding.selector_kind != 'literal' or
            child_binding.selector != '1'):
        return None, 'terminal-capture-chain-child-is-not-tx1'
    if child.get('operator') != '@rx' or not _only_none_transforms(child):
        return None, 'terminal-capture-chain-child-operator-or-transform'
    if re.search(r'%\{tx\.[0-9]+\}', child.get('pattern') or '', re.I):
        return None, 'terminal-capture-chain-child-pattern-expansion'
    for name, value in _raw_setvar_assignments(head):
        if re.search(r'%\{tx\.[1-9][0-9]*\}', name + value, re.I):
            return None, 'terminal-capture-chain-capture-side-effect'

    try:
        head_ast, head_ignore_case, head_dot_all = parse_regex_ast(
            head.get('pattern') or '')
    except Exception as exc:
        return None, f'terminal-capture-chain-head-parse: {exc}'
    data = list(head_ast.data)
    suffix = []
    allowed_suffix = {
        'AT_BOUNDARY', 'AT_NON_BOUNDARY', 'AT_END', 'AT_END_STRING',
    }
    while data and getattr(data[-1][0], 'name', str(data[-1][0])) == 'AT':
        at_name = getattr(data[-1][1], 'name', str(data[-1][1]))
        if at_name not in allowed_suffix:
            return None, 'terminal-capture-chain-unsupported-suffix'
        suffix.insert(0, data.pop())
    if not data or getattr(data[-1][0], 'name', str(data[-1][0])) != 'SUBPATTERN':
        return None, 'terminal-capture-chain-capture-is-not-terminal'
    capture_node = data.pop()
    capture_group, _, _, capture_body = capture_node[1]
    if capture_group != 1:
        return None, 'terminal-capture-chain-selector-is-not-group1'

    def numbered_capture_count(nodes):
        count = 0
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            if name == 'SUBPATTERN':
                count += int(value[0] is not None)
                count += numbered_capture_count(value[3])
            elif name == 'BRANCH':
                count += sum(numbered_capture_count(branch) for branch in value[1])
            elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
                count += numbered_capture_count(value[2])
            elif name in ('ASSERT', 'ASSERT_NOT'):
                count += numbered_capture_count(value[1])
        return count

    if numbered_capture_count(data) or numbered_capture_count(capture_body):
        return None, 'terminal-capture-chain-multiple-captures'
    capture_body = list(capture_body)
    if len(capture_body) != 1:
        return None, 'terminal-capture-chain-capture-is-not-linear'
    capture_op, capture_repeat = capture_body[0]
    capture_op_name = getattr(capture_op, 'name', str(capture_op))
    if capture_op_name not in ('MAX_REPEAT', 'POSSESSIVE_REPEAT'):
        return None, 'terminal-capture-chain-capture-is-not-greedy-repeat'
    capture_minimum, capture_maximum, capture_inner = capture_repeat
    if (capture_minimum < 1 or not
            (capture_maximum == reparser.MAXREPEAT or int(capture_maximum) >= 0xFFFFFFFF)):
        return None, 'terminal-capture-chain-capture-repeat-bounds'

    def one_byte_alphabet(nodes):
        nodes = list(nodes)
        if len(nodes) != 1:
            return None
        op, value = nodes[0]
        name = getattr(op, 'name', str(op))
        if name == 'LITERAL' and 0 <= value < 256:
            alphabet = {value}
            if head_ignore_case and 65 <= value <= 90:
                alphabet.add(value + 32)
            elif head_ignore_case and 97 <= value <= 122:
                alphabet.add(value - 32)
            return alphabet
        if name == 'NOT_LITERAL' and 0 <= value < 256:
            alphabet = set(range(256)) - {value}
            if head_ignore_case and 65 <= value <= 90:
                alphabet.discard(value + 32)
            elif head_ignore_case and 97 <= value <= 122:
                alphabet.discard(value - 32)
            return alphabet
        if name == 'IN':
            mask = build_bitmask_for_in(value, head_ignore_case)
            return {byte for byte in range(256)
                    if mask[byte >> 6] & (1 << (byte & 63))}
        return None

    capture_alphabet = one_byte_alphabet(capture_inner)
    if not capture_alphabet:
        return None, 'terminal-capture-chain-capture-alphabet'

    bridge_ast = None
    if data:
        bridge_op, bridge_repeat = data[-1]
        bridge_name = getattr(bridge_op, 'name', str(bridge_op))
        if bridge_name in ('MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            bridge_minimum, bridge_maximum, bridge_inner = bridge_repeat
            if (bridge_minimum != 0 or not
                    (bridge_maximum == reparser.MAXREPEAT or
                     int(bridge_maximum) >= 0xFFFFFFFF)):
                return None, 'terminal-capture-chain-bridge-repeat-bounds'
            bridge_alphabet = one_byte_alphabet(bridge_inner)
            if not bridge_alphabet:
                return None, 'terminal-capture-chain-bridge-alphabet'
            if bridge_alphabet & capture_alphabet:
                return None, 'terminal-capture-chain-bridge-overlaps-capture'
            bridge_ast = type(head_ast)(head_ast.state, data=[data.pop()])

    if not data:
        return None, 'terminal-capture-chain-empty-prefix'
    core_ast = type(head_ast)(head_ast.state, data=data)
    capture_ast = type(head_ast)(head_ast.state, data=capture_body + suffix)
    child_pattern = child.get('pattern') or ''
    if not _has_absolute_start_anchor(child_pattern):
        child_pattern = r'(?:[\x00-\xff]*)(?:' + child_pattern + ')'
    return {
        'core_ast': core_ast,
        'bridge_ast': bridge_ast,
        'capture_ast': capture_ast,
        'head_ignore_case': head_ignore_case,
        'head_dot_all': head_dot_all,
        'child_pattern': child_pattern,
        'child_negated': bool(child.get('negated')),
    }, None


def terminal_capture_same_value_chain_reason(rule):
    """Return None only for a statically proven terminal-capture TX chain."""
    _, reason = _terminal_capture_chain_plan(rule)
    return reason


def _two_capture_compare_chain_plan(rule):
    """Build a bounded plan for TX.1/TX.2 equality chain predicates.

    A language DFA does not preserve PCRE submatch priority. This lowering is
    therefore limited to two top-level, linear byte-repeat captures separated
    by deterministic regular fragments. The generated walkers recover capture
    boundaries without storing general transaction strings.
    """
    members = rule.get('_chain_members') or []
    if len(members) != 2:
        return None, 'two-capture-compare-member-count'
    head, child = members
    if (head.get('negated') or head.get('operator') != '@rx' or
            'capture' not in (head.get('actions') or {})):
        return None, 'two-capture-compare-head'
    child_binding = _single_positive_binding(child)
    if (child_binding is None or child_binding.count or
            child_binding.collection != 'TX' or
            child_binding.selector_kind != 'literal' or
            child_binding.selector != '1' or
            child.get('operator') != '@streq' or
            not _only_none_transforms(child) or
            not re.fullmatch(r'%\{tx\.2\}', (child.get('pattern') or '').strip(), re.I)):
        return None, 'two-capture-compare-child'
    for name, value in _raw_setvar_assignments(head):
        if re.search(r'%\{tx\.[12]\}', name + value, re.I):
            return None, 'two-capture-compare-capture-side-effect'

    try:
        head_ast, ignore_case, dot_all = parse_regex_ast(head.get('pattern') or '')
    except Exception as exc:
        return None, f'two-capture-compare-head-parse: {exc}'

    def numbered_captures(nodes):
        result = []
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            if name == 'SUBPATTERN':
                if value[0] is not None:
                    result.append(int(value[0]))
                result.extend(numbered_captures(value[3]))
            elif name == 'BRANCH':
                for branch in value[1]:
                    result.extend(numbered_captures(branch))
            elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
                result.extend(numbered_captures(value[2]))
            elif name in ('ASSERT', 'ASSERT_NOT'):
                result.extend(numbered_captures(value[1]))
        return result

    data = list(head_ast.data)
    top_level = [
        (index, int(value[0]), value[3])
        for index, (op, value) in enumerate(data)
        if getattr(op, 'name', str(op)) == 'SUBPATTERN' and value[0] is not None
    ]
    if numbered_captures(data) != [1, 2] or [item[1] for item in top_level] != [1, 2]:
        return None, 'two-capture-compare-capture-layout'

    def linear_capture_body(nodes):
        nodes = list(nodes)
        if len(nodes) != 1:
            return False
        op, value = nodes[0]
        name = getattr(op, 'name', str(op))
        if name not in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            return False
        minimum, maximum, inner = value
        unbounded = maximum == reparser.MAXREPEAT or int(maximum) >= 0xFFFFFFFF
        if int(minimum) < 1 or not unbounded or len(inner) != 1:
            return False
        atom_name = getattr(inner[0][0], 'name', str(inner[0][0]))
        return atom_name in {'LITERAL', 'NOT_LITERAL', 'IN', 'ANY'}

    first_index, _, first_body = top_level[0]
    second_index, _, second_body = top_level[1]
    if not linear_capture_body(first_body) or not linear_capture_body(second_body):
        return None, 'two-capture-compare-nonlinear-capture'

    def minimum_width(nodes):
        width = 0
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            if name in {'LITERAL', 'NOT_LITERAL', 'IN', 'ANY', 'CATEGORY'}:
                width += 1
            elif name == 'SUBPATTERN':
                width += minimum_width(value[3])
            elif name == 'BRANCH':
                width += min((minimum_width(branch) for branch in value[1]), default=0)
            elif name in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
                width += int(value[0]) * minimum_width(value[2])
            elif name == 'AT':
                continue
            else:
                return 1
        return width

    prefix_nodes = data[:first_index]
    bridge_nodes = data[first_index + 1:second_index]
    suffix_nodes = data[second_index + 1:]
    if minimum_width(prefix_nodes) != 0:
        return None, 'two-capture-compare-consuming-prefix'
    if minimum_width(suffix_nodes) != 0:
        return None, 'two-capture-compare-consuming-suffix'
    if not bridge_nodes:
        return None, 'two-capture-compare-empty-bridge'

    make_ast = lambda nodes: type(head_ast)(head_ast.state, data=list(nodes))
    return {
        'prefix_ast': make_ast(prefix_nodes),
        'capture1_ast': make_ast(first_body),
        'bridge_ast': make_ast(bridge_nodes),
        'capture2_ast': make_ast(list(second_body) + suffix_nodes),
        'ignore_case': ignore_case,
        'dot_all': dot_all,
        'equal': not bool(child.get('negated')),
        'multimatch': bool(head.get('multimatch')),
    }, None


def two_capture_compare_chain_reason(rule):
    """Return None only for a statically proven TX.1/TX.2 comparison."""
    _, reason = _two_capture_compare_chain_plan(rule)
    return reason


def _only_none_transforms(member):
    return all(transform.strip().lower() == 'none'
               for transform in member.get('transforms', []))


def same_buffer_phrase_chain_reason(rule):
    """Validate a stateless phrase head plus same-value phrase/regex chain.

    `capture` is observable only when a later predicate or side effect consumes
    the captured TX value. Logging does not affect the detection verdict, so a
    capture used only by `logdata` can be lowered without request-time TX state.
    """
    members = rule.get('_chain_members')
    if not members or len(members) < 2:
        return 'not-a-chain'
    if members[0].get('negated') or members[0].get('operator') != '@pmFromFile':
        return 'chain-head-is-not-pm-from-file'
    for member in members[1:]:
        if member.get('operator') not in ('@pm', '@rx'):
            return 'chain-operator-requires-state'
        if (member.get('variables') or '').strip().upper() != 'MATCHED_VARS':
            return 'chain-collection-requires-state'
        if not _only_none_transforms(member):
            return 'chain-child-transform-requires-state'
        if not member.get('pattern'):
            return 'chain-empty-phrase-set'
    for member in members:
        if '%{tx.' in (member.get('pattern') or '').lower():
            return 'chain-pattern-tx-requires-state'
        variables = (member.get('variables') or '').upper()
        if 'TX:' in variables:
            return 'chain-collection-requires-state'
        for name, value in _raw_setvar_assignments(member):
            if re.search(r'%\{tx\.[0-9]+\}', name + value, re.I):
                return 'chain-capture-side-effect-requires-state'
    return None


def load_pm_literals(data_file, data_dir, rules_dir):
    """Resolve and load a ModSecurity `@pmFromFile` phrase list."""
    candidates = (
        os.path.join(data_dir or rules_dir, data_file),
        os.path.join(rules_dir, 'rules', data_file),
        data_file,
        os.path.join(data_dir or rules_dir, data_file + '.data'),
        os.path.join(rules_dir, 'rules', data_file + '.data'),
    )
    data_path = next((candidate for candidate in candidates
                      if os.path.exists(candidate)), None)
    if data_path is None:
        return None
    literals = []
    with open(data_path, 'r', encoding='utf-8', errors='ignore') as source:
        for line in source:
            line = line.strip()
            if line and not line.startswith('#'):
                literals.append(line)
    return literals


def emit_same_buffer_rule_wrapper(rule, value_helper, xml_collection_plan=None):
    """Emit offset-zero dispatch with typed XML value projection."""
    rule_id = str(rule['id'])
    code = []
    collections = {binding.collection for binding in rule.get('bindings', [])
                   if not binding.excluded}
    xml_aware = 'XML' in collections
    if not xml_aware:
        return (
            f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    if (offset != 0) return 0;\n"
            f"    return {value_helper}(data, len) ? {rule_id} : 0;\n"
            f"}}\n"
        )
    if xml_collection_plan:
        return emit_xml_collection_rule_wrapper(
            rule, value_helper, xml_collection_plan)

    # ModSecurity XML collections expose element text and attribute values,
    # not tag or attribute names. Keep that collection boundary without heap
    # allocation and fall back to the ordinary value for non-XML buffers.
    xml_helper = f"lumina_chain_{rule_id}_xml_values"
    code.append(f"""
static int {xml_helper}(const unsigned char *data, size_t len) {{
    size_t pos = 0;
    while (pos < len && (data[pos] == ' ' || data[pos] == '\\t' || data[pos] == '\\r' || data[pos] == '\\n')) pos++;
    if (pos + 5 > len || data[pos] != '<' || data[pos+1] != '?' ||
        (data[pos+2] | 32) != 'x' || (data[pos+3] | 32) != 'm' || (data[pos+4] | 32) != 'l') return -1;
    pos = 0;
    while (pos < len) {{
        if (data[pos] != '<') {{
            size_t start = pos;
            while (pos < len && data[pos] != '<') pos++;
            if (pos > start && {value_helper}(data + start, pos - start)) return 1;
            continue;
        }}
        if (pos + 9 <= len && data[pos+1] == '!' && data[pos+2] == '[' &&
            data[pos+3] == 'C' && data[pos+4] == 'D' && data[pos+5] == 'A' &&
            data[pos+6] == 'T' && data[pos+7] == 'A' && data[pos+8] == '[') {{
            size_t start = pos + 9;
            pos = start;
            while (pos + 2 < len && !(data[pos] == ']' && data[pos+1] == ']' && data[pos+2] == '>')) pos++;
            if (pos > start && {value_helper}(data + start, pos - start)) return 1;
            pos = pos + 2 < len ? pos + 3 : len;
            continue;
        }}
        if (pos + 4 <= len && data[pos+1] == '!' && data[pos+2] == '-' && data[pos+3] == '-') {{
            pos += 4;
            while (pos + 2 < len && !(data[pos] == '-' && data[pos+1] == '-' && data[pos+2] == '>')) pos++;
            pos = pos + 2 < len ? pos + 3 : len;
            continue;
        }}
        pos++;
        while (pos < len && data[pos] != '>') {{
            if (data[pos] == '\"' || data[pos] == 0x27) {{
                unsigned char quote = data[pos++];
                size_t start = pos;
                while (pos < len && data[pos] != quote) pos++;
                if (pos > start && {value_helper}(data + start, pos - start)) return 1;
                if (pos < len) pos++;
            }} else {{
                pos++;
            }}
        }}
        if (pos < len) pos++;
    }}
    return 0;
}}
""")
    code.append(
        f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
        f"    if (offset != 0) return 0;\n"
        f"    int xml_match = {xml_helper}(data, len);\n"
        f"    if (xml_match >= 0) return xml_match ? {rule_id} : 0;\n"
        f"    return {value_helper}(data, len) ? {rule_id} : 0;\n"
        f"}}\n"
    )
    return '\n'.join(code)


def emit_xml_collection_rule_wrapper(rule, value_helper, plan):
    """Emit same-value fallback plus cross-value positive XML predicates."""
    rule_id = str(rule['id'])
    base_helper = plan['base_helper']
    global_helpers = plan['global_helpers']
    observer = f"lumina_chain_{rule_id}_xml_observe"
    xml_helper = f"lumina_chain_{rule_id}_xml_values"
    global_calls = ''.join(
        f"    if ({helper}(data, len, 0)) global_seen[{index}] = 1;\n"
        for index, helper in enumerate(global_helpers)
    )
    return f"""
static void {observer}(const unsigned char *data, size_t len,
                       int *base_seen, unsigned char *global_seen) {{
    if ({base_helper}(data, len)) *base_seen = 1;
{global_calls}}}

static int {xml_helper}(const unsigned char *data, size_t len) {{
    size_t pos = 0;
    while (pos < len && (data[pos] == ' ' || data[pos] == '\\t' ||
           data[pos] == '\\r' || data[pos] == '\\n')) pos++;
    if (pos + 5 > len || data[pos] != '<' || data[pos+1] != '?' ||
        (data[pos+2] | 32) != 'x' || (data[pos+3] | 32) != 'm' ||
        (data[pos+4] | 32) != 'l') return -1;
    int base_seen = 0;
    unsigned char global_seen[{len(global_helpers)}] = {{0}};
    pos = 0;
    while (pos < len) {{
        if (data[pos] != '<') {{
            size_t start = pos;
            while (pos < len && data[pos] != '<') pos++;
            if (pos > start) {observer}(
                data + start, pos - start, &base_seen, global_seen);
            continue;
        }}
        if (pos + 9 <= len && data[pos+1] == '!' && data[pos+2] == '[' &&
            data[pos+3] == 'C' && data[pos+4] == 'D' && data[pos+5] == 'A' &&
            data[pos+6] == 'T' && data[pos+7] == 'A' && data[pos+8] == '[') {{
            size_t start = pos + 9;
            pos = start;
            while (pos + 2 < len && !(data[pos] == ']' &&
                   data[pos+1] == ']' && data[pos+2] == '>')) pos++;
            if (pos > start) {observer}(
                data + start, pos - start, &base_seen, global_seen);
            pos = pos + 2 < len ? pos + 3 : len;
            continue;
        }}
        if (pos + 4 <= len && data[pos+1] == '!' && data[pos+2] == '-' &&
            data[pos+3] == '-') {{
            pos += 4;
            while (pos + 2 < len && !(data[pos] == '-' &&
                   data[pos+1] == '-' && data[pos+2] == '>')) pos++;
            pos = pos + 2 < len ? pos + 3 : len;
            continue;
        }}
        pos++;
        while (pos < len && data[pos] != '>') {{
            if (data[pos] == '"' || data[pos] == 0x27) {{
                unsigned char quote = data[pos++];
                size_t start = pos;
                while (pos < len && data[pos] != quote) pos++;
                if (pos > start) {observer}(
                    data + start, pos - start, &base_seen, global_seen);
                if (pos < len) pos++;
            }} else {{
                pos++;
            }}
        }}
        if (pos < len) pos++;
    }}
    if (!base_seen) return 0;
    for (size_t i = 0; i < {len(global_helpers)}; i++)
        if (!global_seen[i]) return 0;
    return 1;
}}

int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{
    if (offset != 0) return 0;
    int xml_match = {xml_helper}(data, len);
    if (xml_match >= 0) return xml_match ? {rule_id} : 0;
    return {value_helper}(data, len) ? {rule_id} : 0;
}}
"""


def emit_same_buffer_rx_chain(rule, state_budget=1536, table_budget=2 * 1024 * 1024):
    """Emit an O(member_count * input_length) native DFA chain predicate."""
    rule_id = str(rule['id'])
    members = rule['_chain_members']
    code = []
    helper_names = []
    helper_negated = []
    child_modes = ['same-value']
    recursive_used = False
    bounded_nfa_used = False
    seeded_nfa_used = False
    for ordinal, member in enumerate(members):
        helper = f"lumina_chain_{rule_id}_{ordinal}"
        prefix = f"lumina_chain_dfa_{rule_id}_{ordinal}"
        # Prefixing with a full-byte Kleene star turns offset matching into a
        # linear contains predicate while retaining anchors and boundaries.
        search_pattern = r"(?:[\x00-\xff]*)(?:" + member['pattern'] + ")"
        try:
            code.append(emit_dfa_c(
                rule_id,
                search_pattern,
                state_budget=state_budget,
                table_budget=table_budget,
                function_name=helper,
                symbol_prefix=prefix,
                match_value=1,
                static_function=True,
            ))
        except DfaUnsupportedRegex:
            try:
                nfa = compile_bitset_nfa(
                    search_pattern,
                    state_budget=512,
                    word_budget=8,
                    vector_budget=255,
                    table_budget=256 * 1024,
                )
                if nfa['state_count'] < 256:
                    raise DfaUnsupportedRegex(
                        "bounded NFA reserved for large Thompson graphs")
                fast_accept_plan = compile_seeded_fast_accept_branches(
                    member['pattern'],
                    state_budget=128,
                    table_budget=64 * 1024,
                    min_seed_len=4,
                    max_branches=4,
                )
                mandatory_seed_cover = compile_mandatory_seed_cover(
                    member['pattern'], min_seed_len=1, max_seeds=16)
                code.append(emit_bitset_nfa_c(
                    rule_id,
                    search_pattern,
                    state_budget=512,
                    word_budget=8,
                    vector_budget=255,
                    table_budget=256 * 1024,
                    function_name=helper,
                    symbol_prefix=f"{prefix}_bounded_nfa",
                    match_value=1,
                    static_function=True,
                    fast_accept_plan=fast_accept_plan,
                    fast_accept_table_budget=64 * 1024,
                    mandatory_seed_cover=mandatory_seed_cover,
                ))
                bounded_nfa_used = True
                seeded_nfa_used = seeded_nfa_used or bool(fast_accept_plan)
            except DfaUnsupportedRegex:
                code.append(emit_recursive_factored_concat_dfa(
                    rule_id,
                    member['pattern'],
                    state_budget=max(state_budget, 8192),
                    table_budget=table_budget,
                    total_table_budget=8 * 1024 * 1024,
                    function_name=helper,
                    symbol_prefix=f"{prefix}_recursive",
                    match_value=1,
                    static_function=True,
                ))
                recursive_used = True
        helper_names.append(helper)
        helper_negated.append(bool(member.get('negated')))
        if ordinal:
            child_modes.append(_same_buffer_chain_child_mode(members[0], member))
    value_helper = f"lumina_chain_{rule_id}_value"
    predicates = ''.join(
        (f"    if ({helper}(data, len, 0)) return 0;\n" if negated else
         f"    if (!{helper}(data, len, 0)) return 0;\n")
        for helper, negated in zip(helper_names, helper_negated)
    )
    code.append(
        f"static int {value_helper}(const unsigned char *data, size_t len) {{\n" +
        predicates +
        f"    return 1;\n"
        f"}}\n"
    )

    global_xml_indices = [
        index for index, mode in enumerate(child_modes)
        if mode == 'global-xml'
    ]
    xml_collection_plan = None
    if global_xml_indices:
        base_indices = [
            index for index in range(len(members))
            if index not in global_xml_indices
        ]
        base_helper = f"lumina_chain_{rule_id}_xml_base"
        base_predicates = ''.join(
            (f"    if ({helper_names[index]}(data, len, 0)) return 0;\n"
             if helper_negated[index] else
             f"    if (!{helper_names[index]}(data, len, 0)) return 0;\n")
            for index in base_indices
        )
        code.append(
            f"static int {base_helper}(const unsigned char *data, size_t len) {{\n" +
            base_predicates +
            "    return 1;\n"
            "}\n"
        )
        xml_collection_plan = {
            'base_helper': base_helper,
            'global_helpers': [helper_names[index]
                               for index in global_xml_indices],
        }

    code.append(emit_same_buffer_rule_wrapper(
        rule, value_helper, xml_collection_plan))
    rule['_chain_recursive_dfa'] = recursive_used
    rule['_chain_bounded_nfa'] = bounded_nfa_used
    rule['_chain_seeded_nfa'] = seeded_nfa_used
    rule['_chain_global_xml'] = bool(global_xml_indices)
    return '\n'.join(code)


def emit_terminal_capture_same_value_chain(
        rule, state_budget=1536, table_budget=2 * 1024 * 1024):
    """Emit a parent-first terminal capture chain as composed private DFAs."""
    plan, reason = _terminal_capture_chain_plan(rule)
    if reason is not None:
        raise DfaUnsupportedRegex(reason)
    rule_id = str(rule['id'])
    prefix = f"lumina_terminal_capture_{rule_id}"
    bridge_helper = f"{prefix}_bridge"
    capture_helper = f"{prefix}_capture"
    child_helper = f"{prefix}_child"
    delegate_helper = f"{prefix}_delegate"
    value_helper = f"{prefix}_value"
    core_helper = f"{prefix}_core"
    code = []

    if plan['bridge_ast'] is not None:
        code.append(emit_dfa_c(
            rule_id, None,
            state_budget=state_budget,
            table_budget=table_budget,
            function_name=bridge_helper,
            symbol_prefix=f"{prefix}_bridge_dfa",
            match_value=1,
            static_function=True,
            report_match_end=True,
            longest_match_end=True,
            ast=plan['bridge_ast'],
            ast_ignore_case=plan['head_ignore_case'],
            ast_dot_all=plan['head_dot_all'],
        ))
    code.append(emit_dfa_c(
        rule_id, None,
        state_budget=state_budget,
        table_budget=table_budget,
        function_name=capture_helper,
        symbol_prefix=f"{prefix}_capture_dfa",
        match_value=1,
        static_function=True,
        report_match_end=True,
        longest_match_end=True,
        ast=plan['capture_ast'],
        ast_ignore_case=plan['head_ignore_case'],
        ast_dot_all=plan['head_dot_all'],
    ))
    code.append(emit_dfa_c(
        rule_id, plan['child_pattern'],
        state_budget=state_budget,
        table_budget=table_budget,
        function_name=child_helper,
        symbol_prefix=f"{prefix}_child_dfa",
        match_value=1,
        static_function=True,
    ))

    bridge = (
        f"    if (!{bridge_helper}(data, len, prefix_end, &capture_start)) return 0;\n"
        if plan['bridge_ast'] is not None else
        "    capture_start = prefix_end;\n"
    )
    child_result = f"{child_helper}(data + capture_start, capture_end - capture_start, 0)"
    if plan['child_negated']:
        child_result = f"!{child_result}"
    code.append(
        f"static int {delegate_helper}(const unsigned char *data, size_t len, size_t prefix_end) {{\n"
        f"    size_t capture_start = prefix_end;\n"
        f"    size_t capture_end = prefix_end;\n" +
        bridge +
        f"    if (!{capture_helper}(data, len, capture_start, &capture_end)) return 0;\n"
        f"    return {child_result} ? 1 : -1;\n"
        f"}}\n"
    )
    code.append(emit_dfa_c(
        rule_id, None,
        state_budget=state_budget,
        table_budget=table_budget,
        function_name=core_helper,
        symbol_prefix=f"{prefix}_core_dfa",
        match_value=1,
        static_function=True,
        ast=plan['core_ast'],
        ast_ignore_case=plan['head_ignore_case'],
        ast_dot_all=plan['head_dot_all'],
        accept_delegate_tristate=delegate_helper,
    ))
    code.append(
        f"static int {value_helper}(const unsigned char *data, size_t len) {{\n"
        f"    return {core_helper}(data, len, 0);\n"
        f"}}\n"
    )
    code.append(emit_same_buffer_rule_wrapper(rule, value_helper))
    return '\n'.join(code)


def emit_two_capture_compare_chain(
        rule, state_budget=1536, table_budget=2 * 1024 * 1024):
    """Emit four composed DFA fragments and a zero-copy capture comparison."""
    plan, reason = _two_capture_compare_chain_plan(rule)
    if reason is not None:
        raise DfaUnsupportedRegex(reason)
    rule_id = str(rule['id'])
    prefix = f"lumina_two_capture_{rule_id}"
    helpers = {
        'prefix': f"{prefix}_prefix",
        'capture1': f"{prefix}_capture1",
        'bridge': f"{prefix}_bridge",
        'capture2': f"{prefix}_capture2",
    }
    fragments = (
        ('prefix', plan['prefix_ast'], False),
        ('capture1', plan['capture1_ast'], True),
        ('bridge', plan['bridge_ast'], True),
        ('capture2', plan['capture2_ast'], True),
    )
    code = []
    for name, ast, longest in fragments:
        code.append(emit_dfa_c(
            rule_id, None,
            state_budget=state_budget,
            table_budget=table_budget,
            function_name=helpers[name],
            symbol_prefix=f"{prefix}_{name}_dfa",
            match_value=1,
            static_function=True,
            report_match_end=True,
            longest_match_end=longest,
            ast=ast,
            ast_ignore_case=plan['ignore_case'],
            ast_dot_all=plan['dot_all'],
        ))

    value_helper = f"{prefix}_value"
    equality_result = 'equal' if plan['equal'] else '!equal'
    failed_child = 'continue;' if plan['multimatch'] else 'return 0;'
    code.append(f"""
static int {value_helper}(const unsigned char *data, size_t len) {{
    for (size_t candidate = 0; candidate < len; candidate++) {{
        size_t capture1_start = candidate;
        size_t capture1_end = candidate;
        size_t capture2_start = candidate;
        size_t capture2_end = candidate;
        if (!{helpers['prefix']}(data, len, candidate, &capture1_start) ||
            capture1_start != candidate) continue;
        if (!{helpers['capture1']}(data, len, capture1_start, &capture1_end) ||
            capture1_end <= capture1_start) continue;
        if (!{helpers['bridge']}(data, len, capture1_end, &capture2_start) ||
            capture2_start <= capture1_end) continue;
        if (!{helpers['capture2']}(data, len, capture2_start, &capture2_end) ||
            capture2_end <= capture2_start) continue;
        size_t capture1_len = capture1_end - capture1_start;
        size_t capture2_len = capture2_end - capture2_start;
        int equal = capture1_len == capture2_len;
        for (size_t index = 0; equal && index < capture1_len; index++)
            equal = data[capture1_start + index] == data[capture2_start + index];
        if ({equality_result}) return 1;
        {failed_child}
    }}
    return 0;
}}
""")
    code.append(emit_same_buffer_rule_wrapper(rule, value_helper))
    return '\n'.join(code)


def emit_same_buffer_phrase_chain(rule, head_literals, state_budget=1536,
                                  table_budget=2 * 1024 * 1024):
    """Emit phrase and native regex predicates over one transformed value."""
    rule_id = str(rule['id'])
    members = rule['_chain_members']
    code = []
    predicates = []
    for ordinal, member in enumerate(members):
        operator = member.get('operator')
        negated = bool(member.get('negated'))
        if ordinal == 0 or operator == '@pm':
            literals = (head_literals if ordinal == 0 else
                        [phrase for phrase in member['pattern'].split() if phrase])
            helper_name = f"chain_{rule_id}_{ordinal}"
            helper_code, safe = gen_phrase_scanner(helper_name, literals)
            code.append(helper_code)
            expression = f"lumina_pm_{safe}(data, len)"
        else:
            helper = f"lumina_chain_{rule_id}_{ordinal}_rx"
            search_pattern = r'(?:[\x00-\xff]*)(?:' + member['pattern'] + ')'
            code.append(emit_dfa_c(
                rule_id,
                search_pattern,
                state_budget=state_budget,
                table_budget=table_budget,
                function_name=helper,
                symbol_prefix=f"lumina_chain_{rule_id}_{ordinal}_rx_dfa",
                match_value=1,
                static_function=True,
            ))
            expression = f"{helper}(data, len, 0)"
        predicates.append(f"!({expression})" if negated else expression)
    value_helper = f"lumina_chain_{rule_id}_value"
    code.append(
        f"static int {value_helper}(const unsigned char *data, size_t len) {{\n" +
        ''.join(f"    if (!({predicate})) return 0;\n" for predicate in predicates) +
        f"    return 1;\n"
        f"}}\n"
    )
    code.append(emit_same_buffer_rule_wrapper(rule, value_helper))
    return '\n'.join(code)


def _starts_with_unbounded_repeat(pattern):
    """Return true when an AST branch begins with an unbounded consumer."""
    if reparser is None:
        return False
    try:
        parsed = reparser.parse(pattern)
    except Exception:
        return False

    def starts(nodes):
        nodes = list(nodes)
        while nodes and nodes[0][0].name == 'AT':
            nodes = nodes[1:]
        if not nodes:
            return False
        op, value = nodes[0]
        if op.name == 'SUBPATTERN':
            return starts(value[3])
        if op.name == 'BRANCH':
            return any(starts(branch) for branch in value[1])
        if op.name not in ('MIN_REPEAT', 'MAX_REPEAT', 'POSSESSIVE_REPEAT'):
            return False
        maximum = value[1]
        return maximum == reparser.MAXREPEAT or int(maximum) >= 0xFFFFFFFF

    return starts(parsed)


def dfa_search_lowering(pattern):
    """Return a linear search-DFA for expressions at quadratic-routing risk.

    Per-offset byte routing can become quadratic when a legal regex prefix also
    matches a long benign run. Prefixing an unanchored language with a full-byte
    Kleene star turns ModSecurity search semantics into one linear DFA walk from
    offset zero. This lowering is attempted for wildcard-start expressions,
    multiline anchors and branches beginning with an unbounded consumer.
    Selective fixed-prefix expressions retain the cheaper candidate router.

    Determinization remains bounded by the caller. If the search DFA exceeds
    that budget, the translator falls back to the original candidate-routed DFA.
    """
    if _has_absolute_start_anchor(pattern):
        return pattern, False
    remaining = pattern
    while True:
        global_flags = re.match(r'^\(\?[aiLmsux-]+\)', remaining)
        if not global_flags:
            break
        remaining = remaining[global_flags.end():]
    needs_search = (
        first_bytes_of(pattern) == set(range(256)) or
        _starts_with_unbounded_repeat(pattern) or
        (remaining.startswith('^') and inline_flag_enabled(pattern, 'm'))
    )
    if not needs_search:
        return pattern, False
    return r"(?:[\x00-\xff]*)(?:" + pattern + ")", True


def emit_gap_split_dfa(rule_id, pattern, state_budget=1536,
                       table_budget=2 * 1024 * 1024):
    """Lower `fixed-prefix .*? suffix` without building the monolithic DFA.

    The prefix is verified at the routed offset. A compact suffix DFA is then
    called only at bytes that can begin the suffix, preserving linear scanning
    for protocol-command patterns while avoiding subset-state explosion.
    """
    flags_match = re.match(r'^(\(\?[A-Za-z-]+\))', pattern)
    flags = flags_match.group(1) if flags_match else ''
    body = pattern[len(flags):]
    marker_at = None
    marker = None
    depth = 0
    in_class = False
    escaped = False
    for index, char in enumerate(body):
        if escaped:
            escaped = False
            continue
        if char == '\\':
            escaped = True
            continue
        if char == '[' and not in_class:
            in_class = True
            continue
        if char == ']' and in_class:
            in_class = False
            continue
        if in_class:
            continue
        if char == '(':
            depth += 1
            continue
        if char == ')':
            depth = max(0, depth - 1)
            continue
        if depth == 0 and body.startswith('.*?', index):
            marker_at, marker = index, '.*?'
            break
        if depth == 0 and body.startswith('.*', index):
            marker_at, marker = index, '.*'
            break
    if marker_at is None:
        raise DfaUnsupportedRegex('no splittable wildcard gap')
    prefix_text = body[:marker_at]
    suffix_text = body[marker_at + len(marker):]
    if not prefix_text or not suffix_text:
        raise DfaUnsupportedRegex('wildcard gap lacks prefix or suffix')
    try:
        prefix_ast = reparser.parse(prefix_text)
    except Exception as exc:
        raise DfaUnsupportedRegex(f'invalid wildcard-gap prefix: {exc}') from exc
    prefix_bytes = []
    for node_type, value in prefix_ast:
        if getattr(node_type, 'name', str(node_type)) != 'LITERAL' or value > 255:
            raise DfaUnsupportedRegex('gap prefix is not a fixed byte string')
        prefix_bytes.append(value)
    if not prefix_bytes:
        raise DfaUnsupportedRegex('empty wildcard-gap prefix')

    suffix_pattern = flags + suffix_text
    helper = f"lumina_gap_{rule_id}_suffix"
    prefix = f"lumina_gap_dfa_{rule_id}"
    helper_code = emit_dfa_c(
        rule_id,
        suffix_pattern,
        state_budget=state_budget,
        table_budget=table_budget,
        function_name=helper,
        symbol_prefix=prefix,
        match_value=1,
        static_function=True,
    )
    first = first_bytes_of(suffix_pattern)
    words = [0, 0, 0, 0]
    for byte in first:
        words[byte >> 6] |= 1 << (byte & 63)
    prefix_literal = ', '.join(f'0x{byte:02x}' for byte in prefix_bytes)
    return helper_code + f"""
int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{
    static const unsigned char P[] = {{ {prefix_literal} }};
    static const uint64_t F[4] = {{ {', '.join(f'0x{word:016x}ULL' for word in words)} }};
    const size_t PLEN = sizeof(P);
    if (offset + PLEN > len) return 0;
    for (size_t i = 0; i < PLEN; i++) if (data[offset + i] != P[i]) return 0;
    for (size_t pos = offset + PLEN; pos < len; pos++) {{
        unsigned char byte = data[pos];
        if (!(F[byte >> 6] & (1ULL << (byte & 63)))) continue;
        if ({helper}(data, len, pos)) return {rule_id};
    }}
    return 0;
}}
"""


def emit_factored_branch_concat_dfa(rule_id, pattern, state_budget=8192,
                                    table_budget=2 * 1024 * 1024,
                                    total_table_budget=8 * 1024 * 1024):
    """Factor `prefix + large branch + optional suffix` into native DFAs.

    A monolithic subset construction forms the Cartesian product of the prefix
    and branch languages. This backend keeps one deterministic prefix walker
    and several deterministic branch shards. Every accepted prefix endpoint is
    passed directly to the shard dispatcher, preserving concatenation semantics
    without a runtime regex parser or NFA interpreter.
    """
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if len(ast.data) < 3:
        raise DfaUnsupportedRegex('factored concat requires at least three root tokens')

    def table_bytes(dfa):
        transition_width = 2 if dfa['state_count'] <= 65535 else 4
        return (dfa['state_count'] * dfa['symbol_count'] * transition_width +
                dfa['state_count'] * dfa['symbol_count'] +
                dfa['state_count'] * 4)

    selected = None
    for split in range(len(ast.data) - 1, 0, -1):
        op, value = ast.data[split]
        if getattr(op, 'name', str(op)) != 'BRANCH':
            continue
        branches = value[1]
        if not (2 <= len(branches) <= 32):
            continue
        left_ast = type(ast)(ast.state, data=list(ast.data[:split]))
        trailing = list(ast.data[split + 1:])
        try:
            left_dfa = compile_dfa_ast(
                left_ast, ignore_case, dot_all, state_budget=state_budget)
            left_bytes = table_bytes(left_dfa)
            if left_bytes > table_budget:
                continue
            shards = []
            total_bytes = left_bytes
            for branch in branches:
                shard_ast = type(ast)(ast.state, data=list(branch) + trailing)
                shard_dfa = compile_dfa_ast(
                    shard_ast, ignore_case, dot_all, state_budget=state_budget)
                shard_bytes = table_bytes(shard_dfa)
                if shard_bytes > table_budget:
                    raise DfaUnsupportedRegex('factored branch shard exceeds table budget')
                total_bytes += shard_bytes
                shards.append((shard_ast, shard_dfa))
            if total_bytes > total_table_budget:
                continue
            selected = left_ast, left_dfa, shards
            break
        except DfaUnsupportedRegex:
            continue
    if selected is None:
        raise DfaUnsupportedRegex('no bounded root branch factorization')

    left_ast, left_dfa, shards = selected
    dispatcher = f'lumina_factored_{rule_id}_suffix'
    parts = []
    calls = []
    for shard_index, (shard_ast, shard_dfa) in enumerate(shards):
        helper = f'lumina_factored_{rule_id}_shard_{shard_index}'
        parts.append(emit_dfa_c(
            rule_id, None,
            state_budget=state_budget, table_budget=table_budget,
            function_name=helper,
            symbol_prefix=f'lumina_factored_{rule_id}_shard_dfa_{shard_index}',
            match_value=1, static_function=True,
            ast=shard_ast, ast_ignore_case=ignore_case, ast_dot_all=dot_all,
            compiled_dfa=shard_dfa,
        ))
        calls.append(f'    if ({helper}(data, len, offset)) return 1;')
    parts.append(
        f"static int {dispatcher}(const unsigned char *data, size_t len, size_t offset) {{\n" +
        "\n".join(calls) +
        "\n    return 0;\n}\n"
    )
    parts.append(emit_dfa_c(
        rule_id, None,
        state_budget=state_budget, table_budget=table_budget,
        function_name=f'lumina_scan_rule_{rule_id}',
        symbol_prefix=f'lumina_factored_{rule_id}_prefix_dfa',
        match_value=rule_id,
        ast=left_ast, ast_ignore_case=ignore_case, ast_dot_all=dot_all,
        compiled_dfa=left_dfa, accept_delegate=dispatcher,
    ))
    return '\n'.join(parts)


def emit_recursive_factored_concat_dfa(rule_id, pattern, state_budget=8192,
                                       table_budget=2 * 1024 * 1024,
                                       total_table_budget=8 * 1024 * 1024,
                                       function_name=None, symbol_prefix=None,
                                       match_value=None, static_function=False):
    """Emit a shared continuation DAG for multiple root branch points.

    Each branch shard delegates accepted endpoints to one shared trailing
    matcher. This preserves regular-language concatenation while avoiding the
    Cartesian state product and repeated trailing tables produced by a
    monolithic DFA or by cloning the suffix for every alternative.
    """
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    code = []
    counter = 0
    total_bytes = 0
    prefix = symbol_prefix or f'lumina_recursive_{rule_id}'
    success = f'{prefix}_success'
    public_name = function_name or f'lumina_scan_rule_{rule_id}'
    result_value = rule_id if match_value is None else match_value
    storage = 'static ' if static_function else ''

    def add_case_variants(values):
        expanded = set(values)
        if ignore_case:
            for byte in tuple(expanded):
                if 0x41 <= byte <= 0x5a or 0x61 <= byte <= 0x7a:
                    expanded.add(byte ^ 0x20)
        return {byte & 0xff for byte in expanded}

    def fixed_prefix_sets(nodes, limit=4):
        """Return conservative byte sets for a fixed-width leading prefix."""
        result = []
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            if name == 'AT':
                continue
            if name == 'LITERAL':
                values = add_case_variants({value})
            elif name == 'NOT_LITERAL':
                excluded = add_case_variants({value})
                values = set(range(256)) - excluded
            elif name == 'IN':
                words = build_bitmask_for_in(value, ignore_case)
                values = {
                    byte for byte in range(256)
                    if (words[byte // 64] >> (byte % 64)) & 1
                }
            elif name == 'ANY':
                # Over-including newline is safe for a routing predicate.
                values = set(range(256))
            else:
                break
            result.append(values)
            if len(result) >= limit:
                break
        return result

    candidate_sets = fixed_prefix_sets(ast.data)
    if not candidate_sets:
        candidate_sets = [set(first_bytes_of(pattern))]
    candidate_masks = []
    for values in candidate_sets:
        words = [0, 0, 0, 0]
        for byte in values:
            words[byte >> 6] |= 1 << (byte & 63)
        candidate_masks.append(words)

    code.append(
        f"static int {success}(const unsigned char *data, size_t len, size_t offset) {{\n"
        f"    (void)data; (void)len; (void)offset; return 1;\n"
        f"}}\n"
    )

    def table_bytes(dfa):
        transition_width = 2 if dfa['state_count'] <= 65535 else 4
        return (dfa['state_count'] * dfa['symbol_count'] * transition_width +
                dfa['state_count'] * dfa['symbol_count'] +
                dfa['state_count'] * 4)

    def next_name(kind):
        nonlocal counter
        name = f'{prefix}_{kind}_{counter}'
        counter += 1
        return name

    def build(nodes, continuation):
        nonlocal total_bytes
        nodes = list(nodes)
        if not nodes:
            return continuation
        split = next((index for index, (op, _) in enumerate(nodes)
                      if getattr(op, 'name', str(op)) == 'BRANCH'), None)
        if split is not None:
            _, branch_value = nodes[split]
            branches = branch_value[1]
            if not (2 <= len(branches) <= 64):
                raise DfaUnsupportedRegex('recursive branch fanout exceeds limit')
            trailing = build(nodes[split + 1:], continuation)
            entries = [build(branch, trailing) for branch in branches]
            dispatcher = next_name('dispatch')
            calls = ''.join(
                f"    if ({entry}(data, len, offset)) return 1;\n"
                for entry in entries
            )
            code.append(
                f"static int {dispatcher}(const unsigned char *data, size_t len, size_t offset) {{\n"
                + calls +
                f"    return 0;\n"
                f"}}\n"
            )
            return build(nodes[:split], dispatcher)

        fragment_ast = type(ast)(ast.state, data=nodes)
        fragment_dfa = compile_dfa_ast(
            fragment_ast, ignore_case, dot_all, state_budget=state_budget)
        fragment_bytes = table_bytes(fragment_dfa)
        if fragment_bytes > table_budget:
            raise DfaUnsupportedRegex('recursive fragment table budget exceeded')
        total_bytes += fragment_bytes
        if total_bytes > total_table_budget:
            raise DfaUnsupportedRegex('recursive total table budget exceeded')
        helper = next_name('fragment')
        code.append(emit_dfa_c(
            rule_id, None,
            state_budget=state_budget,
            table_budget=table_budget,
            function_name=helper,
            symbol_prefix=f'{helper}_dfa',
            match_value=1,
            static_function=True,
            ast=fragment_ast,
            ast_ignore_case=ignore_case,
            ast_dot_all=dot_all,
            compiled_dfa=fragment_dfa,
            accept_delegate=continuation,
        ))
        return helper

    entry = build(ast.data, success)
    mask_rows = ',\n'.join(
        '    {' + ', '.join(f'0x{word:016x}ULL' for word in words) + '}'
        for words in candidate_masks
    )
    candidate_mask = f'{prefix}_candidate_mask'
    code.append(
        f"static const uint64_t {candidate_mask}[{len(candidate_masks)}][4] = {{\n"
        f"{mask_rows}\n"
        f"}};\n"
    )
    checks = ''.join(
        f"        if (!({candidate_mask}[{index}][data[candidate + {index}] >> 6] & "
        f"(1ULL << (data[candidate + {index}] & 63)))) continue;\n"
        for index in range(len(candidate_masks))
    )
    code.append(
        f"{storage}int {public_name}(const unsigned char *data, size_t len, size_t offset) {{\n"
        f"    const size_t prefix_len = {len(candidate_masks)};\n"
        f"    if (offset > len || prefix_len > len - offset) return 0;\n"
        f"    for (size_t candidate = offset; candidate + prefix_len <= len; ++candidate) {{\n"
        f"{checks}"
        f"        if ({entry}(data, len, candidate)) return {result_value};\n"
        f"    }}\n"
        f"    return 0;\n"
        f"}}\n"
    )
    return '\n'.join(code)


def emit_top_level_alternative_dfa_router(rule_id, pattern, state_budget=8192,
                                          table_budget=2 * 1024 * 1024,
                                          total_table_budget=8 * 1024 * 1024):
    """Lower one large root alternation into candidate-routed exact DFA shards.

    A root alternation has no shared continuation, so recursively materializing
    every internal branch creates a large call forest. Independent DFA shards
    preserve the exact language while a first-byte route and short fixed-prefix
    guards keep unrelated shards off the hot path.
    """
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if len(ast.data) != 1:
        raise DfaUnsupportedRegex('alternative router requires one root node')
    root_op, root_value = ast.data[0]
    if getattr(root_op, 'name', str(root_op)) != 'BRANCH':
        raise DfaUnsupportedRegex('alternative router requires a root branch')
    branches = root_value[1]
    if not (4 <= len(branches) <= 64):
        raise DfaUnsupportedRegex('alternative router branch fanout outside limits')

    def add_case_variants(values):
        expanded = {byte & 0xff for byte in values}
        if ignore_case:
            for byte in tuple(expanded):
                if 0x41 <= byte <= 0x5a or 0x61 <= byte <= 0x7a:
                    expanded.add(byte ^ 0x20)
        return expanded

    def consuming_values(op, value):
        name = getattr(op, 'name', str(op))
        if name == 'LITERAL':
            return add_case_variants({value})
        if name == 'NOT_LITERAL':
            return set(range(256)) - add_case_variants({value})
        if name == 'IN':
            words = build_bitmask_for_in(value, ignore_case)
            return {
                byte for byte in range(256)
                if words[byte >> 6] & (1 << (byte & 63))
            }
        if name == 'ANY':
            # Newline over-inclusion is safe for a routing predicate.
            return set(range(256))
        return None

    def first_bytes_and_nullable(nodes):
        result = set()
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            direct = consuming_values(op, value)
            if direct is not None:
                result.update(direct)
                return result, False, True
            if name == 'AT':
                continue
            if name == 'SUBPATTERN':
                values, nullable, exact = first_bytes_and_nullable(value[-1])
            elif name == 'BRANCH':
                values = set()
                nullable = False
                exact = True
                for branch in value[1]:
                    branch_values, branch_nullable, branch_exact = (
                        first_bytes_and_nullable(branch))
                    values.update(branch_values)
                    nullable = nullable or branch_nullable
                    exact = exact and branch_exact
            elif name in ('MAX_REPEAT', 'MIN_REPEAT', 'POSSESSIVE_REPEAT'):
                minimum, _, child = value
                values, child_nullable, exact = first_bytes_and_nullable(child)
                nullable = minimum == 0 or child_nullable
            else:
                return set(range(256)), True, False
            result.update(values)
            if not exact:
                return set(range(256)), True, False
            if nullable:
                continue
            return result, False, True
        return result, True, True

    def fixed_prefix_sets(nodes, limit=4):
        result = []
        for op, value in nodes:
            name = getattr(op, 'name', str(op))
            if name == 'AT':
                continue
            values = consuming_values(op, value)
            if values is None:
                break
            result.append(values)
            if len(result) >= limit:
                break
        return result

    def conservative_table_bytes(dfa):
        transition_width = 2 if dfa['state_count'] <= 65535 else 4
        return (dfa['state_count'] * dfa['symbol_count'] * transition_width +
                dfa['state_count'] * dfa['symbol_count'] +
                dfa['state_count'] * 4)

    plans = []
    total_bytes = 0
    for branch_index, branch in enumerate(branches):
        first_bytes, nullable, exact = first_bytes_and_nullable(branch)
        if not exact or nullable or not first_bytes:
            raise DfaUnsupportedRegex(
                'alternative router requires exact non-empty branch starts')
        branch_ast = type(ast)(ast.state, data=list(branch))
        dfa = compile_dfa_ast(
            branch_ast, ignore_case, dot_all, state_budget=state_budget)
        branch_bytes = conservative_table_bytes(dfa)
        if branch_bytes > table_budget:
            raise DfaUnsupportedRegex('alternative router shard exceeds table budget')
        total_bytes += branch_bytes
        if total_bytes > total_table_budget:
            raise DfaUnsupportedRegex('alternative router total table budget exceeded')
        prefix_sets = fixed_prefix_sets(branch)
        if not prefix_sets:
            prefix_sets = [first_bytes]
        plans.append((branch_index, branch_ast, dfa, first_bytes, prefix_sets))

    prefix = f'lumina_alt_{rule_id}'
    code = []
    route = [0] * 256
    for branch_index, _, _, first_bytes, _ in plans:
        for byte in first_bytes:
            route[byte] |= 1 << branch_index

    for branch_index, branch_ast, dfa, _, _ in plans:
        code.append(emit_dfa_c(
            rule_id, None,
            state_budget=state_budget,
            table_budget=table_budget,
            function_name=f'{prefix}_shard_{branch_index}',
            symbol_prefix=f'{prefix}_dfa_{branch_index}',
            match_value=1,
            static_function=True,
            ast=branch_ast,
            ast_ignore_case=ignore_case,
            ast_dot_all=dot_all,
            compiled_dfa=dfa,
            intern_transition_rows=True,
            intern_accept_rows=True,
        ))

    route_type = 'uint16_t' if len(branches) <= 16 else (
        'uint32_t' if len(branches) <= 32 else 'uint64_t')
    route_suffix = 'u' if len(branches) <= 32 else 'ULL'
    route_rows = '\n'.join(
        '    ' + ','.join(
            f'0x{value:x}{route_suffix}' for value in route[index:index + 16]) + ','
        for index in range(0, 256, 16)
    )
    code.append(
        f'static const {route_type} {prefix}_route[256] = {{\n'
        f'{route_rows}\n'
        f'}};\n'
    )

    cases = []
    for branch_index, _, _, _, prefix_sets in plans:
        guards = []
        usable_prefix = 1
        for position, values in enumerate(prefix_sets[1:], start=1):
            if len(values) > 8:
                break
            comparisons = ' || '.join(
                f'data[candidate + {position}] == 0x{byte:02x}u'
                for byte in sorted(values)
            )
            guards.append(f'({comparisons})')
            usable_prefix = position + 1
        condition = ''
        if guards:
            condition = (
                f'candidate + {usable_prefix}u <= len && ' +
                ' && '.join(guards) + ' && ')
        cases.append(
            f'            case {branch_index}u:\n'
            f'                if ({condition}{prefix}_shard_{branch_index}('
            f'data, len, candidate)) return {rule_id};\n'
            f'                break;'
        )

    code.append(
        f'int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n'
        f'    if (offset >= len) return 0;\n'
        f'    for (size_t candidate = offset; candidate < len; ++candidate) {{\n'
        f'        {route_type} pending = {prefix}_route[data[candidate]];\n'
        f'        while (pending) {{\n'
        f'            unsigned shard = (unsigned)__builtin_ctzll((unsigned long long)pending);\n'
        f'            pending &= pending - 1u;\n'
        f'            switch (shard) {{\n' +
        '\n'.join(cases) +
        f'\n            default: break;\n'
        f'            }}\n'
        f'        }}\n'
        f'    }}\n'
        f'    return 0;\n'
        f'}}\n'
    )
    return '\n'.join(code)


def finite_literal_language(nodes, expansion_cap=100000, repeat_cap=8):
    """Expand a finite regular-language fragment into exact byte strings.

    This helper is deliberately strict. Any unbounded repeat, assertion,
    category or other construct that cannot be represented as a finite literal
    dictionary rejects the specialized lowering and leaves the rule on an
    exact DFA/NFA backend.
    """
    language = [b'']
    for op, value in nodes:
        name = getattr(op, 'name', str(op))
        if name == 'LITERAL':
            alternatives = [bytes((value & 0xff,))]
        elif name == 'SUBPATTERN':
            alternatives = finite_literal_language(
                value[-1], expansion_cap=expansion_cap, repeat_cap=repeat_cap)
        elif name == 'BRANCH':
            alternatives = []
            for branch in value[1]:
                alternatives.extend(finite_literal_language(
                    branch, expansion_cap=expansion_cap, repeat_cap=repeat_cap))
                if len(alternatives) > expansion_cap:
                    raise DfaUnsupportedRegex('finite language expansion cap exceeded')
        elif name in ('MAX_REPEAT', 'MIN_REPEAT'):
            minimum, maximum, child = value
            if maximum > repeat_cap:
                raise DfaUnsupportedRegex('finite language contains an unbounded repeat')
            unit = finite_literal_language(
                child, expansion_cap=expansion_cap, repeat_cap=repeat_cap)
            alternatives = []
            for count in range(minimum, maximum + 1):
                repeated = [b'']
                for _ in range(count):
                    repeated = [left + right for left in repeated for right in unit]
                    if len(repeated) > expansion_cap:
                        raise DfaUnsupportedRegex('finite repeat expansion cap exceeded')
                alternatives.extend(repeated)
        elif name == 'IN':
            alternatives = []
            for item_op, item_value in value:
                item_name = getattr(item_op, 'name', str(item_op))
                if item_name == 'LITERAL':
                    alternatives.append(bytes((item_value & 0xff,)))
                elif item_name == 'RANGE':
                    alternatives.extend(
                        bytes((byte,)) for byte in range(item_value[0], item_value[1] + 1))
                else:
                    raise DfaUnsupportedRegex(
                        f'finite language does not support character-set item {item_name}')
        else:
            raise DfaUnsupportedRegex(
                f'finite language does not support regex node {name}')

        language = [left + right for left in language for right in alternatives]
        if len(language) > expansion_cap:
            raise DfaUnsupportedRegex('finite language expansion cap exceeded')
    return language


def finite_mask_language(nodes, ignore_case, dot_all=False,
                         expansion_cap=100000, repeat_cap=8):
    """Expand a finite fixed-width language into exact per-byte masks."""
    assertion_tokens = {
        'AT_BOUNDARY': -1,
        'AT_NON_BOUNDARY': -2,
        'AT_BEGINNING': -3,
        'AT_BEGINNING_STRING': -3,
        'AT_END': -4,
        'AT_END_STRING': -4,
    }
    language = [()]

    def normalize_mask(mask):
        if ignore_case:
            for upper in range(ord('A'), ord('Z') + 1):
                lower = upper | 0x20
                if mask & ((1 << upper) | (1 << lower)):
                    mask |= 1 << lower
                mask &= ~(1 << upper)
        return mask & ((1 << 256) - 1)

    for op, value in nodes:
        name = getattr(op, 'name', str(op))
        if name == 'LITERAL':
            mask = 1 << (value & 0xff)
            if ignore_case and (
                    ord('A') <= value <= ord('Z') or
                    ord('a') <= value <= ord('z')):
                mask |= 1 << (value ^ 0x20)
            alternatives = [(normalize_mask(mask),)]
        elif name == 'NOT_LITERAL':
            excluded = 1 << (value & 0xff)
            if ignore_case and (
                    ord('A') <= value <= ord('Z') or
                    ord('a') <= value <= ord('z')):
                excluded |= 1 << (value ^ 0x20)
            alternatives = [(normalize_mask(((1 << 256) - 1) ^ excluded),)]
        elif name == 'ANY':
            mask = (1 << 256) - 1
            if not dot_all:
                mask &= ~(1 << ord('\n'))
            alternatives = [(normalize_mask(mask),)]
        elif name == 'IN':
            words = build_bitmask_for_in(value, ignore_case)
            mask = sum(word << (word_index * 64)
                       for word_index, word in enumerate(words))
            alternatives = [(normalize_mask(mask),)]
        elif name == 'AT':
            assertion = assertion_tokens.get(getattr(value, 'name', str(value)))
            if assertion is None:
                raise DfaUnsupportedRegex(
                    f'finite mask language does not support assertion {value}')
            alternatives = [(assertion,)]
        elif name == 'SUBPATTERN':
            alternatives = finite_mask_language(
                value[-1], ignore_case, dot_all,
                expansion_cap=expansion_cap, repeat_cap=repeat_cap)
        elif name == 'BRANCH':
            alternatives = []
            for branch in value[1]:
                alternatives.extend(finite_mask_language(
                    branch, ignore_case, dot_all,
                    expansion_cap=expansion_cap, repeat_cap=repeat_cap))
                if len(alternatives) > expansion_cap:
                    raise DfaUnsupportedRegex('finite mask language expansion cap exceeded')
        elif name in ('MAX_REPEAT', 'MIN_REPEAT'):
            minimum, maximum, child = value
            if maximum > repeat_cap:
                raise DfaUnsupportedRegex(
                    'finite mask language contains an unbounded repeat')
            unit = finite_mask_language(
                child, ignore_case, dot_all,
                expansion_cap=expansion_cap, repeat_cap=repeat_cap)
            alternatives = []
            for count in range(minimum, maximum + 1):
                repeated = [()]
                for _ in range(count):
                    repeated = [left + right for left in repeated for right in unit]
                    if len(repeated) > expansion_cap:
                        raise DfaUnsupportedRegex(
                            'finite mask repeat expansion cap exceeded')
                alternatives.extend(repeated)
        else:
            raise DfaUnsupportedRegex(
                f'finite mask language does not support regex node {name}')

        language = [left + right for left in language for right in alternatives]
        if len(language) > expansion_cap:
            raise DfaUnsupportedRegex('finite mask language expansion cap exceeded')
    return language


def scheme_host_classifier_plan(pattern, expansion_cap=4096):
    """Recognize `finite-scheme : /? /? host-alternation` grammars."""
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if not ignore_case or len(ast.data) != 5:
        return None
    names = [getattr(op, 'name', str(op)) for op, _ in ast.data]
    if names != ['BRANCH', 'LITERAL', 'MAX_REPEAT', 'MAX_REPEAT', 'BRANCH']:
        return None
    if ast.data[1][1] != ord(':'):
        return None

    def optional_slash(node):
        _, value = node
        return (int(value[0]) == 0 and int(value[1]) == 1 and
                len(value[2]) == 1 and
                getattr(value[2][0][0], 'name', str(value[2][0][0])) == 'LITERAL' and
                value[2][0][1] == ord('/'))

    if not optional_slash(ast.data[2]) or not optional_slash(ast.data[3]):
        return None
    host_branches = ast.data[4][1][1]
    if not (2 <= len(host_branches) <= 16):
        return None
    if any(_ast_uses_capture(branch) for branch in host_branches):
        return None
    try:
        schemes = finite_mask_language(
            [ast.data[0]], ignore_case, dot_all,
            expansion_cap=expansion_cap, repeat_cap=16)
    except DfaUnsupportedRegex:
        return None
    schemes = tuple(sorted(set(schemes)))
    if not (16 <= len(schemes) <= 65535):
        return None
    for sequence in schemes:
        if not sequence or any(token < 0 for token in sequence):
            return None
        first = sequence[0]
        if first == 0 or first & (first - 1):
            return None
    host_first_bytes = []
    for branch in host_branches:
        first = _ast_first_byte_set(branch, ignore_case)
        if not first or len(first) > 128:
            return None
        host_first_bytes.append(tuple(sorted(first)))
    return {
        'schemes': schemes,
        'host_branches': tuple(tuple(branch) for branch in host_branches),
        'host_first_bytes': tuple(host_first_bytes),
        'ignore_case': ignore_case,
        'dot_all': dot_all,
        'ast_type': type(ast),
        'ast_state': ast.state,
    }


def emit_scheme_host_classifier(rule_id, plan):
    """Emit a compact finite-scheme router with exact procedural host shards."""
    schemes = plan['schemes']
    mask_ids = {}
    class_masks = []
    token_stream = []
    offsets = []
    lengths = []
    first_buckets = [[] for _ in range(256)]
    for pattern_index, sequence in enumerate(schemes):
        offsets.append(len(token_stream))
        lengths.append(len(sequence))
        first = sequence[0].bit_length() - 1
        first_buckets[first].append(pattern_index)
        for mask in sequence:
            if mask and not (mask & (mask - 1)):
                token_stream.append(mask.bit_length() - 1)
                continue
            class_id = mask_ids.get(mask)
            if class_id is None:
                class_id = len(class_masks)
                mask_ids[mask] = class_id
                class_masks.append(mask)
            token_stream.append(256 + class_id)
    if len(token_stream) > 65535 or max(lengths) > 255:
        raise DfaUnsupportedRegex('scheme classifier token budget exceeded')

    bucket_first = [0]
    bucket_patterns = []
    for bucket in first_buckets:
        bucket_patterns.extend(bucket)
        bucket_first.append(len(bucket_patterns))

    prefix = f'lumina_scheme_host_{rule_id}'

    def emit_array(ctype, name, values, width, formatter=str):
        rows = []
        for start in range(0, len(values), width):
            rows.append('    ' + ', '.join(
                formatter(value) for value in values[start:start + width]) + ',')
        return (f'static const {ctype} {name}[{len(values)}] = {{\n' +
                '\n'.join(rows) + '\n};\n')

    class_words = []
    for mask in class_masks:
        class_words.extend((mask >> (word * 64)) & ((1 << 64) - 1)
                           for word in range(4))
    code = [
        emit_array('uint16_t', f'{prefix}_bucket_first', bucket_first, 16),
        emit_array('uint16_t', f'{prefix}_bucket_pattern', bucket_patterns, 16),
        emit_array('uint16_t', f'{prefix}_offset', offsets, 16),
        emit_array('uint8_t', f'{prefix}_length', lengths, 24),
        emit_array('uint16_t', f'{prefix}_token', token_stream, 16),
        emit_array('uint64_t', f'{prefix}_class', class_words, 4,
                   lambda value: f'0x{value:016x}ULL'),
    ]
    code.append(f"""
static inline unsigned char {prefix}_lower(unsigned char byte) {{
    return (byte >= 'A' && byte <= 'Z') ? (unsigned char)(byte | 0x20u) : byte;
}}
""")

    host_route = [0] * 256
    for shard, first_bytes in enumerate(plan['host_first_bytes']):
        for byte in first_bytes:
            host_route[byte] |= 1 << shard
        branch_ast = plan['ast_type'](
            plan['ast_state'], data=list(plan['host_branches'][shard]))
        body = '\n'.join(compile_ast(branch_ast, plan['ignore_case']))
        code.append(
            f"static int {prefix}_host_{shard}(const unsigned char *data, "
            f"size_t len, size_t offset) {{\n"
            f"    size_t cur = offset; bool match = true;\n"
            f"{body}\n"
            f"    return match ? 1 : 0;\n"
            f"}}\n"
        )
    code.append(emit_array(
        'uint16_t', f'{prefix}_host_route', host_route, 16,
        lambda value: f'0x{value:04x}u'))

    host_cases = '\n'.join(
        f"            case {shard}u:\n"
        f"                if ({prefix}_host_{shard}(data, len, offset)) return 1;\n"
        f"                break;"
        for shard in range(len(plan['host_branches']))
    )
    code.append(f"""
static int {prefix}_host(const unsigned char *data, size_t len, size_t offset) {{
    if (offset >= len) return 0;
    uint16_t pending = {prefix}_host_route[data[offset]];
    while (pending) {{
        unsigned shard = (unsigned)__builtin_ctz((unsigned)pending);
        pending &= (uint16_t)(pending - 1u);
        switch (shard) {{
{host_cases}
            default: break;
        }}
    }}
    return 0;
}}
""")

    code.append(f"""
int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{
    if (offset >= len) return 0;
    unsigned char first = {prefix}_lower(data[offset]);
    uint16_t begin = {prefix}_bucket_first[first];
    uint16_t end = {prefix}_bucket_first[(uint16_t)first + 1u];
    for (uint16_t slot = begin; slot < end; ++slot) {{
        uint16_t pattern = {prefix}_bucket_pattern[slot];
        uint8_t length = {prefix}_length[pattern];
        if ((size_t)length + 1u > len - offset) continue;
        uint16_t token_offset = {prefix}_offset[pattern];
        size_t pos = offset;
        uint8_t token_index = 0;
        for (; token_index < length; ++token_index, ++pos) {{
            uint16_t token = {prefix}_token[token_offset + token_index];
            unsigned char byte = {prefix}_lower(data[pos]);
            if (token < 256u) {{
                if (byte != token) break;
            }} else {{
                uint16_t class_id = (uint16_t)(token - 256u);
                if (!({prefix}_class[class_id * 4u + (byte >> 6)] &
                      (1ULL << (byte & 63)))) break;
            }}
        }}
        if (token_index != length || data[pos++] != ':') continue;
        if (pos < len && data[pos] == '/') ++pos;
        if (pos < len && data[pos] == '/') ++pos;
        if ({prefix}_host(data, len, pos)) return {rule_id};
    }}
    return 0;
}}
""")
    return '\n'.join(code)


def fixed_mask_dictionary_plan(pattern, expansion_cap=100000):
    """Recognize a large fixed-width mask dictionary plus typed continuation."""
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if not ignore_case or len(ast.data) != 5:
        return None
    names = [getattr(op, 'name', str(op)) for op, _ in ast.data]
    if names != ['AT', 'BRANCH', 'MAX_REPEAT', 'LITERAL', 'NOT_LITERAL']:
        return None
    if getattr(ast.data[0][1], 'name', str(ast.data[0][1])) != 'AT_BOUNDARY':
        return None
    if not _is_ascii_whitespace_repeat(ast.data[2]):
        return None
    if ast.data[3][1] != ord('=') or ast.data[4][1] != ord('='):
        return None
    try:
        patterns = finite_mask_language(
            [ast.data[1]], ignore_case, dot_all,
            expansion_cap=expansion_cap)
    except DfaUnsupportedRegex:
        return None
    patterns = tuple(sorted(set(patterns)))
    if len(patterns) < 256:
        return None
    for sequence in patterns:
        if not sequence:
            return None
        first = sequence[0]
        if first == 0 or first & (first - 1):
            return None
        byte = first.bit_length() - 1
        if not (ord('a') <= byte <= ord('z') or
                ord('0') <= byte <= ord('9') or byte == ord('_')):
            return None
    return {
        'patterns': patterns,
        'continuation': 'ASSIGN_NON_EQ',
        'start_boundary': True,
    }


def fixed_mask_suffix_prefilter_plan(pattern, expansion_cap=100000):
    """Extract a large exact finite suffix language as a sound prefilter."""
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if not ignore_case or len(ast.data) < 2:
        return None
    last_name = getattr(ast.data[-1][0], 'name', str(ast.data[-1][0]))
    if last_name != 'BRANCH':
        return None
    try:
        patterns = finite_mask_language(
            [ast.data[-1]], ignore_case, dot_all,
            expansion_cap=expansion_cap, repeat_cap=10)
    except DfaUnsupportedRegex:
        return None
    patterns = tuple(sorted(set(patterns)))
    if len(patterns) < 256:
        return None
    for sequence in patterns:
        first_consuming = next(
            (token for token in sequence if token >= 0), None)
        if first_consuming is None or first_consuming == 0 or (
                first_consuming & (first_consuming - 1)):
            return None
        byte = first_consuming.bit_length() - 1
        if not (ord('a') <= byte <= ord('z') or
                ord('0') <= byte <= ord('9') or byte == ord('_')):
            return None
        # Candidate routing assumes assertions do not precede the first byte.
        if sequence[0] < 0:
            return None
    return {
        'patterns': patterns,
        'continuation': 'MATCH',
        'start_boundary': False,
    }


def compact_prefix_fixed_suffix_plan(
        pattern, suffix_plan, state_budget=8192,
        table_budget=2 * 1024 * 1024, minimum_row_savings=2.0):
    """Select a row-interned prefix DFA when its measured table shape is compact."""
    if suffix_plan is None:
        return None
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if len(ast.data) < 2:
        return None
    prefix_ast = type(ast)(ast.state, data=list(ast.data[:-1]))
    try:
        prefix_dfa = compile_dfa_ast(
            prefix_ast, ignore_case, dot_all, state_budget=state_budget)
    except DfaUnsupportedRegex:
        return None

    states = prefix_dfa['state_count']
    symbols = prefix_dfa['symbol_count']
    transition_width = 2 if states <= 65535 else 4
    unique_transitions = len({
        tuple(row) for row in prefix_dfa['transitions']})
    unique_accepts = len({
        tuple(row) for row in prefix_dfa['accepts']})
    unique_eof = len({
        tuple(row) for row in prefix_dfa['eof_accept']})
    transition_index_width = 2 if unique_transitions <= 65535 else 4
    accept_index_width = 1 if unique_accepts <= 255 else 2
    eof_index_width = 1 if unique_eof <= 255 else 2
    raw_bytes = states * symbols * (transition_width + 1) + states * 4
    compact_bytes = (
        unique_transitions * symbols * transition_width +
        states * transition_index_width +
        unique_accepts * symbols +
        states * accept_index_width +
        unique_eof * 4 +
        states * eof_index_width)
    if compact_bytes > table_budget:
        return None
    if raw_bytes < compact_bytes * minimum_row_savings:
        return None

    plan = dict(suffix_plan)
    plan.update({
        'prefix_ast': prefix_ast,
        'prefix_dfa': prefix_dfa,
        'ignore_case': ignore_case,
        'dot_all': dot_all,
        'raw_table_bytes': raw_bytes,
        'compact_table_bytes': compact_bytes,
        'unique_transition_rows': unique_transitions,
        'unique_accept_rows': unique_accepts,
        'unique_eof_rows': unique_eof,
    })
    return plan


def emit_fixed_mask_dictionary(rule_id, plan, function_name=None,
                               symbol_prefix=None, match_value=None,
                               static_function=False, anchored=False):
    """Emit a first-byte bucketed exact verifier for fixed-width mask words."""
    patterns = plan['patterns']
    if len(patterns) > 65535:
        raise DfaUnsupportedRegex('fixed mask dictionary pattern budget exceeded')

    mask_ids = {}
    class_masks = []
    token_stream = []
    offsets = []
    lengths = []
    consume_lengths = []
    first_buckets = [[] for _ in range(256)]
    assertion_codes = {
        -1: 65535,
        -2: 65534,
        -3: 65533,
        -4: 65532,
    }
    for pattern_index, sequence in enumerate(patterns):
        offsets.append(len(token_stream))
        lengths.append(len(sequence))
        consume_lengths.append(sum(token >= 0 for token in sequence))
        first_mask = next(token for token in sequence if token >= 0)
        first_byte = first_mask.bit_length() - 1
        first_buckets[first_byte].append(pattern_index)
        for mask in sequence:
            if mask < 0:
                token_stream.append(assertion_codes[mask])
                continue
            if mask and not (mask & (mask - 1)):
                token_stream.append(mask.bit_length() - 1)
                continue
            class_id = mask_ids.get(mask)
            if class_id is None:
                class_id = len(class_masks)
                mask_ids[mask] = class_id
                class_masks.append(mask)
            token_stream.append(256 + class_id)
    if len(token_stream) > 65535 or max(lengths, default=0) > 65535:
        raise DfaUnsupportedRegex('fixed mask dictionary token budget exceeded')

    bucket_first = [0]
    bucket_patterns = []
    for bucket in first_buckets:
        bucket_patterns.extend(bucket)
        bucket_first.append(len(bucket_patterns))

    prefix = symbol_prefix or f'lumina_fixed_mask_dictionary_{rule_id}'
    public_name = function_name or f'lumina_scan_rule_{rule_id}'
    result_value = rule_id if match_value is None else match_value
    storage = 'static ' if static_function else ''
    candidate_limit = 'offset + 1u' if anchored else 'len'
    boundary_check = (
        f"        if (candidate > 0 && {prefix}_word(data[candidate - 1])) continue;\n"
        if plan.get('start_boundary') else '')

    def emit_array(ctype, name, values, width, formatter=str):
        rows = []
        for start in range(0, len(values), width):
            rows.append(
                '    ' + ', '.join(
                    formatter(value) for value in values[start:start + width]) + ',')
        return (
            f'static const {ctype} {name}[{len(values)}] = {{\n' +
            '\n'.join(rows) + '\n};\n')

    class_words = []
    for mask in class_masks:
        class_words.extend((mask >> (word * 64)) & ((1 << 64) - 1)
                           for word in range(4))
    code = [
        emit_array('uint16_t', f'{prefix}_bucket_first', bucket_first, 16),
        emit_array('uint16_t', f'{prefix}_bucket_pattern', bucket_patterns, 16),
        emit_array('uint16_t', f'{prefix}_offset', offsets, 16),
        emit_array('uint16_t', f'{prefix}_length', lengths, 16),
        emit_array('uint16_t', f'{prefix}_consume_length', consume_lengths, 16),
        emit_array('uint16_t', f'{prefix}_token', token_stream, 16),
        emit_array('uint64_t', f'{prefix}_class', class_words, 4,
                   lambda value: f'0x{value:016x}ULL'),
    ]
    code.append(f"""
static inline unsigned char {prefix}_lower(unsigned char byte) {{
    return (byte >= 'A' && byte <= 'Z') ? (unsigned char)(byte | 0x20u) : byte;
}}

static inline int {prefix}_word(unsigned char byte) {{
    byte = {prefix}_lower(byte);
    return (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') || byte == '_';
}}

{storage}int {public_name}(const unsigned char *data, size_t len, size_t offset) {{
    if (offset >= len) return 0;
    for (size_t candidate = offset; candidate < {candidate_limit}; ++candidate) {{
        unsigned char first = {prefix}_lower(data[candidate]);
{boundary_check}
        uint16_t begin = {prefix}_bucket_first[first];
        uint16_t end = {prefix}_bucket_first[(uint16_t)first + 1u];
        for (uint16_t slot = begin; slot < end; ++slot) {{
            uint16_t pattern = {prefix}_bucket_pattern[slot];
            uint16_t length = {prefix}_length[pattern];
            if ((size_t){prefix}_consume_length[pattern] > len - candidate) continue;
            uint16_t token_offset = {prefix}_offset[pattern];
            size_t pos = candidate;
            uint16_t token_index = 0;
            for (; token_index < length; ++token_index) {{
                uint16_t token = {prefix}_token[token_offset + token_index];
                if (token >= 65532u) {{
                    int previous_word = pos > 0 && {prefix}_word(data[pos - 1]);
                    int current_word = pos < len && {prefix}_word(data[pos]);
                    int assertion_ok = 0;
                    if (token == 65535u) assertion_ok = previous_word != current_word;
                    else if (token == 65534u) assertion_ok = previous_word == current_word;
                    else if (token == 65533u) assertion_ok = pos == 0;
                    else if (token == 65532u) assertion_ok = pos == len;
                    if (!assertion_ok) break;
                    continue;
                }}
                if (pos >= len) break;
                unsigned char byte = {prefix}_lower(data[pos]);
                if (token < 256u) {{
                    if (byte != token) break;
                }} else {{
                    uint16_t class_id = (uint16_t)(token - 256u);
                    if (!({prefix}_class[class_id * 4u + (byte >> 6)] &
                          (1ULL << (byte & 63)))) break;
                }}
                ++pos;
            }}
            if (token_index != length) continue;
            if ({1 if plan['continuation'] == 'MATCH' else 0})
                return {result_value};
            while (pos < len && (data[pos] == ' ' ||
                   (data[pos] >= '\\t' && data[pos] <= '\\r'))) ++pos;
            if (pos + 1 < len && data[pos] == '=' && data[pos + 1] != '=')
                return {result_value};
        }}
    }}
    return 0;
}}
""")
    return '\n'.join(code)


def emit_seeded_suffix_prefilter_recursive(
        rule_id, pattern, plan, state_budget=8192,
        table_budget=2 * 1024 * 1024,
        total_table_budget=8 * 1024 * 1024):
    """Guard an exact recursive DAG with a sound finite suffix matcher."""
    prefilter_name = f'lumina_seeded_suffix_{rule_id}_prefilter'
    exact_name = f'lumina_seeded_suffix_{rule_id}_exact'
    prefilter = emit_fixed_mask_dictionary(
        rule_id, plan,
        function_name=prefilter_name,
        symbol_prefix=f'lumina_seeded_suffix_{rule_id}',
        match_value=1,
        static_function=True,
    )
    exact = emit_recursive_factored_concat_dfa(
        rule_id, pattern,
        state_budget=state_budget,
        table_budget=table_budget,
        total_table_budget=total_table_budget,
        function_name=exact_name,
        symbol_prefix=f'lumina_seeded_exact_{rule_id}',
        match_value=1,
        static_function=True,
    )
    wrapper = f"""
int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{
    if (!{prefilter_name}(data, len, offset)) return 0;
    return {exact_name}(data, len, offset) ? {rule_id} : 0;
}}
"""
    return prefilter + '\n' + exact + '\n' + wrapper


def emit_compact_prefix_fixed_suffix_dfa(
        rule_id, pattern, plan, state_budget=8192,
        table_budget=2 * 1024 * 1024):
    """Emit an exact row-interned prefix DFA with an anchored finite suffix."""
    prefix_ast = plan.get('prefix_ast')
    prefix_dfa = plan.get('prefix_dfa')
    ignore_case = plan.get('ignore_case')
    dot_all = plan.get('dot_all')
    if prefix_ast is None or prefix_dfa is None:
        ast, ignore_case, dot_all = parse_regex_ast(pattern)
        if len(ast.data) < 2:
            raise DfaUnsupportedRegex(
                'compact prefix/suffix requires two AST nodes')
        prefix_ast = type(ast)(ast.state, data=list(ast.data[:-1]))
        prefix_dfa = compile_dfa_ast(
            prefix_ast, ignore_case, dot_all, state_budget=state_budget)
    suffix_name = f'lumina_compact_suffix_{rule_id}'
    prefix_name = f'lumina_compact_prefix_{rule_id}'
    suffix = emit_fixed_mask_dictionary(
        rule_id, plan,
        function_name=suffix_name,
        symbol_prefix=f'{suffix_name}_table',
        match_value=1,
        static_function=True,
        anchored=True,
    )
    prefix = emit_dfa_c(
        rule_id, None,
        state_budget=state_budget,
        table_budget=table_budget,
        function_name=prefix_name,
        symbol_prefix=f'{prefix_name}_dfa',
        match_value=1,
        static_function=True,
        ast=prefix_ast,
        ast_ignore_case=ignore_case,
        ast_dot_all=dot_all,
        compiled_dfa=prefix_dfa,
        accept_delegate=suffix_name,
        intern_transition_rows=True,
        intern_accept_rows=True,
    )

    first_bytes = first_bytes_of(pattern)
    if not first_bytes:
        raise DfaUnsupportedRegex('compact prefix/suffix has no candidate bytes')
    first_mask = [0, 0, 0, 0]
    for byte in first_bytes:
        first_mask[byte >> 6] |= 1 << (byte & 63)
    first_words = ', '.join(
        f'0x{word:016x}ULL' for word in first_mask)
    wrapper = f"""
int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{
    static const uint64_t first_mask[4] = {{ {first_words} }};
    if (offset >= len) return 0;
    for (size_t candidate = offset; candidate < len; ++candidate) {{
        unsigned char byte = data[candidate];
        if (!(first_mask[byte >> 6] & (1ULL << (byte & 63)))) continue;
        if ({prefix_name}(data, len, candidate)) return {rule_id};
    }}
    return 0;
}}
"""
    return suffix + '\n' + prefix + '\n' + wrapper


def _is_ascii_whitespace_repeat(node):
    """Return true for an unbounded zero-or-more ASCII whitespace node."""
    op, value = node
    if getattr(op, 'name', str(op)) not in ('MAX_REPEAT', 'MIN_REPEAT'):
        return False
    minimum, maximum, repeated = value
    if minimum != 0 or getattr(maximum, 'name', str(maximum)) != 'MAXREPEAT':
        return False
    if len(repeated) != 1 or getattr(repeated[0][0], 'name', str(repeated[0][0])) != 'IN':
        return False
    whitespace_words = build_bitmask_for_in(repeated[0][1], False)
    expected_whitespace = [0, 0, 0, 0]
    for byte in (9, 10, 11, 12, 13, 32):
        expected_whitespace[byte >> 6] |= 1 << (byte & 63)
    return whitespace_words == expected_whitespace


def shared_call_dictionary_plan(pattern, expansion_cap=100000):
    """Recognize a finite word dictionary followed by an exact typed suffix."""
    ast, ignore_case, dot_all = parse_regex_ast(pattern)
    if dot_all:
        return None
    names = [getattr(op, 'name', str(op)) for op, _ in ast.data]
    start_boundary = False
    branch_index = 0
    if names and names[0] == 'AT':
        if getattr(ast.data[0][1], 'name', str(ast.data[0][1])) != 'AT_BOUNDARY':
            return None
        start_boundary = True
        branch_index = 1
    expected_length = branch_index + 3
    if len(ast.data) not in (expected_length, expected_length + 1):
        return None
    if names[branch_index:branch_index + 2] != ['BRANCH', 'MAX_REPEAT']:
        return None
    if not _is_ascii_whitespace_repeat(ast.data[branch_index + 1]):
        return None

    continuation = None
    suffix_index = branch_index + 2
    if (len(ast.data) == expected_length and
            names[suffix_index] == 'LITERAL' and
            ast.data[suffix_index][1] == ord('(')):
        continuation = 'CALL'
    elif (len(ast.data) == expected_length + 1 and
          names[suffix_index:] == ['LITERAL', 'NOT_LITERAL'] and
          ast.data[suffix_index][1] == ord('=') and
          ast.data[suffix_index + 1][1] == ord('=')):
        continuation = 'ASSIGN_NON_EQ'
    if continuation is None:
        return None

    try:
        words = finite_literal_language(
            [ast.data[branch_index]], expansion_cap=expansion_cap)
    except DfaUnsupportedRegex:
        return None
    normalized = set()
    for word in words:
        normalized_word = bytes(
            byte | 0x20 if ignore_case and ord('A') <= byte <= ord('Z') else byte
            for byte in word)
        if not normalized_word:
            return None
        trailing = len(normalized_word)
        while (trailing > 0 and
               normalized_word[trailing - 1] in (9, 10, 11, 12, 13, 32)):
            trailing -= 1
        if trailing == 0 or any(
                not (ord('A') <= byte <= ord('Z') or
                     ord('a') <= byte <= ord('z') or
                     ord('0') <= byte <= ord('9') or byte == ord('_'))
                for byte in normalized_word[:trailing]):
            return None
        if any(byte not in (9, 10, 11, 12, 13, 32)
               for byte in normalized_word[trailing:]):
            return None
        normalized.add(normalized_word)
    if not normalized:
        return None
    return {
        'words': tuple(sorted(normalized)),
        'continuation': continuation,
        'ignore_case': ignore_case,
        'start_boundary': start_boundary,
    }


def standalone_call_dictionary_profitable(plan):
    """Select compact standalone tries without stealing shared router families."""
    if plan is None or plan['ignore_case'] or plan['start_boundary']:
        return False
    words = plan['words']
    return (plan['continuation'] == 'CALL' and len(words) >= 8 and
            sum(len(word) for word in words) >= 32)


def emit_shared_call_trie_router(group, router_index):
    """Emit one sparse exact trie returning a local rule accept mask."""
    if not 1 <= len(group) <= 8:
        raise DfaUnsupportedRegex('shared dictionary router supports 1..8 rules')
    ignore_case = group[0][1]['ignore_case']
    start_boundary = group[0][1]['start_boundary']
    if any(plan['ignore_case'] != ignore_case or
           plan['start_boundary'] != start_boundary for _, plan in group):
        raise DfaUnsupportedRegex('shared dictionary router semantics differ')

    nodes = [{}]
    accepts = [0]
    for local_index, (_, plan) in enumerate(group):
        bit = 1 << local_index
        for word in plan['words']:
            node = 0
            for byte in word:
                child = nodes[node].get(byte)
                if child is None:
                    child = len(nodes)
                    nodes[node][byte] = child
                    nodes.append({})
                    accepts.append(0)
                node = child
            accepts[node] |= bit

    edges = []
    node_first = []
    node_count = []
    for children in nodes:
        node_first.append(len(edges))
        ordered = sorted(children.items())
        node_count.append(len(ordered))
        edges.extend(ordered)
    if len(nodes) > 65535 or len(edges) > 65535 or max(node_count, default=0) > 255:
        raise DfaUnsupportedRegex('shared call trie exceeds compact index budget')

    root = [0] * 256
    for byte, target in nodes[0].items():
        root[byte] = target
    subtree_masks = [0] * len(nodes)
    for node in range(len(nodes) - 1, -1, -1):
        mask = accepts[node]
        for child in nodes[node].values():
            mask |= subtree_masks[child]
        subtree_masks[node] = mask

    prefix = f'lumina_shared_call_router_{router_index}'
    continuation_ids = {
        'CALL': 1,
        'ASSIGN_NON_EQ': 2,
    }
    continuations = [
        continuation_ids[plan['continuation']]
        for _, plan in group
    ]

    def emit_array(ctype, name, values, width, formatter=str):
        rows = []
        for start in range(0, len(values), width):
            rows.append(
                '    ' + ', '.join(formatter(value)
                                  for value in values[start:start + width]) + ',')
        return (
            f'static const {ctype} {name}[{len(values)}] = {{\n' +
            '\n'.join(rows) + '\n};\n')

    code = [
        emit_array('uint16_t', f'{prefix}_root', root, 16),
        emit_array('uint16_t', f'{prefix}_node_first', node_first, 16),
        emit_array('uint8_t', f'{prefix}_node_count', node_count, 24),
        emit_array('uint8_t', f'{prefix}_accept', accepts, 24,
                   lambda value: f'0x{value:02x}u'),
        emit_array('uint8_t', f'{prefix}_subtree_mask', subtree_masks, 24,
                   lambda value: f'0x{value:02x}u'),
        emit_array('uint8_t', f'{prefix}_edge_byte',
                   [byte for byte, _ in edges], 24,
                   lambda value: f'0x{value:02x}u'),
        emit_array('uint16_t', f'{prefix}_edge_next',
                   [target for _, target in edges], 16),
        emit_array('uint8_t', f'{prefix}_continuation',
                   continuations, 8),
    ]
    all_mask = (1 << len(group)) - 1
    fold_body = (
        "return (byte >= 'A' && byte <= 'Z') ? "
        "(unsigned char)(byte | 0x20u) : byte;"
        if ignore_case else "return byte;"
    )
    boundary_guard = (
        f"(candidate > 0 && {prefix}_word(data[candidate - 1]))"
        if start_boundary else "0"
    )
    code.append(f"""
static inline unsigned char {prefix}_lower(unsigned char byte) {{
    {fold_body}
}}

static inline int {prefix}_word(unsigned char byte) {{
    return (byte >= 'A' && byte <= 'Z') ||
           (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') || byte == '_';
}}

static inline int {prefix}_continue(const unsigned char *data, size_t len,
                                    size_t pos, uint8_t kind) {{
    while (pos < len && (data[pos] == ' ' ||
           (data[pos] >= '\\t' && data[pos] <= '\\r'))) ++pos;
    if (kind == 1u) return pos < len && data[pos] == '(';
    if (kind == 2u) {{
        return pos + 1 < len && data[pos] == '=' && data[pos + 1] != '=';
    }}
    return 0;
}}

uint64_t {prefix}_match(const unsigned char *data, size_t len, size_t offset,
                        uint64_t wanted_mask) {{
    uint64_t hits = 0;
    wanted_mask &= 0x{all_mask:02x}u;
    if (offset >= len || !wanted_mask) return 0;
    for (size_t candidate = offset; candidate < len; ++candidate) {{
        unsigned char first_byte = {prefix}_lower(data[candidate]);
        uint16_t node = {prefix}_root[first_byte];
        if (!node || !({prefix}_subtree_mask[node] & wanted_mask) ||
            {boundary_guard}) continue;
        size_t pos = candidate + 1;
        for (;;) {{
            uint8_t accepted = (uint8_t)({prefix}_accept[node] & wanted_mask);
            if (accepted) {{
                uint8_t pending = accepted;
                while (pending) {{
                    uint8_t local_index = (uint8_t)__builtin_ctz((unsigned)pending);
                    uint8_t bit = (uint8_t)(1u << local_index);
                    pending = (uint8_t)(pending & (uint8_t)(pending - 1u));
                    if ({prefix}_continue(data, len, pos,
                                          {prefix}_continuation[local_index])) {{
                        hits |= bit;
                    }}
                }}
                if ((hits & wanted_mask) == wanted_mask) return hits;
            }}
            if (pos >= len) break;
            unsigned char byte = {prefix}_lower(data[pos]);
            uint16_t first = {prefix}_node_first[node];
            uint8_t count = {prefix}_node_count[node];
            uint16_t next = 0;
            if (count == 1) {{
                next = ({prefix}_edge_byte[first] == byte)
                           ? {prefix}_edge_next[first] : 0;
            }} else {{
                for (uint8_t edge = 0; edge < count; ++edge) {{
                    uint16_t index = (uint16_t)(first + edge);
                    if ({prefix}_edge_byte[index] == byte) {{
                        next = {prefix}_edge_next[index];
                        break;
                    }}
                }}
            }}
            if (!next || !({prefix}_subtree_mask[next] & wanted_mask)) break;
            node = next;
            ++pos;
        }}
    }}
    return hits;
}}
""")
    wrappers = {}
    for local_index, (rule, _) in enumerate(group):
        rule_id = rule['id']
        wrappers[rule_id] = (
            f"int lumina_scan_rule_{rule_id}(const unsigned char *data, "
            f"size_t len, size_t offset) {{\n"
            f"    const uint64_t wanted = 1ULL << {local_index};\n"
            f"    return ({prefix}_match(data, len, offset, wanted) & wanted) "
            f"? {rule_id} : 0;\n"
            f"}}\n"
        )
    return '\n'.join(code), wrappers, len(nodes), len(edges)


def lower_shared_call_routers(detection):
    """Replace compatible large dictionary matchers with shared trie routers."""
    groups = {}
    for rule in detection:
        if rule.get('operator') != '@rx' or rule.get('negated') or rule.get('_tx_chain'):
            continue
        if rule.get('_standalone_call_trie'):
            continue
        plan = shared_call_dictionary_plan(rule.get('pattern') or '')
        if plan is None:
            continue
        transform_key = tuple(
            str(transform).lower() for transform in (rule.get('transforms') or []))
        group_key = (transform_key, plan['ignore_case'], plan['start_boundary'])
        groups.setdefault(group_key, []).append((rule, plan))

    stats = {'routers': 0, 'rules': 0, 'words': 0, 'nodes': 0, 'edges': 0}
    for _, candidates in sorted(groups.items()):
        if len(candidates) < 2 and len(candidates[0][1]['words']) < 256:
            continue
        # Keep masks in one machine word and bound one generated sparse trie.
        for group_start in range(0, len(candidates), 8):
            group = candidates[group_start:group_start + 8]
            if len(group) < 2 and len(group[0][1]['words']) < 256:
                continue
            try:
                router_code, wrappers, node_count, edge_count = (
                    emit_shared_call_trie_router(group, stats['routers']))
            except DfaUnsupportedRegex:
                continue
            first_rule = group[0][0]
            first_rule['_fn'] = router_code + '\n' + wrappers[first_rule['id']]
            for rule, _ in group[1:]:
                rule['_fn'] = wrappers[rule['id']]
            for local_index, (rule, plan) in enumerate(group):
                continuation = plan['continuation'].lower().replace('_', '-')
                rule['_regex_backend'] = f'shared-seed-{continuation}-trie'
                rule['_force_pos0'] = True
                rule['_shared_router'] = stats['routers']
                rule['_shared_router_bit'] = local_index
                stats['words'] += len(plan['words'])
            stats['routers'] += 1
            stats['rules'] += len(group)
            stats['nodes'] += node_count
            stats['edges'] += edge_count
    return stats


def is_disruptive_detection(r):
    """Accept ordinary ModSecurity disruptive rules, not only CRS scoring rules."""
    if r.get('kind') != 'SecRule' or not r.get('id'):
        return False
    actions = {str(action).lower() for action in (r.get('actions') or {})}
    return bool(actions & {'block', 'deny', 'drop'})


def is_compilable_detection(r, rule_mode):
    if r.get('_chain_members'):
        if rule_mode == 'crs-scoring':
            return chain_is_score_bearing(r)
        return chain_is_score_bearing(r) or any(
            is_disruptive_detection(member) for member in r['_chain_members'])
    if rule_mode == 'crs-scoring':
        return is_score_bearing_detection(r)
    return is_score_bearing_detection(r) or is_disruptive_detection(r)

RUNTIME_COVERED_IDS = {
    # C4 STRUCTURAL pass in luminawaf_inspect_bundle. These rules consume
    # request metadata, not generic URI/ARGS/BODY buffers, so emitting them as
    # parser scans duplicates scoring and creates false positives.
    '911100',  # REQUEST_METHOD !@within %{tx.allowed_methods}
    '920100',  # REQUEST_LINE !@rx valid request-line grammar
    '913100',  # REQUEST_HEADERS:User-Agent @pmFromFile scanners-user-agents
    '920430',  # REQUEST_PROTOCOL !@within %{tx.allowed_http_versions}
    '920660',  # &REQUEST_HEADERS:Request-Range @gt 0
    '920280',  # &REQUEST_HEADERS:Host @eq 0
    '920620',  # &REQUEST_HEADERS:Content-Type @gt 1
    '920320',  # &REQUEST_HEADERS:User-Agent @eq 0
}

# Runtime structural rules may still need translator-owned immutable resources.
# Keep a stable runtime ABI even when a custom ModSecurity configuration omits
# the rule: the generated PM source emits a zero-result stub in that case.
RUNTIME_PM_RULE_IDS = {'913100'}

def emit_streq(rule_id, value):
    lit = _c_bytes_literal(value)
    L = len(value.encode('utf-8', 'replace'))
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    static const unsigned char P[] = {{ {lit} }}; const size_t L = {L};\n"
            f"    (void)offset;\n"
            f"    if (len != L) return 0;\n"
            f"    for (size_t i = 0; i < L; i++) if (data[i] != P[i]) return 0;\n"
            f"    return {rule_id};\n}}\n")

def emit_numeric_compare(rule_id, op, value):
    try:
        threshold = int(str(value).strip())
    except ValueError:
        threshold = 0
    cmp_op = {'@eq': '==', '@gt': '>', '@ge': '>=', '@lt': '<'}.get(op, '==')
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    (void)offset;\n"
            f"    long v = 0; int neg = 0; size_t i = 0;\n"
            f"    while (i < len && (data[i] == ' ' || data[i] == '\\t')) i++;\n"
            f"    if (i < len && data[i] == '-') {{ neg = 1; i++; }}\n"
            f"    int any = 0;\n"
            f"    for (; i < len && data[i] >= '0' && data[i] <= '9'; i++) {{ any = 1; v = v * 10 + (long)(data[i] - '0'); }}\n"
            f"    if (!any) v = (long)len;\n"
            f"    if (neg) v = -v;\n"
            f"    if (v {cmp_op} {threshold}L) return {rule_id};\n"
            f"    return 0;\n}}\n")

def _tx_collection_literal(pattern):
    if 'allowed_methods' in pattern:
        return "GET HEAD POST OPTIONS"
    if 'allowed_http_versions' in pattern:
        return "HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0"
    return pattern

def emit_within(rule_id, pattern, negated=False):
    hay = _tx_collection_literal(pattern)
    lit = _c_bytes_literal(hay)
    L = len(hay.encode('utf-8', 'replace'))
    if negated:
        hit = f"0"
        miss = f"{rule_id}"
    else:
        hit = f"{rule_id}"
        miss = f"0"
    return (f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    static const unsigned char H[] = {{ {lit} }}; const size_t HLEN = {L};\n"
            f"    (void)offset;\n"
            f"    if (len == 0 || len > HLEN) return {miss};\n"
            f"    for (size_t i = 0; i + len <= HLEN; i++) {{ int eq = 1;\n"
            f"        for (size_t q = 0; q < len; q++) {{ unsigned char a = H[i+q], b = data[q];\n"
            f"            if ((a|32) != (b|32)) {{ eq = 0; break; }} }}\n"
            f"        if (eq) return {hit}; }}\n"
            f"    return {miss};\n}}\n")

def emit_negated_rx(rule_id, pattern, state_budget=1536,
                    table_budget=2 * 1024 * 1024):
    """Emit ModSecurity `!@rx` as one inverted native DFA predicate.

    Negation executes once for the complete bound value. The positive regular
    language is determinized at build time and the generated table walker is
    inverted only after evaluation; the procedural emitter cannot preserve
    continuation semantics for nested variable repeats.
    """
    inner_name = f"lumina_scan_rule_{rule_id}_positive"
    dfa_pattern, _ = dfa_search_lowering(pattern)
    code = emit_dfa_c(
        rule_id, dfa_pattern,
        state_budget=state_budget, table_budget=table_budget,
        function_name=inner_name,
        symbol_prefix=f"lumina_negated_dfa_{rule_id}",
        match_value=1, static_function=True,
    )
    return (code + "\n" +
            f"int lumina_scan_rule_{rule_id}(const unsigned char *data, size_t len, size_t offset) {{\n"
            f"    if (offset != 0) return 0;\n"
            f"    return {inner_name}(data, len, 0) ? 0 : {rule_id};\n"
            f"}}\n")


def negated_rx_runtime_safe(rule):
    """Return true when runtime dispatch binds each inversion to one exact value."""
    positive = [b for b in rule.get('bindings', []) if not b.excluded]
    if not positive:
        return False
    if all(binding.collection in {'FILES', 'FILES_NAMES'} and
           not binding.count and binding.selector_kind == 'none'
           for binding in positive):
        return True
    for binding in positive:
        if binding.collection != 'REQUEST_HEADERS':
            return False
        if binding.count or binding.selector_kind != 'literal':
            return False
        if binding.selector.upper() not in HEADER_MASKS:
            return False
    return True


def classify_whole_value_request_rule(rule):
    """Classify request predicates that must see one raw collection value.

    Global canonicalization is not a ModSecurity transform and can corrupt
    protocol values (for example, MIME `*/*` resembles a SQL comment). Named
    header negation therefore executes in the request evaluator against the
    caller-owned raw slice with only its declared transform sequence.
    """
    if rule.get('_chain_members'):
        return None
    metadata_predicate = _classify_request_metadata_member(rule)
    if (metadata_predicate is not None and
            metadata_predicate['type'] == 'raw-uri-contains'):
        return {'kind': 'request-metadata-chain', 'predicates': [metadata_predicate]}
    if not rule.get('negated') or rule.get('operator') != '@rx':
        return None
    if not negated_rx_runtime_safe(rule):
        return None
    transforms = {item.lower() for item in (rule.get('transforms') or [])}
    if not transforms <= {'none', 'lowercase'}:
        return None
    binding = _single_positive_binding(rule)
    header_mask = HEADER_MASKS.get(binding.selector.upper(), 0) if binding else 0
    if not header_mask:
        return None
    return {
        'kind': 'named-header-negated-rx',
        'header_mask': header_mask,
        'header_name': binding.selector,
        'pattern': rule.get('pattern') or '',
        'lowercase_value': 'lowercase' in transforms,
    }

# ---------------------------------------------------------------------------
# Variable -> scope mapping
# ---------------------------------------------------------------------------
def map_scope(variables):
    bindings = parse_variable_bindings(variables)
    if not bindings:
        scope = SCOPE_URI | SCOPE_HEADERS | SCOPE_BODY
        return (f"LUMINA_SCOPE_URI | LUMINA_SCOPE_HEADERS | LUMINA_SCOPE_BODY", scope, VAR_ANY, 0)
    contract = compile_binding_contract(bindings)
    scope = contract['scope']
    vtype = contract['var_type_mask']
    collection_mask = contract['collection_mask']
    if scope == 0:
        # No scope bit was set (e.g. FILES-only rules set only a var-type
        # bit). Default the scope to "all" WITHOUT clobbering vtype: a
        # FILES-scoped rule must keep its distinct var-type bit so generic
        # BODY/ARGS scans don't trip it (see 920121).
        scope = SCOPE_URI | SCOPE_HEADERS | SCOPE_BODY
    parts = []
    if scope & SCOPE_URI: parts.append("LUMINA_SCOPE_URI")
    if scope & SCOPE_HEADERS: parts.append("LUMINA_SCOPE_HEADERS")
    if scope & SCOPE_BODY: parts.append("LUMINA_SCOPE_BODY")
    if vtype == 0:
        vtype = VAR_ANY
    return (" | ".join(parts), scope, vtype, collection_mask)

def map_header_mask(variables):
    return compile_binding_contract(parse_variable_bindings(variables))['header_mask']


def emit_transaction_rules_c(detection, rule_removal_controls=None,
                             rule_target_removal_controls=None):
    """Emit bounded request-level predicates for structurally lowered chains."""
    rule_removal_controls = rule_removal_controls or []
    rule_target_removal_controls = rule_target_removal_controls or []
    transaction_rules = [
        (idx, rule) for idx, rule in enumerate(detection)
        if rule.get('_tx_chain')
    ]
    private_matchers = []

    def emit_byte_array(name, value):
        encoded = value.encode('utf-8')
        storage = encoded or b'\0'
        return (f"static const unsigned char {name}[{len(storage)}] = {{" +
                ",".join(str(byte) for byte in storage) + "};\n")

    def emit_transform_sequence(name, transforms):
        transform_ids = {
            'lowercase': 'LUMINA_T_LOWERCASE',
            'urldecodeuni': 'LUMINA_T_URL_DECODE_UNI',
        }
        values = [transform_ids[item] for item in transforms]
        values.append('LUMINA_T_NONE')
        return (f"static const LuminaTransformId {name}[{len(values)}] = {{" +
                ",".join(values) + "};\n")

    def emit_byte_mask(name, masks):
        return (f"static const uint64_t {name}[4] = {{" +
                ",".join(f"UINT64_C({int(value)})" for value in masks) + "};\n")

    for idx, rule in transaction_rules:
        descriptor = rule['_tx_chain']
        if descriptor['kind'] == 'request-metadata-chain':
            for predicate_index, predicate in enumerate(descriptor['predicates']):
                if predicate['type'] in {'scalar-rx', 'named-header-rx'}:
                    dfa_pattern, _ = dfa_search_lowering(predicate['pattern'])
                    private_matchers.append(emit_dfa_c(
                        rule['id'], dfa_pattern,
                        state_budget=1536, table_budget=2 * 1024 * 1024,
                        function_name=f'lumina_tx_metadata_rx_{idx}_{predicate_index}',
                        symbol_prefix=f'lumina_tx_metadata_rx_dfa_{idx}_{predicate_index}',
                        match_value=1, static_function=True,
                        ascii_lower_input=predicate['lowercase'],
                    ))
                elif predicate['type'] == 'named-header-pm':
                    pm_code, _ = gen_phrase_scanner(
                        f'tx_metadata_pm_{idx}_{predicate_index}',
                        predicate['literals'])
                    private_matchers.append(pm_code)
                elif predicate['type'] == 'scalar-streq':
                    private_matchers.append(emit_byte_array(
                        f'lumina_tx_metadata_value_{idx}_{predicate_index}',
                        predicate['value']))
                elif predicate['type'] == 'scalar-within':
                    private_matchers.append(emit_byte_array(
                        f'lumina_tx_metadata_allowed_{idx}_{predicate_index}',
                        predicate['allowed']))
                elif predicate['type'] == 'raw-uri-contains':
                    private_matchers.append(emit_byte_array(
                        f'lumina_tx_metadata_raw_uri_needle_{idx}_{predicate_index}',
                        predicate['value']))
                elif predicate['type'] == 'request-basename-endswith':
                    private_matchers.append(emit_byte_array(
                        f'lumina_tx_metadata_basename_suffix_{idx}_{predicate_index}',
                        predicate['value']))
                    private_matchers.append(emit_transform_sequence(
                        f'lumina_tx_metadata_basename_transforms_{idx}_{predicate_index}',
                        predicate['transforms']))
        elif descriptor['kind'] == 'request-body-processor-url-validator':
            search_pattern = (r"(?:[\x00-\xff]*)(?:" +
                              descriptor['body_precondition_pattern'] + r")")
            private_matchers.append(emit_dfa_c(
                rule['id'], search_pattern,
                state_budget=256, table_budget=64 * 1024,
                function_name=f'lumina_tx_body_precondition_{idx}',
                symbol_prefix=f'lumina_tx_body_precondition_dfa_{idx}',
                match_value=1, static_function=True,
            ))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_reqbody_processor_{idx}', descriptor['processor']))
        elif descriptor['kind'] == 'multipart-field-not-within-static-tx':
            private_matchers.append(emit_byte_array(
                f'lumina_tx_multipart_field_{idx}', descriptor['field_name']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_multipart_field_prefix_{idx}', descriptor['value_prefix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_multipart_field_suffix_{idx}', descriptor['value_suffix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_multipart_field_allowed_{idx}', descriptor['allowed_value']))
        elif descriptor['kind'] == 'request-method-override-parameter':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['value_pattern'],
                state_budget=256, table_budget=64 * 1024,
                function_name=f'lumina_tx_value_match_{idx}',
                symbol_prefix=f'lumina_tx_value_dfa_{idx}',
                match_value=1, static_function=True,
            ))
            parameter = descriptor['parameter_name'].encode('utf-8')
            private_matchers.append(
                f"static const unsigned char lumina_tx_parameter_{idx}[{len(parameter)}] = {{" +
                ",".join(str(byte) for byte in parameter) + "};\n"
            )
        elif descriptor['kind'] == 'arg-url-authority-off-domain':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['prefix_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_prefix_match_{idx}',
                symbol_prefix=f'lumina_tx_prefix_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
            ))
        elif descriptor['kind'] == 'named-header-capture-not-within-static-tx':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['prefix_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_capture_prefix_{idx}',
                symbol_prefix=f'lumina_tx_capture_prefix_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
            ))
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['capture_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_capture_value_{idx}',
                symbol_prefix=f'lumina_tx_capture_value_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
            ))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_capture_allowed_{idx}', descriptor['allowed_value']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_capture_value_prefix_{idx}', descriptor['value_prefix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_capture_value_suffix_{idx}', descriptor['value_suffix']))
        elif descriptor['kind'] == 'named-header-match-not-within-static-tx':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['match_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_match_value_{idx}',
                symbol_prefix=f'lumina_tx_match_value_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
            ))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_match_allowed_{idx}', descriptor['allowed_value']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_match_value_prefix_{idx}', descriptor['value_prefix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_match_value_suffix_{idx}', descriptor['value_suffix']))
        elif descriptor['kind'] == 'header-name-match-within-static-tx':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['match_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_header_name_match_{idx}',
                symbol_prefix=f'lumina_tx_header_name_match_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
                ascii_lower_input=descriptor['match_lowercase'],
            ))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_header_name_allowed_{idx}', descriptor['allowed_value']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_header_name_value_prefix_{idx}', descriptor['value_prefix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_header_name_value_suffix_{idx}', descriptor['value_suffix']))
        elif descriptor['kind'] == 'request-basename-capture-within-static-tx':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['prefix_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_basename_capture_prefix_{idx}',
                symbol_prefix=f'lumina_tx_basename_capture_prefix_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
            ))
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['capture_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_basename_capture_value_{idx}',
                symbol_prefix=f'lumina_tx_basename_capture_value_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
            ))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_basename_capture_allowed_{idx}', descriptor['allowed_value']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_basename_capture_value_prefix_{idx}', descriptor['value_prefix']))
            private_matchers.append(emit_byte_array(
                f'lumina_tx_basename_capture_value_suffix_{idx}', descriptor['value_suffix']))
            private_matchers.append(emit_transform_sequence(
                f'lumina_tx_basename_capture_transforms_{idx}',
                descriptor['head_transforms']))
        elif descriptor['kind'] == 'named-header-capture-view-chain':
            private_matchers.append(emit_transform_sequence(
                f'lumina_tx_capture_view_transforms_{idx}', descriptor['transforms']))
            for mask_index, masks in enumerate(descriptor['byte_masks']):
                private_matchers.append(emit_byte_mask(
                    f'lumina_tx_capture_view_mask_{idx}_{mask_index}', masks))
            if descriptor['mode'] == 'terminal-capture':
                private_matchers.append(emit_dfa_c(
                    rule['id'], descriptor['child_prefix_pattern'],
                    state_budget=1536, table_budget=2 * 1024 * 1024,
                    function_name=f'lumina_tx_capture_view_prefix_{idx}',
                    symbol_prefix=f'lumina_tx_capture_view_prefix_dfa_{idx}',
                    match_value=1, static_function=True,
                    report_match_end=True, longest_match_end=True,
                    stop_on_dead=True,
                ))
                private_matchers.append(emit_dfa_c(
                    rule['id'], descriptor['child_capture_pattern'],
                    state_budget=1536, table_budget=2 * 1024 * 1024,
                    function_name=f'lumina_tx_capture_view_capture_{idx}',
                    symbol_prefix=f'lumina_tx_capture_view_capture_dfa_{idx}',
                    match_value=1, static_function=True,
                    report_match_end=True, longest_match_end=True,
                    stop_on_dead=True,
                ))
            else:
                child_pattern = (r"(?:[\x00-\xff]*)(?:" +
                                 descriptor['child_pattern'] + r")")
                private_matchers.append(emit_dfa_c(
                    rule['id'], child_pattern,
                    state_budget=1536, table_budget=2 * 1024 * 1024,
                    function_name=f'lumina_tx_capture_view_child_{idx}',
                    symbol_prefix=f'lumina_tx_capture_view_child_dfa_{idx}',
                    match_value=1, static_function=True,
                ))
                private_matchers.append(emit_byte_array(
                    f'lumina_tx_capture_view_forbidden_{idx}',
                    descriptor['forbidden_prefix']))
        elif descriptor['kind'] == 'multipart-header-capture-negated-rx':
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['producer_prefix_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_multipart_prefix_{idx}',
                symbol_prefix=f'lumina_tx_multipart_prefix_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
                ascii_lower_input=descriptor['producer_lowercase_value'],
            ))
            private_matchers.append(emit_dfa_c(
                rule['id'], descriptor['producer_capture_pattern'],
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_multipart_capture_{idx}',
                symbol_prefix=f'lumina_tx_multipart_capture_dfa_{idx}',
                match_value=1, static_function=True,
                report_match_end=True, longest_match_end=True,
                stop_on_dead=True,
                ascii_lower_input=descriptor['producer_lowercase_value'],
            ))
            consumer_pattern, _ = dfa_search_lowering(descriptor['consumer_pattern'])
            private_matchers.append(emit_dfa_c(
                rule['id'], consumer_pattern,
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_multipart_value_positive_{idx}',
                symbol_prefix=f'lumina_tx_multipart_value_dfa_{idx}',
                match_value=1, static_function=True,
                ascii_lower_input=descriptor['consumer_lowercase_value'],
            ))
        elif descriptor['kind'] == 'named-header-negated-rx':
            dfa_pattern, _ = dfa_search_lowering(descriptor['pattern'])
            private_matchers.append(emit_dfa_c(
                rule['id'], dfa_pattern,
                state_budget=1536, table_budget=2 * 1024 * 1024,
                function_name=f'lumina_tx_header_positive_{idx}',
                symbol_prefix=f'lumina_tx_header_positive_dfa_{idx}',
                match_value=1, static_function=True,
                ascii_lower_input=descriptor['lowercase_value'],
            ))

    for control_index, control in enumerate(rule_removal_controls):
        private_matchers.append(emit_byte_array(
            f'lumina_tx_rule_remove_value_{control_index}', control['value']))
    for control_index, control in enumerate(rule_target_removal_controls):
        words = control['allowed_words']
        private_matchers.append(
            f'static const uint64_t lumina_tx_target_allowed_{control_index}[4] = {{'
            f'{words[0]}ULL,{words[1]}ULL,{words[2]}ULL,{words[3]}ULL}};\n')

    lines = [
        '#include <stdint.h>',
        '#include <stddef.h>',
        '#include <stdbool.h>',
        '#include <string.h>',
        '#include "luminawaf.h"',
        '#include "lumina_transforms.h"',
        '#include "generated/crs_short_rules.h"',
        '#include "luminawaf.h"',
        '',
        *private_matchers,
        'static inline unsigned char lumina_tx_ascii_lower(unsigned char c) {',
        "    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20u) : c;",
        '}',
        '',
        'static bool lumina_tx_projected_equal(const unsigned char *input, size_t input_len,',
        '                                      const unsigned char *expected, size_t expected_len,',
        '                                      bool lowercase) {',
        '    if (!input || !expected || input_len != expected_len) return false;',
        '    for (size_t i = 0; i < input_len; i++) {',
        '        unsigned char byte = lowercase ? lumina_tx_ascii_lower(input[i]) : input[i];',
        '        if (byte != expected[i]) return false;',
        '    }',
        '    return true;',
        '}',
        '',
        'static bool lumina_tx_projected_within(const unsigned char *input, size_t input_len,',
        '                                       const unsigned char *allowed, size_t allowed_len,',
        '                                       bool lowercase) {',
        '    if (!input || !allowed || input_len == 0 || input_len > allowed_len) return false;',
        '    for (size_t start = 0; start + input_len <= allowed_len; start++) {',
        '        bool equal = true;',
        '        for (size_t i = 0; i < input_len; i++) {',
        '            unsigned char byte = lowercase ? lumina_tx_ascii_lower(input[i]) : input[i];',
        '            if (byte != allowed[start + i]) { equal = false; break; }',
        '        }',
        '        if (equal) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_byte_range_invalid(const unsigned char *input, size_t input_len,',
        '                                         const uint64_t allowed[4]) {',
        '    if (!input) return input_len != 0;',
        '    for (size_t i = 0; i < input_len; i++) {',
        '        unsigned char byte = input[i];',
        '        if ((allowed[byte >> 6] & (UINT64_C(1) << (byte & 63))) == 0) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'void lumina_eval_target_controls(const unsigned char *data, size_t len,',
        '                                 uint64_t collection_mask,',
        '                                 LuminaRuleState *state) {',
        '    if (!state || (!data && len != 0)) return;',
    ]

    for control_index, control in enumerate(rule_target_removal_controls):
        condition = (
            f'!lumina_tx_byte_range_invalid(data, len, '
            f'lumina_tx_target_allowed_{control_index})'
            if control['operator_negated'] else
            f'lumina_tx_byte_range_invalid(data, len, '
            f'lumina_tx_target_allowed_{control_index})'
        )
        lines.append(
            f'    if ((collection_mask & {control["source_collection_mask"]}) && '
            f'{condition}) {{')
        target_slot = control['target_collection_slot']
        for target_idx in control['target_engine_indices']:
            lines.append(
                f'        lumina_slab_mark(&state->disabled_rule_targets[{target_slot}], '
                f'{target_idx});')
        lines.append('    }')

    lines.extend([
        '}',
        '',
        'static bool lumina_tx_projected_contains(const unsigned char *input, size_t input_len,',
        '                                         const unsigned char *needle, size_t needle_len) {',
        '    if (!input || !needle || needle_len == 0 || needle_len > input_len) return false;',
        '    unsigned char first = needle[0];',
        '    for (size_t start = 0; start + needle_len <= input_len; start++) {',
        '        if (input[start] != first) continue;',
        '        size_t index = 1;',
        '        while (index < needle_len && input[start + index] == needle[index]) index++;',
        '        if (index == needle_len) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_view_has_mask(const unsigned char *input, size_t input_len,',
        '                                    const uint64_t mask[4]) {',
        '    if (!input || !mask) return false;',
        '    for (size_t index = 0; index < input_len; index++) {',
        '        unsigned char byte = input[index];',
        '        if (mask[byte >> 6] & (UINT64_C(1) << (byte & 63))) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static const BundleVar *lumina_tx_raw_uri(const LuminaBundle *bundle) {',
        '    if (!bundle) return NULL;',
        '    for (int index = 0; index < bundle->count; index++) {',
        '        const BundleVar *var = &bundle->vars[index];',
        '        if (var->var_type == LUMINA_VAR_URI && var->ptr) return var;',
        '    }',
        '    return NULL;',
        '}',
        '',
        'static bool lumina_tx_projected_ends_with(const unsigned char *input, size_t input_len,',
        '                                          const unsigned char *suffix, size_t suffix_len,',
        '                                          bool lowercase) {',
        '    if (!input || !suffix || suffix_len > input_len) return false;',
        '    return lumina_tx_projected_equal(input + input_len - suffix_len, suffix_len,',
        '                                     suffix, suffix_len, lowercase);',
        '}',
        '',
        'static bool lumina_tx_request_basename(const LuminaBundle *bundle,',
        '                                       const unsigned char **basename,',
        '                                       size_t *basename_len) {',
        '    if (!bundle || !basename || !basename_len) return false;',
        '    if (bundle->req_basename) {',
        '        *basename = bundle->req_basename;',
        '        *basename_len = bundle->req_basename_len;',
        '        return true;',
        '    }',
        '    for (int i = 0; i < bundle->count; i++) {',
        '        const BundleVar *var = &bundle->vars[i];',
        '        if (var->var_type != LUMINA_VAR_URI || !var->ptr) continue;',
        '        size_t start = var->len;',
        "        while (start > 0 && var->ptr[start - 1] != '/') start--;",
        '        *basename = var->ptr + start;',
        '        *basename_len = var->len - start;',
        '        return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_transform_needed(const LuminaTransformId *transforms,',
        '                                       const unsigned char *data, size_t len) {',
        '    if (!transforms || !data) return false;',
        '    for (size_t index = 0; transforms[index] != LUMINA_T_NONE; index++) {',
        '        LuminaTransformId transform = transforms[index];',
        '        if (transform == LUMINA_T_URL_DECODE_UNI) {',
        "            for (size_t i = 0; i < len; i++) if (data[i] == '%' || data[i] == '+') return true;",
        '        } else if (transform == LUMINA_T_LOWERCASE) {',
        "            for (size_t i = 0; i < len; i++) if (data[i] >= 'A' && data[i] <= 'Z') return true;",
        '        } else {',
        '            return true;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'static size_t lumina_tx_request_body_length(const LuminaBundle *bundle) {',
        '    size_t total = 0;',
        '    for (int i = 0; i < bundle->count; i++) {',
        '        const BundleVar *var = &bundle->vars[i];',
        '        if (var->var_type != LUMINA_VAR_BODY) continue;',
        '        if (var->len > SIZE_MAX - total) return SIZE_MAX;',
        '        total += var->len;',
        '    }',
        '    return total;',
        '}',
        '',
        'static bool lumina_tx_ends_with_ci(const unsigned char *value, size_t value_len,',
        '                                   const unsigned char *suffix, size_t suffix_len) {',
        '    if (!value || !suffix || suffix_len > value_len) return false;',
        '    size_t start = value_len - suffix_len;',
        '    for (size_t i = 0; i < suffix_len; i++) {',
        '        if (lumina_tx_ascii_lower(value[start + i]) !=',
        '            lumina_tx_ascii_lower(suffix[i])) return false;',
        '    }',
        '    return true;',
        '}',
        '',
        'static bool lumina_tx_capture_url_authority(const unsigned char *value, size_t value_len,',
        '                                            const unsigned char **authority, size_t *authority_len) {',
        '    static const unsigned char HTTP[] = "http://";',
        '    static const unsigned char HTTPS[] = "https://";',
        '    static const unsigned char FTP[] = "ftp://";',
        '    static const unsigned char FTPS[] = "ftps://";',
        '    size_t start = 0;',
        '    if (value_len >= sizeof(HTTPS) - 1 && !__builtin_memcmp(value, HTTPS, sizeof(HTTPS) - 1))',
        '        start = sizeof(HTTPS) - 1;',
        '    else if (value_len >= sizeof(HTTP) - 1 && !__builtin_memcmp(value, HTTP, sizeof(HTTP) - 1))',
        '        start = sizeof(HTTP) - 1;',
        '    else if (value_len >= sizeof(FTPS) - 1 && !__builtin_memcmp(value, FTPS, sizeof(FTPS) - 1))',
        '        start = sizeof(FTPS) - 1;',
        '    else if (value_len >= sizeof(FTP) - 1 && !__builtin_memcmp(value, FTP, sizeof(FTP) - 1))',
        '        start = sizeof(FTP) - 1;',
        '    else return false;',
        '    size_t end = start;',
        "    while (end < value_len && value[end] != '/') end++;",
        '    if (end == value_len) return false;',
        '    *authority = value + start;',
        '    *authority_len = end - start;',
        '    return true;',
        '}',
        '',
        'static const BundleVar *lumina_tx_find_header(const LuminaBundle *bundle, uint32_t mask) {',
        '    for (int i = 0; i < bundle->count; i++) {',
        '        const BundleVar *var = &bundle->vars[i];',
        '        if (var->var_type == LUMINA_VAR_HDR && (var->header_mask & mask)) return var;',
        '    }',
        '    return NULL;',
        '}',
        '',
        'static int lumina_tx_decimal_compare(const unsigned char *left, size_t left_len,',
        '                                     const unsigned char *right, size_t right_len) {',
        "    while (left_len > 1 && *left == '0') { left++; left_len--; }",
        "    while (right_len > 1 && *right == '0') { right++; right_len--; }",
        '    if (left_len != right_len) return left_len < right_len ? -1 : 1;',
        '    int cmp = __builtin_memcmp(left, right, left_len);',
        '    return cmp < 0 ? -1 : cmp > 0 ? 1 : 0;',
        '}',
        '',
        'static bool lumina_tx_header_decimal_capture_compare(',
        '        const LuminaBundle *bundle, uint32_t header_mask, unsigned char separator,',
        '        unsigned comparison) {',
        '    const BundleVar *header = lumina_tx_find_header(bundle, header_mask);',
        '    if (!header || !header->ptr) return false;',
        '    const unsigned char *data = header->ptr;',
        '    size_t len = header->len;',
        '    for (size_t i = 0; i < len; i++) {',
        "        if (data[i] < '0' || data[i] > '9') continue;",
        '        size_t left_start = i;',
        "        while (i < len && data[i] >= '0' && data[i] <= '9') i++;",
        '        size_t left_end = i;',
        '        if (i >= len || data[i] != separator) continue;',
        '        size_t right_start = ++i;',
        "        while (i < len && data[i] >= '0' && data[i] <= '9') i++;",
        '        if (i == right_start) continue;',
        '        int cmp = lumina_tx_decimal_compare(',
        '            data + right_start, i - right_start,',
        '            data + left_start, left_end - left_start);',
        '        if ((comparison == 0u && cmp < 0) || (comparison == 1u && cmp > 0) ||',
        '            (comparison == 2u && cmp >= 0) || (comparison == 3u && cmp == 0))',
        '            return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static int lumina_tx_hex(unsigned char c) {',
        "    if (c >= '0' && c <= '9') return c - '0';",
        "    c = lumina_tx_ascii_lower(c);",
        "    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;",
        '}',
        '',
        'static bool lumina_tx_decode_form_component(const unsigned char *src, size_t src_len,',
        '                                            unsigned char *dst, size_t dst_cap,',
        '                                            bool lowercase, size_t *dst_len) {',
        '    size_t out = 0;',
        '    for (size_t i = 0; i < src_len; i++) {',
        '        unsigned char byte = src[i];',
        "        if (byte == '+' ) byte = ' ';",
        "        else if (byte == '%' && i + 1 < src_len && (src[i + 1] == 'u' || src[i + 1] == 'U')) {",
        '            if (i + 5 >= src_len) return false;',
        '            int h0 = lumina_tx_hex(src[i + 2]);',
        '            int h1 = lumina_tx_hex(src[i + 3]);',
        '            int h2 = lumina_tx_hex(src[i + 4]);',
        '            int h3 = lumina_tx_hex(src[i + 5]);',
        '            if ((h0 | h1 | h2 | h3) < 0) return false;',
        '            unsigned value = (unsigned)(h0 << 12 | h1 << 8 | h2 << 4 | h3);',
        '            if (value > 0x7fu) return false;',
        '            byte = (unsigned char)value;',
        '            i += 5;',
        "        } else if (byte == '%') {",
        '            if (i + 2 >= src_len) return false;',
        '            int hi = lumina_tx_hex(src[i + 1]);',
        '            int lo = lumina_tx_hex(src[i + 2]);',
        '            if ((hi | lo) < 0) return false;',
        '            byte = (unsigned char)(hi << 4 | lo);',
        '            i += 2;',
        '        }',
        '        if (out == dst_cap) return false;',
        '        dst[out++] = lowercase ? lumina_tx_ascii_lower(byte) : byte;',
        '    }',
        '    *dst_len = out;',
        '    return true;',
        '}',
        '',
        'static bool lumina_tx_equal_ci(const unsigned char *left, size_t left_len,',
        '                               const unsigned char *right, size_t right_len) {',
        '    if (!left || !right || left_len != right_len) return false;',
        '    for (size_t i = 0; i < left_len; i++) {',
        '        if (lumina_tx_ascii_lower(left[i]) != lumina_tx_ascii_lower(right[i])) return false;',
        '    }',
        '    return true;',
        '}',
        '',
        'static bool lumina_tx_invalid_utf8(const unsigned char *data, size_t len) {',
        '    if (!data && len != 0) return true;',
        '    size_t i = 0;',
        '    while (i < len) {',
        '        unsigned char b0 = data[i++];',
        '        if (b0 < 0x80u) continue;',
        '        if (b0 >= 0xc2u && b0 <= 0xdfu) {',
        '            if (i >= len || data[i] < 0x80u || data[i] > 0xbfu) return true;',
        '            i++;',
        '            continue;',
        '        }',
        '        if (b0 >= 0xe0u && b0 <= 0xefu) {',
        '            if (i + 1 >= len) return true;',
        '            unsigned char b1 = data[i], b2 = data[i + 1];',
        '            if (b2 < 0x80u || b2 > 0xbfu) return true;',
        '            if (b0 == 0xe0u ? (b1 < 0xa0u || b1 > 0xbfu) :',
        '                b0 == 0xedu ? (b1 < 0x80u || b1 > 0x9fu) :',
        '                              (b1 < 0x80u || b1 > 0xbfu)) return true;',
        '            i += 2;',
        '            continue;',
        '        }',
        '        if (b0 >= 0xf0u && b0 <= 0xf4u) {',
        '            if (i + 2 >= len) return true;',
        '            unsigned char b1 = data[i], b2 = data[i + 1], b3 = data[i + 2];',
        '            if (b2 < 0x80u || b2 > 0xbfu || b3 < 0x80u || b3 > 0xbfu) return true;',
        '            if (b0 == 0xf0u ? (b1 < 0x90u || b1 > 0xbfu) :',
        '                b0 == 0xf4u ? (b1 < 0x80u || b1 > 0x8fu) :',
        '                              (b1 < 0x80u || b1 > 0xbfu)) return true;',
        '            i += 3;',
        '            continue;',
        '        }',
        '        return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_decoded_component_invalid_utf8(',
        '        const unsigned char *raw, size_t raw_len) {',
        '    bool has_percent = false;',
        '    bool has_non_ascii = false;',
        '    for (size_t i = 0; i < raw_len; i++) {',
        "        has_percent = has_percent || raw[i] == '%';",
        '        has_non_ascii = has_non_ascii || raw[i] >= 0x80u;',
        '    }',
        '    if (!has_percent)',
        '        return has_non_ascii && lumina_tx_invalid_utf8(raw, raw_len);',
        '    size_t scratch_cap = lumina_xform_scratch_cap();',
        '    if (raw_len > scratch_cap) return false;',
        '    unsigned char *scratch = lumina_xform_scratch();',
        '    size_t decoded_len = 0;',
        '    if (!scratch || !lumina_tx_decode_form_component(',
        '            raw, raw_len, scratch, scratch_cap, false, &decoded_len)) return false;',
        '    return lumina_tx_invalid_utf8(scratch, decoded_len);',
        '}',
        '',
        'static bool lumina_tx_bundle_has_form_body(const LuminaBundle *bundle);',
        '',
        'static bool lumina_tx_bundle_invalid_utf8(const LuminaBundle *bundle,',
        '                                          unsigned collection_mask) {',
        '    bool has_form_body = lumina_tx_bundle_has_form_body(bundle);',
        '    if ((collection_mask & 1u) && bundle->req_filename &&',
        '        lumina_tx_decoded_component_invalid_utf8(',
        '            bundle->req_filename, bundle->req_filename_len)) return true;',
        '    for (int var_index = 0; var_index < bundle->count; var_index++) {',
        '        const BundleVar *var = &bundle->vars[var_index];',
        '        if (!var->ptr) continue;',
        '        if ((collection_mask & 1u) && !bundle->req_filename &&',
        '            var->var_type == LUMINA_VAR_URI &&',
        '            lumina_tx_decoded_component_invalid_utf8(var->ptr, var->len)) return true;',
        '        bool args_container = var->var_type == LUMINA_VAR_ARGS ||',
        '            (has_form_body && var->var_type == LUMINA_VAR_BODY);',
        '        if (!args_container || !(collection_mask & 6u)) continue;',
        '        for (size_t start = 0; start <= var->len;) {',
        '            size_t end = start;',
        "            while (end < var->len && var->ptr[end] != '&') end++;",
        '            size_t equal = start;',
        "            while (equal < end && var->ptr[equal] != '=') equal++;",
        '            if ((collection_mask & 4u) &&',
        '                lumina_tx_decoded_component_invalid_utf8(',
        '                    var->ptr + start, equal - start)) return true;',
        '            size_t value_start = equal < end ? equal + 1 : end;',
        '            if ((collection_mask & 2u) &&',
        '                lumina_tx_decoded_component_invalid_utf8(',
        '                    var->ptr + value_start, end - value_start)) return true;',
        '            if (end == var->len) break;',
        '            start = end + 1;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_bundle_has_form_body(const LuminaBundle *bundle) {',
        '    static const unsigned char FORM[] = "application/x-www-form-urlencoded";',
        '    const BundleVar *content_type = lumina_tx_find_header(bundle, LUMINA_HDR_CONTENT_TYPE);',
        '    if (!content_type || content_type->len < sizeof(FORM) - 1) return false;',
        '    return lumina_tx_equal_ci(content_type->ptr, sizeof(FORM) - 1,',
        '                              FORM, sizeof(FORM) - 1);',
        '}',
        '',
        'typedef int (*LuminaTxValueMatcher)(const unsigned char *, size_t, size_t);',
        'typedef int (*LuminaTxPrefixMatcher)(const unsigned char *, size_t, size_t, size_t *);',
        '',
        'static bool lumina_tx_invalid_url_encoding(const unsigned char *data, size_t len) {',
        '    if (!data) return false;',
        '    for (size_t i = 0; i < len; i++) {',
        "        if (data[i] != '%') continue;",
        '        if (i + 2 >= len) return true;',
        '        unsigned char high = data[i + 1];',
        '        unsigned char low = data[i + 2];',
        "        bool high_hex = (high >= '0' && high <= '9') ||",
        "                        (high >= 'A' && high <= 'F') ||",
        "                        (high >= 'a' && high <= 'f');",
        "        bool low_hex = (low >= '0' && low <= '9') ||",
        "                       (low >= 'A' && low <= 'F') ||",
        "                       (low >= 'a' && low <= 'f');",
        '        if (!high_hex || !low_hex) return true;',
        '        i += 2;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_reqbody_processor_url_invalid(',
        '        const LuminaBundle *bundle, const unsigned char *processor,',
        '        size_t processor_len, LuminaTxValueMatcher precondition) {',
        '    if (!bundle || !bundle->reqbody_processor ||',
        '        !lumina_tx_projected_equal(bundle->reqbody_processor,',
        '            bundle->reqbody_processor_len, processor, processor_len, false))',
        '        return false;',
        '    for (int i = 0; i < bundle->count; i++) {',
        '        const BundleVar *var = &bundle->vars[i];',
        '        if (var->var_type != LUMINA_VAR_BODY || !var->ptr) continue;',
        '        if (precondition(var->ptr, var->len, 0) &&',
        '            lumina_tx_invalid_url_encoding(var->ptr, var->len)) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static unsigned char lumina_tx_wrapped_capture_byte(const unsigned char *prefix,',
        '                                                    size_t prefix_len,',
        '                                                    const unsigned char *capture,',
        '                                                    size_t capture_len,',
        '                                                    const unsigned char *suffix,',
        '                                                    size_t index) {',
        '    if (index < prefix_len) return prefix[index];',
        '    index -= prefix_len;',
        '    if (index < capture_len) return capture[index];',
        '    return suffix[index - capture_len];',
        '}',
        '',
        'static bool lumina_tx_wrapped_capture_within(const unsigned char *capture,',
        '                                             size_t capture_len,',
        '                                             const unsigned char *prefix,',
        '                                             size_t prefix_len,',
        '                                             const unsigned char *suffix,',
        '                                             size_t suffix_len,',
        '                                             const unsigned char *allowed,',
        '                                             size_t allowed_len, bool lowercase) {',
        '    if (!capture || capture_len > SIZE_MAX - prefix_len ||',
        '        suffix_len > SIZE_MAX - prefix_len - capture_len) return false;',
        '    size_t needle_len = prefix_len + capture_len + suffix_len;',
        '    if (needle_len == 0 || needle_len > allowed_len) return false;',
        '    for (size_t start = 0; start + needle_len <= allowed_len; start++) {',
        '        bool equal = true;',
        '        for (size_t index = 0; index < needle_len; index++) {',
        '            unsigned char byte = lumina_tx_wrapped_capture_byte(',
        '                prefix, prefix_len, capture, capture_len, suffix, index);',
        '            if (lowercase) byte = lumina_tx_ascii_lower(byte);',
        '            if (byte != allowed[start + index]) { equal = false; break; }',
        '        }',
        '        if (equal) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_header_capture_not_within(',
        '        const BundleVar *header, LuminaTxPrefixMatcher prefix_matcher,',
        '        LuminaTxPrefixMatcher capture_matcher, const unsigned char *value_prefix,',
        '        size_t value_prefix_len, const unsigned char *value_suffix,',
        '        size_t value_suffix_len, const unsigned char *allowed, size_t allowed_len,',
        '        bool lowercase) {',
        '    if (!header || !header->ptr) return false;',
        '    for (size_t offset = 0; offset < header->len; offset++) {',
        '        size_t capture_start = 0;',
        '        if (!prefix_matcher(header->ptr, header->len, offset, &capture_start)) continue;',
        '        size_t capture_end = capture_start;',
        '        if (!capture_matcher(header->ptr, header->len, capture_start, &capture_end) ||',
        '            capture_end <= capture_start) continue;',
        '        return !lumina_tx_wrapped_capture_within(',
        '            header->ptr + capture_start, capture_end - capture_start,',
        '            value_prefix, value_prefix_len, value_suffix, value_suffix_len,',
        '            allowed, allowed_len, lowercase);',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_header_match_not_within(',
        '        const BundleVar *header, LuminaTxPrefixMatcher matcher,',
        '        const unsigned char *value_prefix, size_t value_prefix_len,',
        '        const unsigned char *value_suffix, size_t value_suffix_len,',
        '        const unsigned char *allowed, size_t allowed_len, bool lowercase) {',
        '    if (!header || !header->ptr) return false;',
        '    size_t match_end = 0;',
        '    if (!matcher(header->ptr, header->len, 0, &match_end) || match_end > header->len)',
        '        return false;',
        '    return !lumina_tx_wrapped_capture_within(',
        '        header->ptr, match_end, value_prefix, value_prefix_len,',
        '        value_suffix, value_suffix_len, allowed, allowed_len, lowercase);',
        '}',
        '',
        'static bool lumina_tx_header_name_within(',
        '        const LuminaBundle *bundle, LuminaTxPrefixMatcher matcher,',
        '        const unsigned char *value_prefix, size_t value_prefix_len,',
        '        const unsigned char *value_suffix, size_t value_suffix_len,',
        '        const unsigned char *allowed, size_t allowed_len, bool lowercase) {',
        '    if (!bundle || !matcher) return false;',
        '    for (int index = 0; index < bundle->count; index++) {',
        '        const BundleVar *var = &bundle->vars[index];',
        '        if (!(var->scope & LUMINA_SCOPE_HEADERS) || !var->name || var->name_len == 0)',
        '            continue;',
        '        size_t match_end = 0;',
        '        if (!matcher(var->name, var->name_len, 0, &match_end) ||',
        '            match_end > var->name_len) continue;',
        '        if (lumina_tx_wrapped_capture_within(',
        '                var->name, match_end, value_prefix, value_prefix_len,',
        '                value_suffix, value_suffix_len, allowed, allowed_len, lowercase))',
        '            return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_basename_capture_within(',
        '        const LuminaBundle *bundle, LuminaTxPrefixMatcher prefix_matcher,',
        '        LuminaTxPrefixMatcher capture_matcher, const LuminaTransformId *transforms,',
        '        const unsigned char *value_prefix, size_t value_prefix_len,',
        '        const unsigned char *value_suffix, size_t value_suffix_len,',
        '        const unsigned char *allowed, size_t allowed_len, bool lowercase) {',
        '    const unsigned char *basename = NULL;',
        '    size_t basename_len = 0;',
        '    if (!lumina_tx_request_basename(bundle, &basename, &basename_len) || !basename)',
        '        return false;',
        '    const unsigned char *view = basename;',
        '    size_t view_len = basename_len;',
        '    if (lumina_tx_transform_needed(transforms, basename, basename_len)) {',
        '        size_t scratch_cap = lumina_xform_scratch_cap();',
        '        if (basename_len > scratch_cap) return false;',
        '        unsigned char *scratch = lumina_xform_scratch();',
        '        if (!scratch) return false;',
        '        __builtin_memcpy(scratch, basename, basename_len);',
        '        view_len = lumina_apply_transforms(transforms, scratch, basename_len);',
        '        view = scratch;',
        '    }',
        '    for (size_t offset = 0; offset < view_len; offset++) {',
        '        size_t capture_start = 0;',
        '        if (!prefix_matcher(view, view_len, offset, &capture_start)) continue;',
        '        size_t capture_end = capture_start;',
        '        if (!capture_matcher(view, view_len, capture_start, &capture_end) ||',
        '            capture_end <= capture_start) continue;',
        '        if (lumina_tx_wrapped_capture_within(',
        '                view + capture_start, capture_end - capture_start,',
        '                value_prefix, value_prefix_len, value_suffix, value_suffix_len,',
        '                allowed, allowed_len, lowercase)) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_starts_with_ci(const unsigned char *value, size_t value_len,',
        '                                     const unsigned char *prefix, size_t prefix_len) {',
        '    if (!value || !prefix || prefix_len > value_len) return false;',
        '    for (size_t i = 0; i < prefix_len; i++) {',
        '        if (lumina_tx_ascii_lower(value[i]) != lumina_tx_ascii_lower(prefix[i])) return false;',
        '    }',
        '    return true;',
        '}',
        '',
        'static bool lumina_tx_multipart_boundary(const LuminaBundle *bundle,',
        '                                         const unsigned char **boundary,',
        '                                         size_t *boundary_len) {',
        '    static const unsigned char MULTIPART[] = "multipart/";',
        '    static const unsigned char BOUNDARY[] = "boundary";',
        '    const BundleVar *content_type = lumina_tx_find_header(bundle, LUMINA_HDR_CONTENT_TYPE);',
        '    if (!content_type || !lumina_tx_starts_with_ci(',
        '            content_type->ptr, content_type->len, MULTIPART, sizeof(MULTIPART) - 1))',
        '        return false;',
        '    size_t pos = sizeof(MULTIPART) - 1;',
        "    while (pos < content_type->len && content_type->ptr[pos] != ';') pos++;",
        '    while (pos < content_type->len) {',
        "        if (content_type->ptr[pos] == ';') pos++;",
        "        while (pos < content_type->len && (content_type->ptr[pos] == ' ' ||",
        "               content_type->ptr[pos] == '\\t')) pos++;",
        '        size_t name_start = pos;',
        "        while (pos < content_type->len && content_type->ptr[pos] != '=' &&",
        "               content_type->ptr[pos] != ';') pos++;",
        '        size_t name_end = pos;',
        "        while (name_end > name_start && (content_type->ptr[name_end - 1] == ' ' ||",
        "               content_type->ptr[name_end - 1] == '\\t')) name_end--;",
        "        if (pos == content_type->len || content_type->ptr[pos] != '=') continue;",
        '        pos++;',
        "        while (pos < content_type->len && (content_type->ptr[pos] == ' ' ||",
        "               content_type->ptr[pos] == '\\t')) pos++;",
        '        bool quoted = pos < content_type->len && content_type->ptr[pos] == 34;',
        '        if (quoted) pos++;',
        '        size_t value_start = pos;',
        '        if (quoted) {',
        '            while (pos < content_type->len && content_type->ptr[pos] != 34) pos++;',
        '        } else {',
        "            while (pos < content_type->len && content_type->ptr[pos] != ';' &&",
        "                   content_type->ptr[pos] != ' ' && content_type->ptr[pos] != '\\t') pos++;",
        '        }',
        '        size_t value_end = pos;',
        '        if (quoted && pos < content_type->len) pos++;',
        '        if (name_end - name_start == sizeof(BOUNDARY) - 1 &&',
        '            lumina_tx_equal_ci(content_type->ptr + name_start, name_end - name_start,',
        '                               BOUNDARY, sizeof(BOUNDARY) - 1) &&',
        '            value_end > value_start) {',
        '            *boundary = content_type->ptr + value_start;',
        '            *boundary_len = value_end - value_start;',
        '            return true;',
        '        }',
        "        while (pos < content_type->len && content_type->ptr[pos] != ';') pos++;",
        '    }',
        '    return false;',
        '}',
        '',
        'static int lumina_tx_multipart_boundary_line(const unsigned char *line, size_t line_len,',
        '                                             const unsigned char *boundary,',
        '                                             size_t boundary_len) {',
        "    if (!line || line_len < boundary_len + 2 || line[0] != '-' || line[1] != '-') return 0;",
        '    if (__builtin_memcmp(line + 2, boundary, boundary_len)) return 0;',
        '    size_t pos = boundary_len + 2;',
        '    int kind = 1;',
        "    if (pos + 2 <= line_len && line[pos] == '-' && line[pos + 1] == '-') {",
        '        kind = 2;',
        '        pos += 2;',
        '    }',
        "    while (pos < line_len && (line[pos] == ' ' || line[pos] == '\\t')) pos++;",
        '    return pos == line_len ? kind : 0;',
        '}',
        '',
        'static bool lumina_tx_multipart_field_not_within(',
        '        const LuminaBundle *bundle, const unsigned char *field, size_t field_len,',
        '        const unsigned char *prefix, size_t prefix_len,',
        '        const unsigned char *suffix, size_t suffix_len,',
        '        const unsigned char *allowed, size_t allowed_len, bool lowercase) {',
        '    static const unsigned char NAME[] = "name";',
        '    const unsigned char *boundary = NULL;',
        '    size_t boundary_len = 0;',
        '    if (!field || !field_len ||',
        '        !lumina_tx_multipart_boundary(bundle, &boundary, &boundary_len)) return false;',
        '    for (int var_index = 0; var_index < bundle->count; var_index++) {',
        '        const BundleVar *body = &bundle->vars[var_index];',
        '        if (body->var_type != LUMINA_VAR_BODY || !body->ptr) continue;',
        '        bool in_headers = false;',
        '        bool target_part = false;',
        '        bool read_value = false;',
        '        for (size_t start = 0; start <= body->len;) {',
        '            size_t end = start;',
        "            while (end < body->len && body->ptr[end] != '\\n') end++;",
        '            size_t line_len = end - start;',
        "            if (line_len && body->ptr[start + line_len - 1] == '\\r') line_len--;",
        '            const unsigned char *line = body->ptr + start;',
        '            int boundary_kind = lumina_tx_multipart_boundary_line(',
        '                line, line_len, boundary, boundary_len);',
        '            if (boundary_kind) {',
        '                in_headers = boundary_kind == 1;',
        '                target_part = false;',
        '                read_value = false;',
        '            } else if (in_headers && line_len == 0) {',
        '                in_headers = false;',
        '                read_value = target_part;',
        '            } else if (in_headers) {',
        '                for (size_t pos = 0; pos + sizeof(NAME) - 1 <= line_len; pos++) {',
        '                    if (!lumina_tx_equal_ci(line + pos, sizeof(NAME) - 1,',
        '                                            NAME, sizeof(NAME) - 1)) continue;',
        '                    size_t value = pos + sizeof(NAME) - 1;',
        "                    while (value < line_len && (line[value] == ' ' || line[value] == '\t')) value++;",
        "                    if (value == line_len || line[value] != '=') continue;",
        '                    value++;',
        "                    while (value < line_len && (line[value] == ' ' || line[value] == '\t')) value++;",
        '                    bool quoted = value < line_len && line[value] == 34;',
        '                    if (quoted) value++;',
        '                    size_t value_end = value;',
        "                    while (value_end < line_len && (quoted ? line[value_end] != 34 :",
        "                           line[value_end] != ';' && line[value_end] != ' ' &&",
        "                           line[value_end] != '\t')) value_end++;",
        '                    if (value_end - value == field_len &&',
        '                        !__builtin_memcmp(line + value, field, field_len))',
        '                        target_part = true;',
        '                    break;',
        '                }',
        '            } else if (read_value) {',
        '                return !lumina_tx_wrapped_capture_within(',
        '                    line, line_len, prefix, prefix_len, suffix, suffix_len,',
        '                    allowed, allowed_len, lowercase);',
        '            }',
        '            if (end == body->len) break;',
        '            start = end + 1;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_multipart_header_invalid(',
        '        const LuminaBundle *bundle, LuminaTxPrefixMatcher prefix_matcher,',
        '        LuminaTxPrefixMatcher capture_matcher, LuminaTxValueMatcher value_matcher) {',
        '    const unsigned char *boundary = NULL;',
        '    size_t boundary_len = 0;',
        '    if (!lumina_tx_multipart_boundary(bundle, &boundary, &boundary_len)) return false;',
        '    for (int var_index = 0; var_index < bundle->count; var_index++) {',
        '        const BundleVar *body = &bundle->vars[var_index];',
        '        if (body->var_type != LUMINA_VAR_BODY || !body->ptr) continue;',
        '        bool in_headers = false;',
        '        for (size_t start = 0; start <= body->len;) {',
        '            size_t end = start;',
        "            while (end < body->len && body->ptr[end] != '\\n') end++;",
        '            size_t line_len = end - start;',
        "            if (line_len && body->ptr[start + line_len - 1] == '\\r') line_len--;",
        '            const unsigned char *line = body->ptr + start;',
        '            int boundary_kind = lumina_tx_multipart_boundary_line(',
        '                line, line_len, boundary, boundary_len);',
        '            if (boundary_kind) {',
        '                in_headers = boundary_kind == 1;',
        '            } else if (in_headers && line_len == 0) {',
        '                in_headers = false;',
        '            } else if (in_headers) {',
        '                size_t capture_start = 0;',
        '                size_t capture_end = 0;',
        '                if (prefix_matcher(line, line_len, 0, &capture_start) &&',
        '                    capture_start <= line_len &&',
        '                    capture_matcher(line, line_len, capture_start, &capture_end) &&',
        '                    capture_end >= capture_start && capture_end <= line_len &&',
        '                    !value_matcher(line + capture_start, capture_end - capture_start, 0))',
        '                    return true;',
        '            }',
        '            if (end == body->len) break;',
        '            start = end + 1;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_method_override_parameter(const LuminaBundle *bundle,',
        '                                                const unsigned char *parameter,',
        '                                                size_t parameter_len, uint8_t source_mask,',
        '                                                bool lowercase_value,',
        '                                                LuminaTxValueMatcher matcher) {',
        '    if (!bundle->req_method || bundle->req_method_len == 0) return false;',
        '    bool has_form_body = (source_mask & 2u) && lumina_tx_bundle_has_form_body(bundle);',
        '    for (int var_index = 0; var_index < bundle->count; var_index++) {',
        '        const BundleVar *var = &bundle->vars[var_index];',
        '        bool eligible = ((source_mask & 1u) && var->var_type == LUMINA_VAR_ARGS) ||',
        '                        (has_form_body && var->var_type == LUMINA_VAR_BODY);',
        '        if (!eligible || !var->ptr) continue;',
        '        for (size_t start = 0; start <= var->len;) {',
        '            size_t end = start;',
        "            while (end < var->len && var->ptr[end] != '&') end++;",
        '            size_t equal = start;',
        "            while (equal < end && var->ptr[equal] != '=') equal++;",
        '            unsigned char name[128];',
        '            size_t name_len = 0;',
        '            if (lumina_tx_decode_form_component(var->ptr + start, equal - start,',
        '                                                name, sizeof(name), false, &name_len) &&',
        '                name_len == parameter_len &&',
        '                !__builtin_memcmp(name, parameter, parameter_len)) {',
        '                unsigned char value[256];',
        '                size_t value_len = 0;',
        '                size_t value_start = equal < end ? equal + 1 : end;',
        '                if (lumina_tx_decode_form_component(var->ptr + value_start, end - value_start,',
        '                                                    value, sizeof(value), lowercase_value,',
        '                                                    &value_len) &&',
        '                    matcher(value, value_len, 0) &&',
        '                    !lumina_tx_equal_ci(bundle->req_method, bundle->req_method_len,',
        '                                        value, value_len)) return true;',
        '            }',
        '            if (end == var->len) break;',
        '            start = end + 1;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_authority_matches_host(const unsigned char *authority,',
        '                                             size_t authority_len,',
        '                                             const unsigned char *host, size_t host_len) {',
        '    if (!authority || !host || host_len > authority_len) return false;',
        '    size_t start = authority_len - host_len;',
        '    if (!lumina_tx_equal_ci(authority + start, host_len, host, host_len)) return false;',
        "    return start == 0 || authority[start - 1] == '.';",
        '}',
        '',
        'static bool lumina_tx_value_has_off_domain_authority(const unsigned char *value,',
        '                                                      size_t value_len,',
        '                                                      const BundleVar *host,',
        '                                                      LuminaTxPrefixMatcher matcher) {',
        '    for (size_t offset = 0; offset < value_len; offset++) {',
        '        size_t authority_start = 0;',
        '        if (!matcher(value, value_len, offset, &authority_start)) continue;',
        '        size_t authority_end = authority_start;',
        "        while (authority_end < value_len && value[authority_end] != '/') authority_end++;",
        '        if (!lumina_tx_authority_matches_host(value + authority_start,',
        '                                               authority_end - authority_start,',
        '                                               host->ptr, host->len)) return true;',
        '    }',
        '    return false;',
        '}',
        '',
        'static bool lumina_tx_arg_authority_off_domain(const LuminaBundle *bundle,',
        '                                               uint8_t source_mask, uint32_t host_mask,',
        '                                               LuminaTxPrefixMatcher matcher) {',
        '    const BundleVar *host = lumina_tx_find_header(bundle, host_mask);',
        '    if (!host) return false;',
        '    bool has_form_body = (source_mask & 2u) && lumina_tx_bundle_has_form_body(bundle);',
        '    for (int var_index = 0; var_index < bundle->count; var_index++) {',
        '        const BundleVar *var = &bundle->vars[var_index];',
        '        bool eligible = ((source_mask & 1u) && var->var_type == LUMINA_VAR_ARGS) ||',
        '                        (has_form_body && var->var_type == LUMINA_VAR_BODY);',
        '        if (!eligible || !var->ptr) continue;',
        '        for (size_t start = 0; start <= var->len;) {',
        '            size_t end = start;',
        "            while (end < var->len && var->ptr[end] != '&') end++;",
        '            size_t equal = start;',
        "            while (equal < end && var->ptr[equal] != '=') equal++;",
        '            size_t value_start = equal < end ? equal + 1 : end;',
        '            const unsigned char *raw_value = var->ptr + value_start;',
        '            size_t raw_len = end - value_start;',
        '            if (lumina_tx_value_has_off_domain_authority(raw_value, raw_len, host, matcher))',
        '                return true;',
        '            unsigned char decoded[256];',
        '            size_t decoded_len = 0;',
        '            if (lumina_tx_decode_form_component(raw_value, raw_len, decoded, sizeof(decoded),',
        '                                                false, &decoded_len) &&',
        '                lumina_tx_value_has_off_domain_authority(decoded, decoded_len, host, matcher))',
        '                return true;',
        '            if (end == var->len) break;',
        '            start = end + 1;',
        '        }',
        '    }',
        '    return false;',
        '}',
        '',
        'int lumina_eval_tx_rules(const LuminaBundle *bundle, LuminaRuleState *state) {',
        '    if (!bundle || !state) return 0;',
        '    int threat = 0;',
    ])

    for control_index, control in enumerate(rule_removal_controls):
        value_len = len(control['value'].encode('utf-8'))
        lowercase = 'true' if control['lowercase_value'] else 'false'
        ptr_field = control['ptr_field']
        len_field = control['len_field']
        lines.extend([
            f'    if (bundle->{ptr_field} &&',
            f'        lumina_tx_projected_equal(bundle->{ptr_field}, bundle->{len_field},',
            f'                                  lumina_tx_rule_remove_value_{control_index},',
            f'                                  {value_len}u, {lowercase})) {{',
        ])
        for target_idx in control['target_engine_indices']:
            lines.append(f'        lumina_slab_mark(&state->disabled_rules, {target_idx});')
        lines.append('    }')

    for idx, rule in transaction_rules:
        descriptor = rule['_tx_chain']
        rule_id = int(rule['id'])
        score = int(rule['_tx_score'])
        if descriptor['kind'] in {
                'request-metadata-chain', 'request-method-override-parameter',
                'named-header-decimal-capture-compare',
                'named-header-capture-view-chain',
                'multipart-field-not-within-static-tx',
                'request-body-processor-url-validator',
                'arg-url-authority-off-domain',
                'named-header-capture-not-within-static-tx',
                'named-header-match-not-within-static-tx',
                'header-name-match-within-static-tx',
                'request-basename-capture-within-static-tx',
                'static-tx-gated-utf8-validator',
                'multipart-header-capture-negated-rx', 'named-header-negated-rx'}:
            lines.append(
                f'    if (!lumina_slab_test(&state->completed_rules, {idx})) {{')
        else:
            lines.append(
                f'    if (lumina_slab_test(&state->predicate_rules, {idx}) && '
                f'!lumina_slab_test(&state->completed_rules, {idx})) {{')
        if descriptor['kind'] == 'request-metadata-chain':
            lines.append(f'        bool metadata_match_{idx} = true;')
            for predicate_index, predicate in enumerate(descriptor['predicates']):
                predicate_var = f'metadata_predicate_{idx}_{predicate_index}'
                positive_var = f'metadata_positive_{idx}_{predicate_index}'
                negated = bool(predicate['negated'])
                if predicate['type'] in {'scalar-rx', 'scalar-streq', 'scalar-within'}:
                    ptr_field, len_field = REQUEST_METADATA_FIELDS[predicate['collection']]
                    lines.append(f'        bool {positive_var} = false;')
                    if predicate['type'] == 'scalar-rx':
                        positive_expression = (
                            f'lumina_tx_metadata_rx_{idx}_{predicate_index}('
                            f'bundle->{ptr_field}, bundle->{len_field}, 0) != 0')
                    elif predicate['type'] == 'scalar-streq':
                        value_len = len(predicate['value'].encode('utf-8'))
                        lowercase = 'true' if predicate['lowercase'] else 'false'
                        positive_expression = (
                            f'lumina_tx_projected_equal(bundle->{ptr_field}, bundle->{len_field}, '
                            f'lumina_tx_metadata_value_{idx}_{predicate_index}, {value_len}u, '
                            f'{lowercase})')
                    else:
                        allowed_len = len(predicate['allowed'].encode('utf-8'))
                        lowercase = 'true' if predicate['lowercase'] else 'false'
                        positive_expression = (
                            f'lumina_tx_projected_within(bundle->{ptr_field}, bundle->{len_field}, '
                            f'lumina_tx_metadata_allowed_{idx}_{predicate_index}, {allowed_len}u, '
                            f'{lowercase})')
                    lines.extend([
                        f'        if (bundle->{ptr_field} && bundle->{len_field} > 0)',
                        f'            {positive_var} = {positive_expression};',
                        f'        bool {predicate_var} = bundle->{ptr_field} && bundle->{len_field} > 0 &&',
                        f'            {"!" if negated else ""}{positive_var};',
                    ])
                elif predicate['type'] in {'named-header-rx', 'named-header-pm'}:
                    mask = int(predicate['header_mask'])
                    if predicate['type'] == 'named-header-rx':
                        positive_expression = (
                            f'lumina_tx_metadata_rx_{idx}_{predicate_index}('
                            'header->ptr, header->len, 0) != 0')
                    else:
                        positive_expression = (
                            f'lumina_pm_tx_metadata_pm_{idx}_{predicate_index}('
                            'header->ptr, header->len) != 0')
                    lines.extend([
                        f'        bool {predicate_var} = false;',
                        f'        for (int metadata_header_{idx}_{predicate_index} = 0;',
                        f'             metadata_header_{idx}_{predicate_index} < bundle->count;',
                        f'             metadata_header_{idx}_{predicate_index}++) {{',
                        f'            const BundleVar *header = &bundle->vars[metadata_header_{idx}_{predicate_index}];',
                        f'            if (header->var_type != LUMINA_VAR_HDR || !(header->header_mask & {mask}u))',
                        '                continue;',
                        f'            bool {positive_var} = {positive_expression};',
                        f'            if ({"!" if negated else ""}{positive_var}) {{',
                        f'                {predicate_var} = true;',
                        '                break;',
                        '            }',
                        '        }',
                    ])
                elif predicate['type'] == 'raw-uri-contains':
                    value_len = len(predicate['value'].encode('utf-8'))
                    lines.extend([
                        f'        const BundleVar *metadata_raw_uri_{idx}_{predicate_index} =',
                        '            lumina_tx_raw_uri(bundle);',
                        f'        bool {positive_var} = metadata_raw_uri_{idx}_{predicate_index} &&',
                        '            lumina_tx_projected_contains(',
                        f'                metadata_raw_uri_{idx}_{predicate_index}->ptr,',
                        f'                metadata_raw_uri_{idx}_{predicate_index}->len,',
                        f'                lumina_tx_metadata_raw_uri_needle_{idx}_{predicate_index},',
                        f'                {value_len}u);',
                        f'        bool {predicate_var} = metadata_raw_uri_{idx}_{predicate_index} &&',
                        f'            {"!" if negated else ""}{positive_var};',
                    ])
                elif predicate['type'] == 'request-basename-endswith':
                    value_len = len(predicate['value'].encode('utf-8'))
                    lowercase = 'true' if predicate['lowercase'] else 'false'
                    lines.extend([
                        f'        const unsigned char *metadata_basename_{idx}_{predicate_index} = NULL;',
                        f'        size_t metadata_basename_len_{idx}_{predicate_index} = 0;',
                        f'        bool metadata_basename_present_{idx}_{predicate_index} =',
                        '            lumina_tx_request_basename(bundle,',
                        f'                &metadata_basename_{idx}_{predicate_index},',
                        f'                &metadata_basename_len_{idx}_{predicate_index});',
                        f'        const unsigned char *metadata_basename_view_{idx}_{predicate_index} =',
                        f'            metadata_basename_{idx}_{predicate_index};',
                        f'        size_t metadata_basename_view_len_{idx}_{predicate_index} =',
                        f'            metadata_basename_len_{idx}_{predicate_index};',
                        f'        if (metadata_basename_present_{idx}_{predicate_index} &&',
                        '            lumina_tx_transform_needed(',
                        f'                lumina_tx_metadata_basename_transforms_{idx}_{predicate_index},',
                        f'                metadata_basename_{idx}_{predicate_index},',
                        f'                metadata_basename_len_{idx}_{predicate_index})) {{',
                        f'            if (metadata_basename_len_{idx}_{predicate_index} > lumina_xform_scratch_cap())',
                        f'                metadata_basename_present_{idx}_{predicate_index} = false;',
                        '            else {',
                        f'                unsigned char *metadata_scratch_{idx}_{predicate_index} = lumina_xform_scratch();',
                        f'                __builtin_memcpy(metadata_scratch_{idx}_{predicate_index}, metadata_basename_{idx}_{predicate_index},',
                        f'                                 metadata_basename_len_{idx}_{predicate_index});',
                        f'                metadata_basename_view_len_{idx}_{predicate_index} = lumina_apply_transforms(',
                        f'                    lumina_tx_metadata_basename_transforms_{idx}_{predicate_index},',
                        f'                    metadata_scratch_{idx}_{predicate_index}, metadata_basename_len_{idx}_{predicate_index});',
                        f'                metadata_basename_view_{idx}_{predicate_index} = metadata_scratch_{idx}_{predicate_index};',
                        '            }',
                        '        }',
                        f'        bool {positive_var} = metadata_basename_present_{idx}_{predicate_index} &&',
                        '            lumina_tx_projected_ends_with(',
                        f'                metadata_basename_view_{idx}_{predicate_index},',
                        f'                metadata_basename_view_len_{idx}_{predicate_index},',
                        f'                lumina_tx_metadata_basename_suffix_{idx}_{predicate_index},',
                        f'                {value_len}u, {lowercase});',
                        f'        bool {predicate_var} = metadata_basename_present_{idx}_{predicate_index} &&',
                        f'            {"!" if negated else ""}{positive_var};',
                    ])
                elif predicate['type'] == 'body-length-compare':
                    operators = {
                        '@eq': '==', '@gt': '>', '@ge': '>=', '@lt': '<',
                    }
                    comparison = (
                        f'(lumina_tx_request_body_length(bundle) '
                        f'{operators[predicate["operator"]]} {int(predicate["expected"])}u)')
                    lines.append(
                        f'        bool {predicate_var} = {"!" if negated else ""}{comparison};')
                elif predicate['type'] == 'header-count-eq':
                    if predicate['count_field'] is not None:
                        count_expression = f'bundle->{predicate["count_field"]}'
                    else:
                        count_expression = (
                            f'((bundle->hdr_presence_mask & {int(predicate["presence_mask"])}u) '
                            f'? 1u : 0u)')
                    comparison = f'({count_expression} == {int(predicate["expected"])}u)'
                    lines.append(
                        f'        bool {predicate_var} = {"!" if negated else ""}{comparison};')
                lines.append(f'        metadata_match_{idx} = metadata_match_{idx} && {predicate_var};')
            lines.extend([
                f'        if (metadata_match_{idx}) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'named-header-decimal-capture-compare':
            comparison = {'@lt': 0, '@gt': 1, '@ge': 2, '@eq': 3}[descriptor['operator']]
            lines.extend([
                '        if (lumina_tx_header_decimal_capture_compare(',
                f'                bundle, {int(descriptor["header_mask"])}u,',
                f'                {int(descriptor["separator"])}u, {comparison}u)) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'named-header-capture-view-chain':
            header_mask = int(descriptor['header_mask'])
            boundary = int(descriptor['view']['boundary'])
            lines.extend([
                f'        const BundleVar *capture_view_header_{idx} =',
                f'            lumina_tx_find_header(bundle, {header_mask}u);',
                f'        const unsigned char *capture_view_data_{idx} =',
                f'            capture_view_header_{idx} ? capture_view_header_{idx}->ptr : NULL;',
                f'        size_t capture_view_len_{idx} =',
                f'            capture_view_header_{idx} ? capture_view_header_{idx}->len : 0;',
                f'        bool capture_view_match_{idx} = capture_view_data_{idx} != NULL;',
                f'        if (capture_view_match_{idx} && lumina_tx_transform_needed(',
                f'                lumina_tx_capture_view_transforms_{idx}, capture_view_data_{idx},',
                f'                capture_view_len_{idx})) {{',
                f'            if (capture_view_len_{idx} > lumina_xform_scratch_cap()) {{',
                f'                capture_view_match_{idx} = false;',
                '            } else {',
                '                unsigned char *scratch = lumina_xform_scratch();',
                f'                memcpy(scratch, capture_view_data_{idx}, capture_view_len_{idx});',
                f'                capture_view_len_{idx} = lumina_apply_transforms(',
                f'                    lumina_tx_capture_view_transforms_{idx}, scratch, capture_view_len_{idx});',
                f'                capture_view_data_{idx} = scratch;',
                '            }',
                '        }',
                f'        size_t capture_view_start_{idx} = 0;',
                f'        size_t capture_view_end_{idx} = capture_view_len_{idx};',
            ])
            if descriptor['view']['mode'] == 'prefix-before-byte':
                lines.extend([
                    f'        capture_view_end_{idx} = 0;',
                    f'        while (capture_view_end_{idx} < capture_view_len_{idx} &&',
                    f'               capture_view_data_{idx}[capture_view_end_{idx}] != {boundary}u)',
                    f'            capture_view_end_{idx}++;',
                    f'        capture_view_match_{idx} = capture_view_match_{idx} && capture_view_end_{idx} > 0;',
                ])
            else:
                lines.extend([
                    f'        while (capture_view_start_{idx} < capture_view_len_{idx} &&',
                    f'               capture_view_data_{idx}[capture_view_start_{idx}] != {boundary}u)',
                    f'            capture_view_start_{idx}++;',
                    f'        capture_view_match_{idx} = capture_view_match_{idx} &&',
                    f'            capture_view_start_{idx} < capture_view_len_{idx};',
                ])
            lines.extend([
                f'        const unsigned char *capture_view_{idx} =',
                f'            capture_view_match_{idx} ? capture_view_data_{idx} + capture_view_start_{idx} :',
                '            (const unsigned char *)"";',
                f'        size_t capture_view_size_{idx} =',
                f'            capture_view_end_{idx} - capture_view_start_{idx};',
            ])
            if descriptor['mode'] == 'terminal-capture':
                lines.extend([
                    f'        size_t capture_view_prefix_end_{idx} = 0;',
                    f'        size_t capture_view_capture_end_{idx} = 0;',
                    f'        capture_view_match_{idx} = capture_view_match_{idx} &&',
                    f'            lumina_tx_capture_view_prefix_{idx}(',
                    f'                capture_view_{idx}, capture_view_size_{idx}, 0,',
                    f'                &capture_view_prefix_end_{idx}) &&',
                    f'            lumina_tx_capture_view_capture_{idx}(',
                    f'                capture_view_{idx}, capture_view_size_{idx},',
                    f'                capture_view_prefix_end_{idx}, &capture_view_capture_end_{idx}) &&',
                    f'            capture_view_capture_end_{idx} > capture_view_prefix_end_{idx};',
                ])
                mask_data = (f'capture_view_{idx} + capture_view_prefix_end_{idx}')
                mask_len = (f'capture_view_capture_end_{idx} - capture_view_prefix_end_{idx}')
            else:
                forbidden_len = len(descriptor['forbidden_prefix'].encode('utf-8'))
                lines.extend([
                    f'        capture_view_match_{idx} = capture_view_match_{idx} &&',
                    f'            lumina_tx_capture_view_child_{idx}(',
                    f'                capture_view_{idx}, capture_view_size_{idx}, 0) &&',
                    f'            !(capture_view_size_{idx} >= {forbidden_len}u &&',
                    f'              lumina_tx_projected_equal(capture_view_{idx}, {forbidden_len}u,',
                    f'                  lumina_tx_capture_view_forbidden_{idx}, {forbidden_len}u, false));',
                ])
                mask_data = f'capture_view_{idx}'
                mask_len = f'capture_view_size_{idx}'
            for mask_index in range(len(descriptor['byte_masks'])):
                lines.append(
                    f'        capture_view_match_{idx} = capture_view_match_{idx} && '
                    f'lumina_tx_view_has_mask({mask_data}, {mask_len}, '
                    f'lumina_tx_capture_view_mask_{idx}_{mask_index});')
            lines.extend([
                f'        if (capture_view_match_{idx}) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'arg-name-and-header-absent':
            mask = int(descriptor['header_mask'])
            lines.extend([
                f'        if (!lumina_tx_find_header(bundle, {mask}u)) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'request-body-processor-url-validator':
            processor_len = len(descriptor['processor'].encode('utf-8'))
            lines.extend([
                '        if (lumina_tx_reqbody_processor_url_invalid(',
                f'                bundle, lumina_tx_reqbody_processor_{idx}, {processor_len}u,',
                f'                lumina_tx_body_precondition_{idx})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'multipart-field-not-within-static-tx':
            field_len = len(descriptor['field_name'].encode('utf-8'))
            prefix_len = len(descriptor['value_prefix'].encode('utf-8'))
            suffix_len = len(descriptor['value_suffix'].encode('utf-8'))
            allowed_len = len(descriptor['allowed_value'].encode('utf-8'))
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                '        if (lumina_tx_multipart_field_not_within(',
                f'                bundle, lumina_tx_multipart_field_{idx}, {field_len}u,',
                f'                lumina_tx_multipart_field_prefix_{idx}, {prefix_len}u,',
                f'                lumina_tx_multipart_field_suffix_{idx}, {suffix_len}u,',
                f'                lumina_tx_multipart_field_allowed_{idx}, {allowed_len}u,',
                f'                {lowercase})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'arg-name-and-off-domain-header':
            capture_mask = int(descriptor['capture_header_mask'])
            suffix_mask = int(descriptor['suffix_header_mask'])
            lines.extend([
                f'        const BundleVar *capture_header = lumina_tx_find_header(bundle, {capture_mask}u);',
                f'        const BundleVar *suffix_header = lumina_tx_find_header(bundle, {suffix_mask}u);',
                '        const unsigned char *authority = NULL;',
                '        size_t authority_len = 0;',
                '        if (capture_header && suffix_header &&',
                '            lumina_tx_capture_url_authority(capture_header->ptr, capture_header->len,',
                '                                            &authority, &authority_len) &&',
                '            !lumina_tx_ends_with_ci(authority, authority_len,',
                '                                    suffix_header->ptr, suffix_header->len)) {',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'request-method-override-parameter':
            collection = descriptor['parameter_collection']
            source_mask = {'ARGS': 3, 'ARGS_GET': 1, 'ARGS_POST': 2}[collection]
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                f'        if (lumina_tx_method_override_parameter(bundle, lumina_tx_parameter_{idx},',
                f'                                                sizeof(lumina_tx_parameter_{idx}), {source_mask}u,',
                f'                                                {lowercase}, lumina_tx_value_match_{idx})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'arg-url-authority-off-domain':
            collection = descriptor['parameter_collection']
            source_mask = {'ARGS': 3, 'ARGS_GET': 1, 'ARGS_POST': 2}[collection]
            host_mask = int(descriptor['suffix_header_mask'])
            lines.extend([
                f'        if (lumina_tx_arg_authority_off_domain(bundle, {source_mask}u, {host_mask}u,',
                f'                                               lumina_tx_prefix_match_{idx})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'named-header-capture-not-within-static-tx':
            capture_mask = int(descriptor['capture_header_mask'])
            prefix_len = len(descriptor['value_prefix'].encode('utf-8'))
            suffix_len = len(descriptor['value_suffix'].encode('utf-8'))
            allowed_len = len(descriptor['allowed_value'].encode('utf-8'))
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                f'        const BundleVar *capture_header = lumina_tx_find_header(bundle, {capture_mask}u);',
                '        if (lumina_tx_header_capture_not_within(',
                f'                capture_header, lumina_tx_capture_prefix_{idx},',
                f'                lumina_tx_capture_value_{idx}, lumina_tx_capture_value_prefix_{idx},',
                f'                {prefix_len}u, lumina_tx_capture_value_suffix_{idx}, {suffix_len}u,',
                f'                lumina_tx_capture_allowed_{idx}, {allowed_len}u, {lowercase})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'named-header-match-not-within-static-tx':
            capture_mask = int(descriptor['capture_header_mask'])
            prefix_len = len(descriptor['value_prefix'].encode('utf-8'))
            suffix_len = len(descriptor['value_suffix'].encode('utf-8'))
            allowed_len = len(descriptor['allowed_value'].encode('utf-8'))
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                f'        const BundleVar *capture_header = lumina_tx_find_header(bundle, {capture_mask}u);',
                '        if (lumina_tx_header_match_not_within(',
                f'                capture_header, lumina_tx_match_value_{idx},',
                f'                lumina_tx_match_value_prefix_{idx}, {prefix_len}u,',
                f'                lumina_tx_match_value_suffix_{idx}, {suffix_len}u,',
                f'                lumina_tx_match_allowed_{idx}, {allowed_len}u, {lowercase})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'header-name-match-within-static-tx':
            prefix_len = len(descriptor['value_prefix'].encode('utf-8'))
            suffix_len = len(descriptor['value_suffix'].encode('utf-8'))
            allowed_len = len(descriptor['allowed_value'].encode('utf-8'))
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                '        if (lumina_tx_header_name_within(',
                f'                bundle, lumina_tx_header_name_match_{idx},',
                f'                lumina_tx_header_name_value_prefix_{idx}, {prefix_len}u,',
                f'                lumina_tx_header_name_value_suffix_{idx}, {suffix_len}u,',
                f'                lumina_tx_header_name_allowed_{idx}, {allowed_len}u,',
                f'                {lowercase})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'request-basename-capture-within-static-tx':
            prefix_len = len(descriptor['value_prefix'].encode('utf-8'))
            suffix_len = len(descriptor['value_suffix'].encode('utf-8'))
            allowed_len = len(descriptor['allowed_value'].encode('utf-8'))
            lowercase = 'true' if descriptor['lowercase_value'] else 'false'
            lines.extend([
                '        if (lumina_tx_basename_capture_within(',
                f'                bundle, lumina_tx_basename_capture_prefix_{idx},',
                f'                lumina_tx_basename_capture_value_{idx},',
                f'                lumina_tx_basename_capture_transforms_{idx},',
                f'                lumina_tx_basename_capture_value_prefix_{idx}, {prefix_len}u,',
                f'                lumina_tx_basename_capture_value_suffix_{idx}, {suffix_len}u,',
                f'                lumina_tx_basename_capture_allowed_{idx}, {allowed_len}u,',
                f'                {lowercase})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'static-tx-gated-utf8-validator':
            collection_mask = 0
            for collection in descriptor['collections']:
                collection_mask |= {
                    'REQUEST_FILENAME': 1,
                    'ARGS': 2,
                    'ARGS_NAMES': 4,
                }[collection]
            lines.extend([
                f'        if (lumina_tx_bundle_invalid_utf8(bundle, {collection_mask}u)) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'multipart-header-capture-negated-rx':
            lines.extend([
                '        if (lumina_tx_multipart_header_invalid(',
                f'                bundle, lumina_tx_multipart_prefix_{idx},',
                f'                lumina_tx_multipart_capture_{idx},',
                f'                lumina_tx_multipart_value_positive_{idx})) {{',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        elif descriptor['kind'] == 'named-header-negated-rx':
            header_mask = int(descriptor['header_mask'])
            lines.extend([
                f'        const BundleVar *header = lumina_tx_find_header(bundle, {header_mask}u);',
                f'        if (header && !lumina_tx_header_positive_{idx}(',
                '                header->ptr, header->len, 0)) {',
                f'            int committed = lumina_commit_generated_rule(state, {idx}, {rule_id}, {score},',
                f'                                                          g_short_rule_category[{idx}]);',
                '            if (committed) threat = committed;',
                '        }',
            ])
        lines.append('    }')

    lines.extend(['    return threat;', '}', ''])
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Main compiler
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('rules_dir')
    ap.add_argument('out_dir')
    ap.add_argument('--pl', type=int, default=2, help='target paranoia level (default 2)')
    ap.add_argument('--data-dir', default=None,
                    help='directory containing @pmFromFile .data files')
    ap.add_argument('--chunk-lines', type=int, default=18000,
                    help='approximate generated C line budget per parser rule chunk')
    ap.add_argument('--dfa-state-budget', type=int, default=1536,
                    help='maximum determinized states per @rx rule (default 1536)')
    ap.add_argument('--dfa-table-budget', type=int, default=2 * 1024 * 1024,
                    help='maximum native DFA table bytes per @rx rule (default 2 MiB)')
    ap.add_argument('--dfa-compact-state-budget', type=int, default=4096,
                    help='second-pass state cap for compact regexes (default 4096)')
    ap.add_argument('--dfa-compact-pattern-limit', type=int, default=256,
                    help='maximum pattern characters eligible for the second DFA pass')
    ap.add_argument('--dfa-factored-state-budget', type=int, default=8192,
                    help='maximum states per factored DFA shard (default 8192)')
    ap.add_argument('--dfa-factored-total-table-budget', type=int, default=8 * 1024 * 1024,
                    help='maximum aggregate tables for one factored rule (default 8 MiB)')
    ap.add_argument('--rule-mode', choices=('auto', 'crs-scoring', 'modsecurity'), default='auto',
                    help='auto selects CRS scoring rules when present, otherwise ordinary disruptive SecRules')
    args = ap.parse_args()

    parsed_rules = parse_conf_files(args.rules_dir)
    rule_mode = args.rule_mode
    if rule_mode == 'auto':
        rule_mode = ('crs-scoring' if any(is_score_bearing_detection(r) for r in parsed_rules)
                     else 'modsecurity')
    static_tx_values = collect_static_tx_values(parsed_rules)
    dynamic_tx_producers = collect_dynamic_tx_collection_producers(parsed_rules)
    rules = group_rule_chains(parsed_rules)
    grouped_chain_count = sum(bool(r.get('_chain_members')) for r in rules)
    print(f"[v9] parsed {len(parsed_rules)} statements from {args.rules_dir} "
          f"({grouped_chain_count} chains)")
    print(f"[v9] rule mode: {rule_mode}")

    detection = []
    skipped_gating = 0
    skipped_blocking = 0
    skipped_pl = 0
    skipped_unhandled = 0
    skipped_runtime = 0
    unsupported_rules = []
    pm_scanners = {}  # safe_name -> (name, literals)
    runtime_pm_scanners = {}  # runtime-covered rule id -> safe scanner name
    dfa_rules = 0
    dfa_chain_rules = 0

    for r in rules:
        score_bearing = chain_is_score_bearing(r)
        tx_descriptor = classify_transaction_chain(
            r, static_tx_values, dynamic_tx_producers)
        if tx_descriptor is None:
            tx_descriptor = classify_whole_value_request_rule(r)
        if r['is_gating']:
            skipped_gating += 1
            continue
        if r.get('phase') not in (1, 2):
            skipped_unhandled += 1
            continue
        if r['is_blocking_eval'] and tx_descriptor is None:
            if score_bearing:
                # Dynamic TX collections require transaction state. Compiling
                # their scalar operator against URI/ARGS/BODY changes the
                # operand and creates unconditional false positives.
                skipped_unhandled += 1
                unsupported_rules.append({"rule_id": r.get("id"), "reason": "runtime-tx-state"})
            else:
                skipped_blocking += 1
            continue
        if r['paranoia'] is None or r['paranoia'] > args.pl:
            skipped_pl += 1
            continue
        if r['kind'] != 'SecRule' or not r['operator']:
            skipped_unhandled += 1
            continue
        if not r.get('id'):
            # ID-less SecRule statements are usually chain children. They must
            # be attached to the chain head, never emitted as independent rules.
            skipped_unhandled += 1
            unsupported_rules.append({"rule_id": None, "reason": "chain-child-or-missing-id"})
            continue
        if str(r.get('id')) in RUNTIME_COVERED_IDS:
            runtime_id = str(r.get('id'))
            if (runtime_id in RUNTIME_PM_RULE_IDS and
                    r.get('operator') == '@pmFromFile' and
                    r.get('pm_datafile')):
                df = r['pm_datafile']
                lits = load_pm_literals(df, args.data_dir, args.rules_dir)
                if lits is not None:
                    safe = re.sub(r'[^0-9a-zA-Z]', '_', df)
                    if safe not in pm_scanners:
                        pm_scanners[safe] = (df, lits)
                    runtime_pm_scanners[runtime_id] = safe
            skipped_runtime += 1
            continue
        # Only compile rules that actually contribute to the anomaly score.
        # Pure setup/sampling rules (e.g. 901420 -> TX:sampling_rnd100) only set
        # unrelated TX vars and, as raw-buffer matchers, false-positive against
        # request data. In CRS, every real detection rule increments
        # tx.anomaly_score (or a *_score), so this is the sound discriminator.
        if not is_compilable_detection(r, rule_mode):
            skipped_unhandled += 1
            continue
        if (tx_descriptor is None and
                not r.get('binding_contract', {}).get('recognized', False)):
            skipped_unhandled += 1
            unsupported_rules.append({
                "rule_id": r.get("id"),
                "reason": "unknown-collection",
                "details": r.get('binding_contract', {}).get('unsupported', []),
            })
            continue
        if tx_descriptor is not None:
            r['_tx_chain'] = tx_descriptor
            r['_tx_score'] = r['score']
            r['_tx_chain_member_count'] = len(r.get('_chain_members', []))
            r.pop('_chain_members', None)
            r['chain'] = False
            r['score'] = 0

        if (r.get('_tx_chain') or {}).get('kind') in {
                'request-metadata-chain', 'request-method-override-parameter',
                'named-header-decimal-capture-compare',
                'named-header-capture-view-chain',
                'multipart-field-not-within-static-tx',
                'request-body-processor-url-validator',
                'arg-url-authority-off-domain',
                'named-header-capture-not-within-static-tx',
                'named-header-match-not-within-static-tx',
                'header-name-match-within-static-tx',
                'request-basename-capture-within-static-tx',
                'static-tx-gated-utf8-validator',
                'multipart-header-capture-negated-rx', 'named-header-negated-rx'}:
            r['_fn'] = (
                f"int lumina_scan_rule_{r['id']}(const unsigned char *data, size_t len, size_t offset) {{\n"
                f"    (void)data; (void)len; (void)offset; return 0;\n}}\n"
            )
            r['_force_pos0'] = True
            r['_regex_backend'] = 'transaction-runtime-dfa'
            detection.append(r)
            continue

        if r.get('_chain_members'):
            capture_compare_reason = two_capture_compare_chain_reason(r)
            if capture_compare_reason is None:
                try:
                    r['_fn'] = emit_two_capture_compare_chain(
                        r,
                        state_budget=args.dfa_state_budget,
                        table_budget=args.dfa_table_budget,
                    )
                except DfaUnsupportedRegex as exc:
                    skipped_unhandled += 1
                    unsupported_rules.append({
                        "rule_id": r.get("id"),
                        "reason": "two-capture-compare-chain-dfa-budget",
                        "details": str(exc),
                    })
                    continue
                r['_force_pos0'] = True
                r['_regex_backend'] = 'dfa-two-capture-compare-chain'
                dfa_chain_rules += 1
                detection.append(r)
                continue
            phrase_reason = same_buffer_phrase_chain_reason(r)
            if phrase_reason is None:
                literals = load_pm_literals(
                    r['pm_datafile'], args.data_dir, args.rules_dir)
                if literals is None:
                    skipped_unhandled += 1
                    unsupported_rules.append({
                        "rule_id": r.get("id"),
                        "reason": "chain-pm-data-file-not-found",
                        "details": r.get("pm_datafile"),
                    })
                    continue
                try:
                    r['_fn'] = emit_same_buffer_phrase_chain(
                        r, literals,
                        state_budget=args.dfa_state_budget,
                        table_budget=args.dfa_table_budget,
                    )
                except DfaUnsupportedRegex as exc:
                    skipped_unhandled += 1
                    unsupported_rules.append({
                        "rule_id": r.get("id"),
                        "reason": "phrase-chain-dfa-budget",
                        "details": str(exc),
                    })
                    continue
                r['_force_pos0'] = True
                r['_regex_backend'] = (
                    'phrase-rx-same-buffer-chain'
                    if any(member.get('operator') == '@rx'
                           for member in r['_chain_members'][1:]) else
                    'phrase-same-buffer-chain'
                )
                if r['_regex_backend'] == 'phrase-rx-same-buffer-chain':
                    dfa_chain_rules += 1
                detection.append(r)
                continue
            terminal_capture_reason = terminal_capture_same_value_chain_reason(r)
            if terminal_capture_reason is None:
                try:
                    r['_fn'] = emit_terminal_capture_same_value_chain(
                        r,
                        state_budget=args.dfa_state_budget,
                        table_budget=args.dfa_table_budget,
                    )
                except DfaUnsupportedRegex as exc:
                    skipped_unhandled += 1
                    unsupported_rules.append({
                        "rule_id": r.get("id"),
                        "reason": "terminal-capture-chain-dfa-budget",
                        "details": str(exc),
                    })
                    continue
                r['_force_pos0'] = True
                r['_regex_backend'] = 'dfa-terminal-capture-chain'
                dfa_chain_rules += 1
                detection.append(r)
                continue
            reason = same_buffer_rx_chain_reason(r)
            if reason is not None:
                skipped_unhandled += 1
                unsupported_rules.append({
                    "rule_id": r.get("id"),
                    "reason": reason,
                    "phrase_reason": phrase_reason,
                    "terminal_capture_reason": terminal_capture_reason,
                    "capture_compare_reason": capture_compare_reason,
                    "chain_members": len(r['_chain_members']),
                })
                continue
            try:
                r['_fn'] = emit_same_buffer_rx_chain(
                    r,
                    state_budget=args.dfa_state_budget,
                    table_budget=args.dfa_table_budget,
                )
            except DfaUnsupportedRegex as exc:
                skipped_unhandled += 1
                unsupported_rules.append({
                    "rule_id": r.get("id"),
                    "reason": "chain-dfa-budget",
                    "details": str(exc),
                })
                continue
            r['_force_pos0'] = True
            if r.get('_chain_global_xml'):
                r['_regex_backend'] = (
                    'nfa-seeded-bounded-xml-collection-chain'
                    if r.get('_chain_seeded_nfa') else
                    ('nfa-bounded-xml-collection-chain'
                     if r.get('_chain_bounded_nfa') else
                    ('dfa-recursive-xml-collection-chain'
                     if r.get('_chain_recursive_dfa') else
                     'dfa-xml-collection-chain')))
            else:
                r['_regex_backend'] = (
                    'nfa-seeded-bounded-same-buffer-chain'
                    if r.get('_chain_seeded_nfa') else
                    ('nfa-bounded-same-buffer-chain'
                     if r.get('_chain_bounded_nfa') else
                    ('dfa-recursive-same-buffer-chain'
                     if r.get('_chain_recursive_dfa') else
                     'dfa-same-buffer-chain')))
            dfa_chain_rules += 1
            detection.append(r)
            continue
        if r['negated']:
            if r['operator'] == '@within':
                r['_fn'] = emit_within(r['id'], r['pattern'], negated=True)
                detection.append(r)
            elif r['operator'] == '@rx' and negated_rx_runtime_safe(r):
                try:
                    r['_fn'] = emit_negated_rx(
                        r['id'], r['pattern'],
                        state_budget=args.dfa_state_budget,
                        table_budget=args.dfa_table_budget,
                    )
                except DfaUnsupportedRegex as exc:
                    skipped_unhandled += 1
                    unsupported_rules.append({
                        "rule_id": r.get("id"),
                        "reason": "negated-dfa-budget",
                        "details": str(exc),
                    })
                    continue
                r['_force_pos0'] = True
                r['_regex_backend'] = 'negated-dfa'
                dfa_rules += 1
                detection.append(r)
            else:
                # Negation is emitted only when the runtime can bind one exact
                # variable value. Unsupported collections remain an explicit
                # manifest gap rather than falling back to a generic buffer.
                skipped_unhandled += 1
                unsupported_rules.append({
                    "rule_id": r.get("id"),
                    "reason": "unsafe-negated-operator-binding",
                    "operator": r.get("operator"),
                    "details": r.get('binding_contract', {}).get('unsupported', []),
                })
            continue
        if r['operator'] == '@rx':
            if not r['id']:
                continue
            try:
                transform_dag_lowered = False
                call_dictionary_plan = shared_call_dictionary_plan(r['pattern'])
                fixed_mask_plan = fixed_mask_dictionary_plan(r['pattern'])
                scheme_host_plan = scheme_host_classifier_plan(r['pattern'])
                suffix_prefilter_plan = (
                    fixed_mask_suffix_prefilter_plan(r['pattern'])
                    if len(r['pattern']) > args.dfa_compact_pattern_limit
                    else None)
                compact_prefix_plan = compact_prefix_fixed_suffix_plan(
                    r['pattern'], suffix_prefilter_plan,
                    state_budget=args.dfa_factored_state_budget,
                    table_budget=args.dfa_table_budget,
                )
                if standalone_call_dictionary_profitable(call_dictionary_plan):
                    router_code, wrappers, _, _ = emit_shared_call_trie_router(
                        [(r, call_dictionary_plan)], f"rule_{r['id']}")
                    fn = router_code + '\n' + wrappers[r['id']]
                    r['_regex_backend'] = 'standalone-finite-call-trie'
                    r['_force_pos0'] = True
                    r['_standalone_call_trie'] = True
                    transform_dag_lowered = True
                elif fixed_mask_plan is not None:
                    fn = emit_fixed_mask_dictionary(r['id'], fixed_mask_plan)
                    r['_regex_backend'] = 'seeded-fixed-mask-dictionary'
                    r['_force_pos0'] = True
                    transform_dag_lowered = True
                elif scheme_host_plan is not None:
                    fn = emit_scheme_host_classifier(r['id'], scheme_host_plan)
                    r['_regex_backend'] = 'scheme-host-classifier'
                    transform_dag_lowered = True
                elif compact_prefix_plan is not None:
                    fn = emit_compact_prefix_fixed_suffix_dfa(
                        r['id'], r['pattern'], compact_prefix_plan,
                        state_budget=args.dfa_factored_state_budget,
                        table_budget=args.dfa_table_budget,
                    )
                    r['_regex_backend'] = 'compact-prefix-dfa-fixed-suffix'
                    r['_force_pos0'] = True
                    transform_dag_lowered = True
                    dfa_rules += 1
                elif suffix_prefilter_plan is not None:
                    fn = emit_seeded_suffix_prefilter_recursive(
                        r['id'], r['pattern'], suffix_prefilter_plan,
                        state_budget=args.dfa_factored_state_budget,
                        table_budget=args.dfa_table_budget,
                        total_table_budget=args.dfa_factored_total_table_budget,
                    )
                    r['_regex_backend'] = 'seeded-suffix-prefilter-recursive-exact'
                    r['_force_pos0'] = True
                    transform_dag_lowered = True
                    dfa_rules += 1
                elif transform_requires_offset_zero(r.get('transforms')):
                    # One typed-value dispatch feeds one candidate-routed DAG.
                    # This preserves unanchored search after transforms whose
                    # output has no useful raw first-byte relation.
                    try:
                        if not r.get('multimatch'):
                            raise DfaUnsupportedRegex(
                                'alternative router reserved for multiMatch views')
                        fn = emit_top_level_alternative_dfa_router(
                            r['id'], r['pattern'],
                            state_budget=args.dfa_factored_state_budget,
                            table_budget=args.dfa_table_budget,
                            total_table_budget=args.dfa_factored_total_table_budget,
                        )
                        r['_regex_backend'] = 'dfa-transform-alternative-router'
                        r['_force_pos0'] = True
                        transform_dag_lowered = True
                        dfa_rules += 1
                    except DfaUnsupportedRegex:
                        try:
                            fn = emit_recursive_factored_concat_dfa(
                                r['id'], r['pattern'],
                                state_budget=args.dfa_factored_state_budget,
                                table_budget=args.dfa_table_budget,
                                total_table_budget=args.dfa_factored_total_table_budget,
                            )
                            r['_regex_backend'] = 'dfa-transform-candidate-dag'
                            r['_force_pos0'] = True
                            transform_dag_lowered = True
                            dfa_rules += 1
                        except DfaUnsupportedRegex:
                            # Retain the ordinary selective backend when both
                            # exact candidate routers exceed generated-size caps.
                            pass
                if transform_dag_lowered:
                    pass
                elif repeated_token_threshold_plan(r['pattern']) is not None:
                    fn = emit_repeated_token_threshold(r['id'], r['pattern'])
                    r['_regex_backend'] = 'repeated-token-threshold-microkernel'
                    r['_force_pos0'] = True
                elif crlf_command_grammar_plan(r['pattern']) is not None:
                    fn = emit_crlf_command_grammar(r['id'], r['pattern'])
                    r['_regex_backend'] = 'crlf-command-grammar-microkernel'
                elif r.get('_tx_chain') or requires_dfa(r['pattern']):
                    dfa_pattern, is_search_dfa = dfa_search_lowering(r['pattern'])
                    try:
                        fn = emit_dfa_c(r['id'], dfa_pattern,
                                        state_budget=args.dfa_state_budget,
                                        table_budget=args.dfa_table_budget)
                        r['_regex_backend'] = 'dfa-search' if is_search_dfa else 'dfa'
                        if is_search_dfa:
                            r['_force_pos0'] = True
                        dfa_rules += 1
                    except DfaUnsupportedRegex as primary_error:
                        recovered_original_dfa = False
                        if is_search_dfa:
                            try:
                                fn = emit_dfa_c(
                                    r['id'], r['pattern'],
                                    state_budget=args.dfa_state_budget,
                                    table_budget=args.dfa_table_budget,
                                )
                                r['_regex_backend'] = 'dfa-all-offsets'
                                r['_no_anywhere'] = True
                                dfa_rules += 1
                                recovered_original_dfa = True
                            except DfaUnsupportedRegex:
                                pass
                        if not recovered_original_dfa:
                            try:
                                fn = emit_gap_split_dfa(
                                    r['id'], r['pattern'],
                                    state_budget=args.dfa_state_budget,
                                    table_budget=args.dfa_table_budget,
                                )
                                r['_regex_backend'] = 'dfa-gap-split'
                                dfa_rules += 1
                            except DfaUnsupportedRegex:
                                recovered_factored = False
                                if len(r['pattern']) > args.dfa_compact_pattern_limit:
                                    try:
                                        fn = emit_recursive_factored_concat_dfa(
                                            r['id'], r['pattern'],
                                            state_budget=args.dfa_factored_state_budget,
                                            table_budget=args.dfa_table_budget,
                                            total_table_budget=args.dfa_factored_total_table_budget,
                                        )
                                        r['_regex_backend'] = 'dfa-recursive-factored-dag'
                                        r['_force_pos0'] = True
                                        dfa_rules += 1
                                        recovered_factored = True
                                    except DfaUnsupportedRegex:
                                        pass
                                if (not recovered_factored and
                                        len(r['pattern']) > args.dfa_compact_pattern_limit):
                                    try:
                                        fn = emit_factored_branch_concat_dfa(
                                            r['id'], r['pattern'],
                                            state_budget=args.dfa_factored_state_budget,
                                            table_budget=args.dfa_table_budget,
                                            total_table_budget=args.dfa_factored_total_table_budget,
                                        )
                                        r['_regex_backend'] = 'dfa-factored-branch-concat'
                                        dfa_rules += 1
                                        recovered_factored = True
                                    except DfaUnsupportedRegex:
                                        pass
                                if not recovered_factored:
                                    retry_compact = (
                                        len(r['pattern']) <= args.dfa_compact_pattern_limit and
                                        'state budget' in str(primary_error).lower()
                                    )
                                    if retry_compact:
                                        try:
                                            fn = emit_dfa_c(
                                                r['id'], dfa_pattern,
                                                state_budget=args.dfa_compact_state_budget,
                                                table_budget=args.dfa_table_budget,
                                            )
                                            r['_regex_backend'] = ('dfa-search-compact-escalated'
                                                                   if is_search_dfa else
                                                                   'dfa-compact-escalated')
                                            if is_search_dfa:
                                                r['_force_pos0'] = True
                                            dfa_rules += 1
                                        except DfaUnsupportedRegex:
                                            try:
                                                fn = emit_bitset_nfa_c(r['id'], r['pattern'], state_budget=64)
                                                r['_regex_backend'] = 'nfa-bitset-fallback'
                                                dfa_rules += 1
                                            except DfaUnsupportedRegex:
                                                fn = emit_procedural_fallback(r['id'], r['pattern'])
                                                r['_regex_backend'] = 'procedural-fallback'
                                    else:
                                        try:
                                            fn = emit_bitset_nfa_c(r['id'], r['pattern'], state_budget=64)
                                            r['_regex_backend'] = 'nfa-bitset-fallback'
                                            dfa_rules += 1
                                        except DfaUnsupportedRegex:
                                            fn = emit_procedural_fallback(r['id'], r['pattern'])
                                            r['_regex_backend'] = 'procedural-fallback'
                else:
                    fn = emit_procedural_fallback(r['id'], r['pattern'])
                    r['_regex_backend'] = 'procedural'
            except Exception as e:
                skipped_unhandled += 1
                # log a few
                if skipped_unhandled <= 20:
                    print(f"  skip @rx id={r.get('id')}: {e}")
                continue
            r['_fn'] = fn
            detection.append(r)
        elif r['operator'] == '@pm':
            # inline @pm (phrase set). Whole-buffer-safe positive operator.
            if not r['id'] or not r['pattern']:
                skipped_unhandled += 1
                continue
            lits = [p for p in r['pattern'].split() if p]
            if not lits:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_inline_pm(r['id'], lits)
            detection.append(r)
        elif r['operator'] in ('@contains',):
            if not r['id'] or not r['pattern']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_contains(r['id'], r['pattern'])
            detection.append(r)
        elif r['operator'] == '@detectXSS':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_detect(r['id'], 'lumina_scan_xss')
            detection.append(r)
        elif r['operator'] == '@detectSQLi':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_detect_sqli(r['id'])
            r['_regex_backend'] = 'lumina-sqli-owned'
            detection.append(r)
        elif r['operator'] == '@validateByteRange':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_validate_byte_range(r['id'], r['pattern'])
            detection.append(r)
        elif r['operator'] == '@validateUtf8Encoding':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_validate_utf8(r['id'])
            detection.append(r)
        elif r['operator'] == '@validateUrlEncoding':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_validate_url_encoding(r['id'])
            detection.append(r)
        elif r['operator'] == '@pmFromFile':
            if not r['id'] or not r['pm_datafile']:
                continue
            df = r['pm_datafile']
            lits = load_pm_literals(df, args.data_dir, args.rules_dir)
            if lits is None:
                skipped_unhandled += 1
                continue
            safe = re.sub(r'[^0-9a-zA-Z]', '_', df)
            if safe not in pm_scanners:
                pm_scanners[safe] = (df, lits)
            r['_pm_safe'] = safe
            r['_fn'] = (
                f"int lumina_scan_rule_{r['id']}(const unsigned char *data, size_t len, size_t offset) {{\n"
                f"    if (lumina_pm_{safe}(data + offset, len - offset)) return {r['id']};\n    return 0;\n}}\n"
            )
            detection.append(r)
        elif r['operator'] in ('@eq', '@gt', '@ge', '@lt'):
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_numeric_compare(r['id'], r['operator'], r['pattern'])
            detection.append(r)
        elif r['operator'] == '@streq':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_streq(r['id'], r['pattern'])
            detection.append(r)
        elif r['operator'] == '@within':
            if not r['id']:
                skipped_unhandled += 1
                continue
            r['_fn'] = emit_within(r['id'], r['pattern'], negated=False)
            detection.append(r)
        else:
            skipped_unhandled += 1
            unsupported_rules.append({
                "rule_id": r.get("id"),
                "reason": "unsupported-operator",
                "operator": r.get("operator"),
            })

    # de-dup by id (chains only emit the head; we treat each SecRule as one rule)
    by_id = {}
    for r in detection:
        by_id.setdefault(r['id'], r)
    detection = list(by_id.values())
    # HPP parameter-counter rules match ANY non-empty input -> never a block signal.
    HPP_SKIP = {'921170'}
    detection = [r for r in detection if r['id'] not in HPP_SKIP]
    shared_call_stats = lower_shared_call_routers(detection)
    rule_removal_controls, control_unsupported = collect_rule_removal_controls(
        parsed_rules, detection)
    unsupported_rules.extend(control_unsupported)
    rule_target_removal_controls, target_control_unsupported = (
        collect_rule_target_removal_controls(parsed_rules, detection))
    unsupported_rules.extend(target_control_unsupported)
    print(f"[v9] detection rules (PL<={args.pl}): {len(detection)}  "
          f"| gating={skipped_gating} blocking={skipped_blocking} "
          f"runtime-covered={skipped_runtime} pl-filtered={skipped_pl} "
          f"unhandled={skipped_unhandled} "
          f"| pm-scanners={len(pm_scanners)} dfa-rules={dfa_rules} "
          f"dfa-chain-rules={dfa_chain_rules}")
    print(
        "[v9] shared call routers: "
        f"routers={shared_call_stats['routers']} rules={shared_call_stats['rules']} "
        f"words={shared_call_stats['words']} nodes={shared_call_stats['nodes']} "
        f"edges={shared_call_stats['edges']}")

    # Build routing tables
    n = len(detection)
    NWORDS = (n + 63) // 64
    if NWORDS < 2:
        NWORDS = 2
    mask = [[0] * NWORDS for _ in range(256)]
    scope_entries = []
    collection_entries = []
    cat_entries = []
    par_entries = []
    vt_entries = []
    hdr_entries = []
    score_entries = []
    rule_id_entries = []
    multimatch_entries = []
    shared_router_entries = []
    table_entries = []
    scope_values = []
    vt_values = []
    hdr_values = []
    fn_chunks = []       # list of (chunk_index, code)
    pm_chunk = []

    # phrase scanners first
    for safe, (name, lits) in pm_scanners.items():
        code, _ = gen_phrase_scanner(name, lits)
        pm_chunk.append(code)
    for runtime_id in sorted(RUNTIME_PM_RULE_IDS, key=int):
        safe = runtime_pm_scanners.get(runtime_id)
        if safe:
            pm_chunk.append(
                f"int lumina_pm_runtime_{runtime_id}(const unsigned char *data, size_t len) {{\n"
                f"    return lumina_pm_{safe}(data, len);\n"
                "}"
            )
        else:
            pm_chunk.append(
                f"int lumina_pm_runtime_{runtime_id}(const unsigned char *data, size_t len) {{\n"
                "    (void)data; (void)len;\n"
                "    return 0;\n"
                "}"
            )

    # Distribute rule functions by generated C line budget, not by rule count.
    # CRS regexes vary wildly in emitted size; a 200-rule chunk produced a
    # 200k-line translation unit that makes clang -O1/-O2 impractical.
    rule_chunks = []
    cur = []
    cur_lines = 0
    for r in detection:
        fn_lines = r['_fn'].count('\n') + 1
        if cur and cur_lines + fn_lines > args.chunk_lines:
            rule_chunks.append(cur)
            cur = []
            cur_lines = 0
        cur.append(r)
        cur_lines += fn_lines
    if cur:
        rule_chunks.append(cur)

    for ci, chunk in enumerate(rule_chunks):
        code = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n#include \"generated/crs_short_rules.h\"\n#include \"luminawaf.h\"\n\n"
        for r in chunk:
            code += r['_fn'] + "\n"
        fn_chunks.append(code)

    pm_source = (
        "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n"
        "#include \"generated/crs_short_rules.h\"\n#include \"luminawaf.h\"\n\n" +
        "\n\n".join(pm_chunk) + "\n")
    tx_c = emit_transaction_rules_c(
        detection, rule_removal_controls, rule_target_removal_controls)
    # Intern across every generated matcher family. A transaction-chain DFA
    # and a direct SecRule DFA may therefore share identical immutable tables
    # while retaining separate inlinable walkers and accept behavior.
    resource_units = fn_chunks + [pm_source, tx_c]
    resource_units, shared_tables_header, shared_tables_source, shared_table_stats = (
        intern_generated_const_arrays(resource_units))
    fn_chunks = resource_units[:-2]
    pm_source, tx_c = resource_units[-2:]
    print(
        "[v9] shared AOT tables: "
        f"groups={shared_table_stats['shared_arrays']} "
        f"references={shared_table_stats['replaced_arrays']} "
        f"reclaimed-rodata={shared_table_stats['reclaimed_bytes']} bytes")

    for idx, r in enumerate(detection):
        scope_str, scope_value, vtype, col_mask_str = map_scope(r['variables'])
        hdr_value = map_header_mask(r['variables'])
        table_entries.append(f"    lumina_scan_rule_{r['id']},")
        scope_entries.append(f"    {scope_str},")
        collection_entries.append(f"    {col_mask_str},")
        cat_entries.append(f"    {CAT.get(r['category'], CAT['GEN'])},")
        par_entries.append(f"    {r['paranoia']},")
        vt_entries.append(f"    {vtype},")
        hdr_entries.append(f"    {hdr_value},")  # hdr_mask: 0 = applies to all headers (simplified)
        score_entries.append(f"    {r['score']},")
        rule_id_entries.append(f"    {int(r['id'])},")
        multimatch_entries.append(f"    {'true' if r.get('multimatch') else 'false'},")
        shared_router_entries.append(
            f"    {int(r.get('_shared_router', -1)) + 1 if '_shared_router' in r else 0},")
        scope_values.append(scope_value)
        vt_values.append(vtype)
        hdr_values.append(hdr_value)
        # first-byte routing
        try:
            fbs = (set(range(256)) if r.get('_force_pos0') else
                   transform_aware_first_bytes(r['pattern'], r.get('transforms'))
                   if r['operator'] == '@rx' else set(range(256)))
        except Exception:
            fbs = set(range(256))
        for b in fbs:
            if idx < 64 * NWORDS:
                mask[b][idx >> 6] |= (1 << (idx & 63))

    n = len(detection)

    anywhere_mask = [0] * NWORDS
    empty_mask = [0] * NWORDS
    request_body_mask = [0] * NWORDS
    xml_container_mask = [0] * NWORDS
    for idx in range(n):
        if detection[idx].get('operator') == '@rx' and not detection[idx].get('_tx_chain'):
            positive_empty = regex_matches_empty(detection[idx].get('pattern') or '')
            if positive_empty != bool(detection[idx].get('negated')):
                empty_mask[idx >> 6] |= 1 << (idx & 63)
        if any(binding.collection == 'REQUEST_BODY' and not binding.excluded
               for binding in detection[idx].get('bindings', [])):
            request_body_mask[idx >> 6] |= 1 << (idx & 63)
        if str(detection[idx].get('_regex_backend', '')).endswith('xml-collection-chain'):
            xml_container_mask[idx >> 6] |= 1 << (idx & 63)
        if detection[idx].get('_no_anywhere'):
            continue
        bit = 1 << (idx & 63)
        word = idx >> 6
        if all(mask[b][word] & bit for b in range(256)):
            anywhere_mask[word] |= bit

    active_pos0 = [[[0 for _ in range(NWORDS)] for _ in range(VAR_TYPE_SLOTS)] for _ in range(8)]
    active_posN = [[[0 for _ in range(NWORDS)] for _ in range(VAR_TYPE_SLOTS)] for _ in range(8)]
    for scope_idx in range(8):
        for var_idx in range(VAR_TYPE_SLOTS):
            var_bit = (1 << var_idx) if var_idx != 5 else 0
            for idx in range(n):
                ok = (scope_values[idx] & scope_idx) != 0
                ok = ok and (var_idx == 5 or (vt_values[idx] & var_bit) != 0)
                if ok:
                    active_pos0[scope_idx][var_idx][idx >> 6] |= (1 << (idx & 63))
            for word in range(NWORDS):
                active_posN[scope_idx][var_idx][word] = active_pos0[scope_idx][var_idx][word] & ~anywhere_mask[word]

    # Header selectors constrain only REQUEST_HEADERS values. Slot zero contains
    # generic/custom-header rules; slots 1..N contain generic rules plus rules
    # selecting the corresponding known header bit. This removes the runtime
    # O(rule_count) rebuild while preserving mixed bindings such as
    # ARGS|REQUEST_HEADERS:User-Agent through the ordinary non-header tables.
    header_active_pos0 = [
        [[0 for _ in range(NWORDS)] for _ in range(HEADER_SELECTOR_SLOTS)]
        for _ in range(8)
    ]
    header_active_posN = [
        [[0 for _ in range(NWORDS)] for _ in range(HEADER_SELECTOR_SLOTS)]
        for _ in range(8)
    ]
    header_var_bit = 1 << 3  # LUMINA_VAR_HDR
    for scope_idx in range(8):
        for selector_slot in range(HEADER_SELECTOR_SLOTS):
            selector_mask = 0 if selector_slot == 0 else 1 << (selector_slot - 1)
            for idx in range(n):
                if (scope_values[idx] & scope_idx) == 0:
                    continue
                if (vt_values[idx] & header_var_bit) == 0:
                    continue
                rule_header_mask = hdr_values[idx]
                if rule_header_mask != 0 and (rule_header_mask & selector_mask) == 0:
                    continue
                header_active_pos0[scope_idx][selector_slot][idx >> 6] |= 1 << (idx & 63)
            for word in range(NWORDS):
                header_active_posN[scope_idx][selector_slot][word] = (
                    header_active_pos0[scope_idx][selector_slot][word] & ~anywhere_mask[word]
                )

    def emit_word_array(words):
        return "{" + ", ".join(f"0x{x:016x}ULL" for x in words) + "}"
    # ---- emit chunks ----
    os.makedirs(args.out_dir, exist_ok=True)
    # clean old parser_rules chunks
    for f in glob.glob(os.path.join(args.out_dir, 'parser_rules_*.c')):
        os.remove(f)

    # tables chunk
    # NOTE: lumina_dispatch_rule (transform-aware per-rule dispatch) is emitted
    # HERE by the translator so regeneration is self-contained. Previously it
    # was a hand-patch on top of the generated parser_rules_0000.c and got
    # clobbered on every regen (recurring hazard). Behaviour is identical to the
    # previous hand-patch: seq NONE -> direct call (zero copy). Transformed
    # rules retain a bounded raw prefix and separately derive its transformed
    # length. This preserves anchors, word boundaries and local decode context
    # without re-transforming the full request prefix for every candidate.
    DISPATCH_SRC = (
        "#include <string.h>\n"
        "#include \"lumina_transforms.h\"\n"
        "#include \"generated/crs_transform_mask.h\"\n\n"
        "static int g_anywhere_p[LUMINA_SHORT_RULE_COUNT];\n"
        "static int g_anywhere_p_init = 0;\n"
        "typedef struct {\n"
        "    const unsigned char *data;\n"
        "    size_t len;\n"
        "    size_t offset;\n"
        "    size_t transformed_len;\n"
        "    size_t transformed_offset;\n"
        "    uint8_t sequence_id;\n"
        "    uint8_t valid;\n"
        "} LuminaTransformViewCache;\n"
        "#define LUMINA_TRANSFORM_VIEW_SLOTS 8u\n"
        "static __thread LuminaTransformViewCache "
        "g_transform_view_cache[LUMINA_TRANSFORM_VIEW_SLOTS];\n"
        "typedef struct {\n"
        "    const unsigned char *data;\n"
        "    size_t len;\n"
        "    uint64_t dirty[LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS];\n"
        "    uint8_t valid;\n"
        "} LuminaTransformInputClass;\n"
        "static __thread LuminaTransformInputClass g_transform_input_class;\n"
        "void lumina_reset_transform_view_cache(void) {\n"
        "    for (size_t i = 0; i < LUMINA_TRANSFORM_VIEW_SLOTS; ++i)\n"
        "        g_transform_view_cache[i].valid = 0;\n"
        "    g_transform_input_class.valid = 0;\n"
        "}\n\n"
        "static inline int lumina_transform_sequence_may_change(\n"
        "        uint8_t sequence_id, const unsigned char *data, size_t len) {\n"
        "    LuminaTransformInputClass *input = &g_transform_input_class;\n"
        "    if (!input->valid || input->data != data || input->len != len) {\n"
        "        for (size_t word = 0; word < LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS; ++word)\n"
        "            input->dirty[word] = g_transform_sequence_always_dirty[word];\n"
        "        for (size_t i = 0; i < len; ++i) {\n"
        "            const uint64_t *byte_dirty = g_transform_sequence_dirty_by_byte[data[i]];\n"
        "            for (size_t word = 0; word < LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS; ++word)\n"
        "                input->dirty[word] |= byte_dirty[word];\n"
        "        }\n"
        "        input->data = data;\n"
        "        input->len = len;\n"
        "        input->valid = 1;\n"
        "    }\n"
        "    return (input->dirty[sequence_id >> 6] >> (sequence_id & 63)) & 1u;\n"
        "}\n\n"
        "static inline int rule_is_anywhere_p(int idx) {\n"
        "    if (!g_anywhere_p_init) {\n"
        "        for (int i = 0; i < LUMINA_SHORT_RULE_COUNT; i++) {\n"
        "            int w = i >> 6; uint64_t bit = 1ULL << (i & 63);\n"
        "            int all = 1;\n"
        "            for (int b = 0; b < 256; b++) if (!(g_short_rule_mask[b][w] & bit)) { all = 0; break; }\n"
        "            g_anywhere_p[i] = all;\n"
        "        }\n"
        "        g_anywhere_p_init = 1;\n"
        "    }\n"
        "    return g_anywhere_p[idx];\n"
        "}\n\n"
        "int lumina_dispatch_rule(int idx, const unsigned char *data, size_t len, size_t offset) {\n"
        "    const LuminaTransformId *seq = g_rule_transform_seq[idx];\n"
        "    if (seq[0] == LUMINA_T_NONE) return g_short_rule_table[idx](data, len, offset);\n"
        "    const uint8_t sequence_id = g_rule_transform_seq_id[idx];\n"
        "    if (!lumina_transform_sequence_may_change(sequence_id, data, len))\n"
        "        return g_short_rule_table[idx](data, len, offset);\n"
        "    const size_t context_start = offset > 32 ? offset - 32 : 0;\n"
        "    const size_t raw_prefix = offset - context_start;\n"
        "    size_t n = len - context_start; size_t transformed_offset = 0;\n"
        "    const size_t cache_slot = sequence_id & (LUMINA_TRANSFORM_VIEW_SLOTS - 1u);\n"
        "    LuminaTransformViewCache *cache = &g_transform_view_cache[cache_slot];\n"
        "    uint8_t *s = lumina_xform_scratch_slot(cache_slot);\n"
        "    if (n > lumina_xform_scratch_cap()) return g_short_rule_table[idx](data, len, offset);\n"
        "    if (g_short_rule_multimatch[idx]) {\n"
        "        cache->valid = 0;\n"
        "        int r = g_short_rule_table[idx](data, len, offset);\n"
        "        if (r) return r;\n"
        "        for (int i = 0; i < 12 && seq[i] != LUMINA_T_NONE; i++) {\n"
        "            LuminaTransformId sub_seq[12];\n"
        "            for (int j = 0; j <= i; j++) sub_seq[j] = seq[j];\n"
        "            sub_seq[i+1] = LUMINA_T_NONE;\n"
        "            n = len - context_start; transformed_offset = 0;\n"
        "            bool cmdline_boundary_fold = false;\n"
        "            if (raw_prefix > 0) {\n"
        "                memcpy(s, data + context_start, raw_prefix);\n"
        "                transformed_offset = lumina_apply_transforms(sub_seq, s, raw_prefix);\n"
        "                for (int j = 0; j <= i; j++) {\n"
        "                    if (sub_seq[j] == LUMINA_T_CMDLINE && transformed_offset > 0 &&\n"
        "                        s[transformed_offset - 1] == ' ' &&\n"
        "                        (data[offset] == '/' || data[offset] == '(')) {\n"
        "                        cmdline_boundary_fold = true;\n"
        "                        break;\n"
        "                    }\n"
        "                }\n"
        "            }\n"
        "            memcpy(s, data + context_start, n);\n"
        "            n = lumina_apply_transforms(sub_seq, s, n);\n"
        "            transformed_offset -= cmdline_boundary_fold;\n"
        "            if (transformed_offset <= n) {\n"
        "                r = g_short_rule_table[idx](s, n, transformed_offset);\n"
        "                if (r) return r;\n"
        "            }\n"
        "        }\n"
        "        return 0;\n"
        "    }\n"
        "    if (cache->valid && cache->data == data && cache->len == len &&\n"
        "        cache->offset == offset && cache->sequence_id == sequence_id) {\n"
        "        return g_short_rule_table[idx](\n"
        "            s, cache->transformed_len, cache->transformed_offset);\n"
        "    }\n"
        "    cache->valid = 0;\n"
        "    bool cmdline_boundary_fold = false;\n"
        "    if (raw_prefix > 0) {\n"
        "        memcpy(s, data + context_start, raw_prefix);\n"
        "        transformed_offset = lumina_apply_transforms(seq, s, raw_prefix);\n"
        "        for (int i = 0; i < 12 && seq[i] != LUMINA_T_NONE; i++) {\n"
        "            if (seq[i] == LUMINA_T_CMDLINE && transformed_offset > 0 &&\n"
        "                s[transformed_offset - 1] == ' ' &&\n"
        "                (data[offset] == '/' || data[offset] == '(')) {\n"
        "                cmdline_boundary_fold = true;\n"
        "                break;\n"
        "            }\n"
        "        }\n"
        "    }\n"
        "    memcpy(s, data + context_start, n);\n"
        "    n = lumina_apply_transforms(seq, s, n);\n"
        "    transformed_offset -= cmdline_boundary_fold;\n"
        "    if (transformed_offset > n) return 0;\n"
        "    cache->data = data;\n"
        "    cache->len = len;\n"
        "    cache->offset = offset;\n"
        "    cache->transformed_len = n;\n"
        "    cache->transformed_offset = transformed_offset;\n"
        "    cache->sequence_id = sequence_id;\n"
        "    cache->valid = 1;\n"
        "    return g_short_rule_table[idx](s, n, transformed_offset);\n"
        "}\n\n"
    )
    tables_code = "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n#include \"generated/crs_short_rules.h\"\n#include \"luminawaf.h\"\n\n"
    tables_code += DISPATCH_SRC
    tables_code += "extern int lumina_scan_rule_0(const unsigned char*,size_t,size_t);\n"
    for r in detection:
        tables_code += f"extern int lumina_scan_rule_{r['id']}(const unsigned char*,size_t,size_t);\n"
    for safe in pm_scanners:
        tables_code += f"extern int lumina_pm_{safe}(const unsigned char*,size_t);\n"
    tables_code += f"\nconst uint64_t g_short_rule_mask[256][{NWORDS}] = {{\n"
    for i in range(256):
        cols = ", ".join(f"0x{mask[i][w]:016x}ULL" for w in range(NWORDS))
        tables_code += f"    {{{cols}}},\n"
    tables_code += "};\n\n"
    tables_code += f"const uint64_t g_short_rule_anywhere_mask[{NWORDS}] = {emit_word_array(anywhere_mask)};\n\n"
    tables_code += f"const uint64_t g_short_rule_empty_mask[{NWORDS}] = {emit_word_array(empty_mask)};\n\n"
    tables_code += f"const uint64_t g_short_rule_request_body_mask[{NWORDS}] = {emit_word_array(request_body_mask)};\n\n"
    tables_code += f"const uint64_t g_short_rule_xml_container_mask[{NWORDS}] = {emit_word_array(xml_container_mask)};\n\n"
    tables_code += f"const uint64_t g_short_rule_active_pos0[8][{VAR_TYPE_SLOTS}][{NWORDS}] = {{\n"
    for scope_idx in range(8):
        tables_code += "    {\n"
        for var_idx in range(VAR_TYPE_SLOTS):
            tables_code += f"        {emit_word_array(active_pos0[scope_idx][var_idx])},\n"
        tables_code += "    },\n"
    tables_code += "};\n\n"
    tables_code += f"const uint64_t g_short_rule_header_active_pos0[8][{HEADER_SELECTOR_SLOTS}][{NWORDS}] = {{\n"
    for scope_idx in range(8):
        tables_code += "    {\n"
        for selector_slot in range(HEADER_SELECTOR_SLOTS):
            tables_code += f"        {emit_word_array(header_active_pos0[scope_idx][selector_slot])},\n"
        tables_code += "    },\n"
    tables_code += "};\n\n"
    tables_code += f"const uint64_t g_short_rule_header_active_posN[8][{HEADER_SELECTOR_SLOTS}][{NWORDS}] = {{\n"
    for scope_idx in range(8):
        tables_code += "    {\n"
        for selector_slot in range(HEADER_SELECTOR_SLOTS):
            tables_code += f"        {emit_word_array(header_active_posN[scope_idx][selector_slot])},\n"
        tables_code += "    },\n"
    tables_code += "};\n\n"
    tables_code += f"const uint64_t g_short_rule_active_posN[8][{VAR_TYPE_SLOTS}][{NWORDS}] = {{\n"
    for scope_idx in range(8):
        tables_code += "    {\n"
        for var_idx in range(VAR_TYPE_SLOTS):
            tables_code += f"        {emit_word_array(active_posN[scope_idx][var_idx])},\n"
        tables_code += "    },\n"
    tables_code += "};\n\n"
    tables_code += f"const uint32_t g_short_rule_scope[{n}] = {{\n" + "\n".join(scope_entries) + "\n};\n"
    tables_code += f"const uint64_t g_short_rule_collection_mask[{n}] = {{\n" + "\n".join(collection_entries) + "\n};\n"
    tables_code += f"const uint8_t g_short_rule_category[{n}] = {{\n" + "\n".join(cat_entries) + "\n};\n"
    tables_code += f"const bool g_short_rule_multimatch[{n}] = {{\n" + "\n".join(multimatch_entries) + "\n};\n"
    tables_code += f"const uint8_t g_short_rule_paranoia[{n}] = {{\n" + "\n".join(par_entries) + "\n};\n"
    tables_code += f"const uint16_t g_short_rule_var_type[{n}] = {{\n" + "\n".join(vt_entries) + "\n};\n"
    tables_code += f"const uint32_t g_short_rule_hdr_mask[{n}] = {{\n" + "\n".join(hdr_entries) + "\n};\n"
    tables_code += f"const uint8_t g_short_rule_score[{n}] = {{\n" + "\n".join(score_entries) + "\n};\n"
    tables_code += f"const int g_short_rule_id[{n}] = {{\n" + "\n".join(rule_id_entries) + "\n};\n"
    tables_code += f"const uint8_t g_short_rule_shared_router[{n}] = {{\n" + "\n".join(shared_router_entries) + "\n};\n"
    tables_code += f"int (*g_short_rule_table[{n}])(const unsigned char*,size_t,size_t) = {{\n" + "\n".join(table_entries) + "\n};\n"
    shared_router_count = shared_call_stats['routers']
    shared_router_masks = [[0] * NWORDS for _ in range(shared_router_count)]
    shared_router_members = [[] for _ in range(shared_router_count)]
    for idx, rule in enumerate(detection):
        if '_shared_router' not in rule:
            continue
        router = int(rule['_shared_router'])
        local_bit = int(rule['_shared_router_bit'])
        shared_router_masks[router][idx >> 6] |= 1 << (idx & 63)
        shared_router_members[router].append((idx, local_bit))
    if shared_router_count:
        tables_code += (
            f"const uint64_t g_shared_router_rule_mask[{shared_router_count}]"
            f"[{NWORDS}] = {{\n")
        for words in shared_router_masks:
            tables_code += f"    {emit_word_array(words)},\n"
        tables_code += "};\n\n"
        for router in range(shared_router_count):
            tables_code += (
                f"extern uint64_t lumina_shared_call_router_{router}_match("
                "const unsigned char*,size_t,size_t,uint64_t);\n")
        tables_code += (
            "\nvoid lumina_dispatch_shared_router(int router_id, "
            "const unsigned char *data, size_t len, size_t offset, "
            "const uint64_t *wanted, uint64_t *matched) {\n"
            f"    for (int word = 0; word < {NWORDS}; ++word) matched[word] = 0;\n"
            "    switch (router_id) {\n")
        for router, members in enumerate(shared_router_members):
            tables_code += f"    case {router}: {{\n        uint64_t local_wanted = 0;\n"
            for idx, local_bit in members:
                tables_code += (
                    f"        if (wanted[{idx >> 6}] & "
                    f"(1ULL << {idx & 63})) local_wanted |= 1ULL << {local_bit};\n")
            tables_code += (
                f"        uint64_t hits = lumina_shared_call_router_{router}_match("
                "data, len, offset, local_wanted);\n")
            for idx, local_bit in members:
                tables_code += (
                    f"        if (hits & (1ULL << {local_bit})) "
                    f"matched[{idx >> 6}] |= 1ULL << {idx & 63};\n")
            tables_code += "        break;\n    }\n"
        tables_code += "    default: break;\n    }\n}\n\n"
    # master scan: first-byte-routed over the table; returns (id | paranoia<<24)
    tables_code += f"""
int lumina_scan_generated(const unsigned char *data, size_t len, size_t offset,
                          uint32_t context_flag, uint8_t var_type,
                          uint32_t header_mask, uint64_t collection_mask) {{
    uint32_t var_bit = (var_type < {VAR_TYPE_SLOTS} && var_type != 5)
                           ? (1u << var_type)
                           : 0u;
    for (size_t i = offset; i < len; i++) {{
        uint8_t fb = data[i];
        for (int word = 0; word < {NWORDS}; word++) {{
            uint64_t w = g_short_rule_mask[fb][word];
            while (w) {{
                int bit = __builtin_ctzll(w);
                int idx = word*64 + bit;
                if ((g_short_rule_scope[idx] & context_flag) &&
                    (var_type == 5 || (g_short_rule_var_type[idx] & var_bit)) &&
                    (var_type != 3 || g_short_rule_hdr_mask[idx] == 0 ||
                     (g_short_rule_hdr_mask[idx] & header_mask)) &&
                    (g_short_rule_collection_mask[idx] == 0 || (g_short_rule_collection_mask[idx] & collection_mask))) {{
                    int rid = g_short_rule_table[idx](data, len, i);
                    if (rid) return (rid & 0xFFFFFF) | (g_short_rule_paranoia[idx] << 24);
                }}
                w &= w - 1;
            }}
        }}
    }}
    return 0;
}}
"""
    # write chunks: tables as parser_rules_0000.c; pm scanners as parser_rules_0001.c
    with open(os.path.join(args.out_dir, 'parser_rules_0000.c'), 'w') as f:
        f.write(tables_code)
    with open(os.path.join(args.out_dir, 'parser_rules_0001.c'), 'w') as f:
        f.write(pm_source)
    with open(os.path.join(args.out_dir, 'parser_rules_0002.c'), 'w') as f:
        f.write(shared_tables_source)

    generated_dir = os.path.join(args.out_dir, 'generated')
    os.makedirs(generated_dir, exist_ok=True)
    with open(os.path.join(generated_dir, 'crs_shared_tables.h'), 'w') as f:
        f.write(shared_tables_header)

    # ---- emit typed request-level chain evaluator ----
    with open(os.path.join(args.out_dir, 'crs_tx_rules.c'), 'w') as f:
        f.write("\n".join(line.rstrip() for line in tx_c.splitlines()) + "\n")


    # rule function chunks parser_rules_0003..
    for ci, code in enumerate(fn_chunks):
        with open(os.path.join(args.out_dir, f'parser_rules_{ci+3:04d}.c'), 'w') as f:
            f.write(code)

    # ---- regenerate parser_input.c (lumina_waf_scan delegates to master scan) ----
    nchunks = 3 + len(fn_chunks)
    inp = "#include <stddef.h>\n#include <string.h>\n#include \"generated/crs_short_rules.h\"\n#include \"luminawaf.h\"\n\n"
    inp += "int lumina_scan_generated(const unsigned char *data, size_t len, size_t offset, uint32_t context_flag, uint8_t var_type, uint32_t header_mask, uint64_t collection_mask);\n\n"
    inp += "/* v9: single master scan over the bitmask-routed table; flat p99, branchless routing. */\n"
    inp += "int lumina_waf_scan(const unsigned char *str, size_t len) {\n"
    inp += "    uint32_t scope = LUMINA_SCOPE_URI | LUMINA_SCOPE_HEADERS | LUMINA_SCOPE_BODY;\n"
    inp += "    int enc = lumina_scan_generated(str, len, 0, scope, 5, 0, 0);\n"
    inp += "    return enc & 0xFFFFFF;\n"
    inp += "}\n\n"
    with open(os.path.join(args.out_dir, 'parser_input.c'), 'w') as f:
        f.write(inp)

    # ---- crs_short_rules.h (self-contained) ----
    hdr = "#ifndef CRS_SHORT_RULES_H\n#define CRS_SHORT_RULES_H\n"
    hdr += "#include <stdint.h>\n#include <stddef.h>\n#include <stdbool.h>\n\n"
    # Single source of truth: the runtime scan loop bound MUST equal NWORDS,
    # otherwise it silently under-scans the mask array and misses rules.
    hdr += f"#define CRS_SHORT_RULE_MASK_DIMS {NWORDS}\n"
    hdr += f"#define LUMINA_SHORT_RULE_COUNT {n}\n"
    hdr += f"#define LUMINA_GENERATED_VAR_TYPE_SLOTS {VAR_TYPE_SLOTS}\n"
    hdr += f"#define LUMINA_HEADER_SELECTOR_SLOTS {HEADER_SELECTOR_SLOTS}\n"
    hdr += f"extern const uint64_t g_short_rule_mask[256][{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_anywhere_mask[{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_empty_mask[{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_request_body_mask[{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_xml_container_mask[{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_active_pos0[8][LUMINA_GENERATED_VAR_TYPE_SLOTS][{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_active_posN[8][LUMINA_GENERATED_VAR_TYPE_SLOTS][{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_header_active_pos0[8][LUMINA_HEADER_SELECTOR_SLOTS][{NWORDS}];\n"
    hdr += f"extern const uint64_t g_short_rule_header_active_posN[8][LUMINA_HEADER_SELECTOR_SLOTS][{NWORDS}];\n"
    hdr += f"extern const uint32_t g_short_rule_scope[{n}];\n"
    hdr += f"extern const uint64_t g_short_rule_collection_mask[{n}];\n"
    hdr += f"extern const uint8_t g_short_rule_category[{n}];\n"
    hdr += f"extern const bool g_short_rule_multimatch[{n}];\n"
    hdr += f"extern const uint8_t g_short_rule_paranoia[{n}];\n"
    hdr += f"extern const uint16_t g_short_rule_var_type[{n}];\n"
    hdr += f"extern const uint32_t g_short_rule_hdr_mask[{n}];\n"
    hdr += f"extern const uint8_t g_short_rule_score[{n}];\n"
    hdr += f"extern const int g_short_rule_id[{n}];\n"
    hdr += f"extern const uint8_t g_short_rule_shared_router[{n}];\n"
    hdr += f"#define LUMINA_SHARED_ROUTER_COUNT {shared_router_count}\n"
    if shared_router_count:
        hdr += (
            f"extern const uint64_t g_shared_router_rule_mask[{shared_router_count}]"
            f"[{NWORDS}];\n"
            "extern void lumina_dispatch_shared_router(int router_id, "
            "const unsigned char *data, size_t len, size_t offset, "
            "const uint64_t *wanted, uint64_t *matched);\n")
    hdr += f"extern int (*g_short_rule_table[{n}])(const unsigned char*,size_t,size_t);\n"
    hdr += "extern void lumina_reset_transform_view_cache(void);\n"
    hdr += "extern int lumina_scan_generated(const unsigned char *data, size_t len, size_t offset, uint32_t context_flag, uint8_t var_type, uint32_t header_mask, uint64_t collection_mask);\n"
    hdr += "extern int lumina_waf_scan(const unsigned char *str, size_t len);\n"
    for safe in pm_scanners:
        hdr += f"extern int lumina_pm_{safe}(const unsigned char *data, size_t len);\n"
    for runtime_id in sorted(RUNTIME_PM_RULE_IDS, key=int):
        hdr += f"extern int lumina_pm_runtime_{runtime_id}(const unsigned char *data, size_t len);\n"
    hdr += "#endif\n"
    gen_dir = os.path.join(args.out_dir, 'generated')
    os.makedirs(gen_dir, exist_ok=True)
    with open(os.path.join(gen_dir, 'crs_short_rules.h'), 'w') as f:
        f.write(hdr)

    manifest = {
        "schema": "lumina-waf-rule-manifest-v1",
        "generator": "tools/sidecar_translator.py",
        "lumina_provenance": {
            "registry_version": LUMINA_MARKER_REGISTRY_VERSION,
            "build_tag": LUMINA_MARKER_BUILD_TAG,
            "generator_fingerprint": LUMINA_MARKER_GENERATOR_FINGERPRINT,
            "marker_policy": "passive-forensic-no-telemetry",
        },
        "rules_dir": os.path.abspath(args.rules_dir),
        "data_dir": os.path.abspath(args.data_dir or args.rules_dir),
        "paranoia_level": args.pl,
        "rule_mode": rule_mode,
        "dfa_state_budget": args.dfa_state_budget,
        "dfa_table_budget": args.dfa_table_budget,
        "dfa_factored_state_budget": args.dfa_factored_state_budget,
        "dfa_factored_total_table_budget": args.dfa_factored_total_table_budget,
        "dfa_compact_state_budget": args.dfa_compact_state_budget,
        "dfa_compact_pattern_limit": args.dfa_compact_pattern_limit,
        "short_rule_count": n,
        "mask_words": NWORDS,
        "runtime_covered_rule_ids": sorted(int(x) for x in RUNTIME_COVERED_IDS),
        "generated_rule_ids": [int(r["id"]) for r in detection],
        "generated_rules": [
            {
                "engine_idx": idx,
                "rule_id": int(r["id"]),
                "phase": r.get("phase"),
                "paranoia": r.get("paranoia"),
                "operator": ("!" if r.get("negated") else "") + (r.get("operator") or ""),
                "variables": r.get("variables") or "",
                "bindings": [asdict(binding) for binding in r.get("bindings", [])],
                "binding_contract": r.get("binding_contract", {}),
                "category": r.get("category") or "GEN",
                "score": r.get("score"),
                "chain": bool(r.get("chain")),
                "chain_member_count": r.get(
                    "_tx_chain_member_count", len(r.get("_chain_members", []))),
                "transaction_kind": (r.get("_tx_chain") or {}).get("kind"),
                "transaction_score": r.get("_tx_score"),
                "regex_backend": r.get("_regex_backend"),
            }
            for idx, r in enumerate(detection)
        ],
        "rule_removal_controls": rule_removal_controls,
        "rule_target_removal_controls": rule_target_removal_controls,
        "skipped": {
            "gating": skipped_gating,
            "blocking": skipped_blocking,
            "runtime_covered": skipped_runtime,
            "pl_filtered": skipped_pl,
            "unhandled": skipped_unhandled,
            "unsupported_rules": unsupported_rules,
        },
    }
    with open(os.path.join(gen_dir, "rule_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")

    print(f"[v9] wrote {nchunks} rule chunks + tables + parser_input.c + crs_short_rules.h")

if __name__ == '__main__':
    main()
