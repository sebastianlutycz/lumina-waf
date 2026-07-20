#!/usr/bin/env python3
"""Emit per-rule ModSecurity transform sequences from rule_manifest.json.

Rows are indexed by engine idx, matching the translator's generated rule order.
The data is AOT-compiled into the runtime; no CRS parsing happens at request time.
"""

from __future__ import annotations

import argparse
import glob
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "src/generated"
DEFAULT_MANIFEST = GEN / "rule_manifest.json"
MAX_TRANSFORMS = 12


TRANSFORM_DIRTY_BYTES = {
    "LUMINA_T_LOWERCASE": set(range(ord("A"), ord("Z") + 1)),
    "LUMINA_T_URL_DECODE": {ord("%"), ord("+")},
    "LUMINA_T_URL_DECODE_UNI": {ord("%"), ord("+")},
    "LUMINA_T_HTML_ENTITY_DECODE": {ord("&")},
    "LUMINA_T_REMOVE_NULLS": {0},
    "LUMINA_T_JS_DECODE": {ord("\\")},
    "LUMINA_T_CSS_DECODE": {ord("\\")},
    "LUMINA_T_NORMALIZE_PATH": {ord("/"), ord(".")},
    "LUMINA_T_NORMALIZE_PATH_WIN": {ord("/"), ord("."), ord("\\")},
    "LUMINA_T_COMPRESS_WS": {ord(c) for c in " \t\n\r\f\v"},
    "LUMINA_T_REMOVE_WS": {ord(c) for c in " \t\n\r\f\v"},
    "LUMINA_T_UTF8_TO_UNICODE": set(range(0x80, 0x100)),
    "LUMINA_T_REPLACE_COMMENTS": {ord("<"), ord("/")},
    "LUMINA_T_CMDLINE": (
        set(range(ord("A"), ord("Z") + 1)) |
        {ord(c) for c in "\\\"'^ \t\r\n\v\f,;/()"} |
        {0xA0}
    ),
    "LUMINA_T_ESCAPE_SEQ_DECODE": {ord("\\")},
    "LUMINA_T_REMOVE_COMMENTS_CHAR": {
        ord("/"), ord("*"), ord("<"), ord("-"), ord("#")
    },
}

TRANSFORM_ALWAYS_DIRTY = {
    "LUMINA_T_BASE64_DECODE",
    "LUMINA_T_LENGTH",
}


NAME2ENUM = {
    "lowercase": "LUMINA_T_LOWERCASE",
    "url_decode": "LUMINA_T_URL_DECODE",
    "urldecode": "LUMINA_T_URL_DECODE",
    "url_decode_uni": "LUMINA_T_URL_DECODE_UNI",
    "urldecodeuni": "LUMINA_T_URL_DECODE_UNI",
    "html_entity_decode": "LUMINA_T_HTML_ENTITY_DECODE",
    "htmlentitydecode": "LUMINA_T_HTML_ENTITY_DECODE",
    "remove_nulls": "LUMINA_T_REMOVE_NULLS",
    "removenulls": "LUMINA_T_REMOVE_NULLS",
    "js_decode": "LUMINA_T_JS_DECODE",
    "jsdecode": "LUMINA_T_JS_DECODE",
    "css_decode": "LUMINA_T_CSS_DECODE",
    "cssdecode": "LUMINA_T_CSS_DECODE",
    "normalise_path": "LUMINA_T_NORMALIZE_PATH",
    "normalisepath": "LUMINA_T_NORMALIZE_PATH",
    "normalize_path": "LUMINA_T_NORMALIZE_PATH",
    "normalizepath": "LUMINA_T_NORMALIZE_PATH",
    "normalize_path_win": "LUMINA_T_NORMALIZE_PATH_WIN",
    "normalizepathwin": "LUMINA_T_NORMALIZE_PATH_WIN",
    "compress_whitespace": "LUMINA_T_COMPRESS_WS",
    "compresswhitespace": "LUMINA_T_COMPRESS_WS",
    "remove_whitespace": "LUMINA_T_REMOVE_WS",
    "removewhitespace": "LUMINA_T_REMOVE_WS",
    "replace_comments": "LUMINA_T_REPLACE_COMMENTS",
    "replacecomments": "LUMINA_T_REPLACE_COMMENTS",
    "utf8_to_unicode": "LUMINA_T_UTF8_TO_UNICODE",
    "utf8tounicode": "LUMINA_T_UTF8_TO_UNICODE",
    "cmd_line": "LUMINA_T_CMDLINE",
    "cmdline": "LUMINA_T_CMDLINE",
    "base64decode": "LUMINA_T_BASE64_DECODE",
    "escape_seq_decode": "LUMINA_T_ESCAPE_SEQ_DECODE",
    "escapeseqdecode": "LUMINA_T_ESCAPE_SEQ_DECODE",
    "length": "LUMINA_T_LENGTH",
    "remove_comments_char": "LUMINA_T_REMOVE_COMMENTS_CHAR",
    "removecommentschar": "LUMINA_T_REMOVE_COMMENTS_CHAR",
}

NEXT_DIRECTIVE = re.compile(r"\n[ \t]*(?:SecRule|SecAction|SecMarker|SecComponentSignature)\b")


def quoted_regions(statement: str) -> list[str]:
    """Extract ModSecurity quoted fields without reading trailing comments."""
    regions: list[str] = []
    index = 0
    while index < len(statement):
        if statement[index] != '"':
            index += 1
            continue
        index += 1
        value: list[str] = []
        escaped = False
        while index < len(statement):
            char = statement[index]
            if char == '"' and not escaped:
                index += 1
                break
            value.append(char)
            if char == '\\' and not escaped:
                escaped = True
            else:
                escaped = False
            index += 1
        regions.append(''.join(value))
    return regions


def parse_blocks(text: str) -> list[tuple[int, list[str]]]:
    blocks: list[tuple[int, list[str]]] = []
    for match in re.finditer(r"(?m)^[ \t]*SecRule\b", text):
        start = match.start()
        nxt = NEXT_DIRECTIVE.search(text, pos=start + 1)
        end = nxt.start() if nxt else len(text)
        segment = text[start:end]
        quotes = quoted_regions(segment)
        if len(quotes) < 2:
            continue
        actions = quotes[1]
        id_match = re.search(r"\bid\s*:\s*(\d+)", actions)
        if not id_match:
            continue
        rid = int(id_match.group(1))
        transforms = re.findall(r"\bt\s*:\s*([A-Za-z0-9_]+)", actions)
        blocks.append((rid, transforms))
    return blocks


def build_sequences(ids: list[int], rules_dir: Path) -> tuple[dict[int, list[str]], set[int]]:
    id2idx = {rid: idx for idx, rid in enumerate(ids)}
    seqs = {rid: [] for rid in ids}
    found: set[int] = set()

    for filename in sorted(glob.glob(str(rules_dir / "*.conf"))):
        text = Path(filename).read_text(encoding="utf-8", errors="ignore")
        for rid, raw_transforms in parse_blocks(text):
            norm = [t.lower().replace(" ", "") for t in raw_transforms]
            # SecRule transforms inherit from SecDefaultAction, not from the
            # preceding SecRule. The CRS comparator defaults contain no
            # transforms, and t:none resets that default for the current rule.
            effective: list[str] = []
            for name in norm:
                if name == "none":
                    effective.clear()
                    continue
                enum = NAME2ENUM.get(name)
                if enum:
                    effective.append(enum)
            if rid in id2idx:
                seqs[rid] = effective[: MAX_TRANSFORMS - 1]
                found.add(rid)
    return seqs, found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="translator rule manifest")
    parser.add_argument("--rules-dir", default=None, help="CRS rules directory; default from manifest")
    parser.add_argument("--out-dir", default=str(GEN), help="generated output directory")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    ids = [int(x) for x in manifest["generated_rule_ids"]]
    rules_dir = Path(args.rules_dir or manifest["rules_dir"])
    out_dir = Path(args.out_dir)
    n = len(ids)

    seqs, found = build_sequences(ids, rules_dir)
    sequence_ids: dict[tuple[str, ...], int] = {(): 0}
    rule_sequence_ids: list[int] = []
    for rid in ids:
        key = tuple(seqs[rid])
        if key not in sequence_ids:
            sequence_ids[key] = len(sequence_ids)
        rule_sequence_ids.append(sequence_ids[key])
    if len(sequence_ids) > 256:
        raise ValueError(
            f"transform sequence inventory exceeds uint8_t ABI: {len(sequence_ids)}")
    sequence_mask_words = (len(sequence_ids) + 63) // 64
    sequences_by_id: list[tuple[str, ...]] = [()] * len(sequence_ids)
    for sequence, sequence_id in sequence_ids.items():
        sequences_by_id[sequence_id] = sequence
    dirty_by_byte = [[0] * sequence_mask_words for _ in range(256)]
    always_dirty = [0] * sequence_mask_words
    for sequence_id, sequence in enumerate(sequences_by_id):
        dirty_bytes: set[int] = set()
        sequence_always_dirty = False
        for transform in sequence:
            if transform in TRANSFORM_ALWAYS_DIRTY:
                sequence_always_dirty = True
                break
            transform_dirty = TRANSFORM_DIRTY_BYTES.get(transform)
            if transform_dirty is None:
                sequence_always_dirty = True
                break
            dirty_bytes.update(transform_dirty)
        word = sequence_id >> 6
        bit = 1 << (sequence_id & 63)
        if sequence_always_dirty:
            always_dirty[word] |= bit
        else:
            for byte in dirty_bytes:
                dirty_by_byte[byte][word] |= bit
    out_dir.mkdir(parents=True, exist_ok=True)
    h_path = out_dir / "crs_transform_mask.h"
    c_path = out_dir / "crs_transform_mask.c"

    h_path.write_text(
        "/* AUTO-GENERATED by tools/gen_transform_mask.py. Do not edit. */\n"
        "#ifndef LUMINA_CRS_TRANSFORM_MASK_H\n"
        "#define LUMINA_CRS_TRANSFORM_MASK_H\n"
        '#include "lumina_transforms.h"\n'
        f"#define LUMINA_TRANSFORM_SEQUENCE_COUNT {len(sequence_ids)}\n"
        f"#define LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS {sequence_mask_words}\n"
        "/* Per-rule ordered ModSecurity t: transform sequence, indexed by engine idx. */\n"
        "extern const LuminaTransformId g_rule_transform_seq[LUMINA_SHORT_RULE_COUNT][12];\n"
        "extern const uint8_t g_rule_transform_seq_id[LUMINA_SHORT_RULE_COUNT];\n"
        "extern const uint64_t "
        "g_transform_sequence_dirty_by_byte[256][LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS];\n"
        "extern const uint64_t "
        "g_transform_sequence_always_dirty[LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS];\n"
        "#endif\n",
        encoding="utf-8",
    )

    lines: list[str] = []
    lines.append("/* AUTO-GENERATED by tools/gen_transform_mask.py. Do not edit. */")
    lines.append('#include "generated/crs_transform_mask.h"')
    lines.append("")
    lines.append("const LuminaTransformId g_rule_transform_seq[LUMINA_SHORT_RULE_COUNT][12] = {")
    for idx, rid in enumerate(ids):
        row = seqs[rid]
        if row:
            values = row + ["LUMINA_T_NONE"]
            lines.append(f"    /* [{idx}] CRS {rid} */ {{{', '.join(values)}}},")
        else:
            lines.append(f"    /* [{idx}] CRS {rid}: (none) */ {{LUMINA_T_NONE}},")
    lines.append("};")
    lines.append("")
    lines.append("const uint8_t g_rule_transform_seq_id[LUMINA_SHORT_RULE_COUNT] = {")
    for idx, rid in enumerate(ids):
        lines.append(f"    /* [{idx}] CRS {rid} */ {rule_sequence_ids[idx]},")
    lines.append("};")
    lines.append("")
    lines.append(
        "const uint64_t g_transform_sequence_dirty_by_byte"
        "[256][LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS] = {")
    for byte, words in enumerate(dirty_by_byte):
        values = ", ".join(f"0x{word:016x}ULL" for word in words)
        lines.append(f"    /* 0x{byte:02x} */ {{{values}}},")
    lines.append("};")
    lines.append("")
    values = ", ".join(f"0x{word:016x}ULL" for word in always_dirty)
    lines.append(
        "const uint64_t g_transform_sequence_always_dirty"
        "[LUMINA_TRANSFORM_SEQUENCE_MASK_WORDS] = "
        f"{{{values}}};")
    c_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rules_with_t = sum(1 for rid in ids if seqs[rid])
    print(f"emitted g_rule_transform_seq[{n}]")
    print(f"unique transform sequences: {len(sequence_ids)}")
    print(f"engine rules with transforms (incl inherited): {rules_with_t}/{n}")
    print(f"engine rules found in CRS .conf: {len(found)}/{n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
