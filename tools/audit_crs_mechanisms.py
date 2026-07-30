#!/usr/bin/env python3
"""Classify CRS PL rules into LuminaWAF mechanism classes.

This is a read-only compiler audit. It answers whether a SecRule should bind to
C1 phrase, C2/C3 AOT regex, C4 structural validator, C5 scalar validator, C6
chain metadata, or C7 scanner before generated artifacts are promoted.
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import sidecar_translator as sidecar  # noqa: E402


SCALAR_OPS = {
    "@eq",
    "@ge",
    "@gt",
    "@lt",
    "@within",
    "@contains",
    "@beginsWith",
    "@endsWith",
    "@streq",
    "@validateByteRange",
    "@validateUtf8Encoding",
    "@validateUrlEncoding",
    "@ipMatch",
}

STRUCTURAL_VARS = {
    "REQUEST_METHOD",
    "REQUEST_LINE",
    "REQUEST_PROTOCOL",
    "REQUEST_HEADERS",
    "REQUEST_HEADERS_NAMES",
    "REQUEST_BODY_LENGTH",
    "REQBODY_PROCESSOR",
    "MULTIPART_STRICT_ERROR",
    "MULTIPART_UNMATCHED_BOUNDARY",
    "MULTIPART_PART_HEADERS",
    "UNIQUE_ID",
    "REMOTE_ADDR",
}

TX_REF_RE = re.compile(r"%\{tx\.([^}]+)\}", re.I)
ANOMALY_RE = re.compile(r"setvar\s*:\s*['\"]?tx\.inbound_anomaly_score_pl[0-9]+\s*=\s*\+", re.I)

RUNTIME_COVERED_IDS = {
    911100,  # REQUEST_METHOD !@within %{tx.allowed_methods}
    920100,  # REQUEST_LINE !@rx request-line grammar
    913100,  # REQUEST_HEADERS:User-Agent @pmFromFile scanners-user-agents
    920171,  # GET/HEAD request with Transfer-Encoding header chain
    920280,  # missing Host header count
    920320,  # missing User-Agent header count
    920430,  # REQUEST_PROTOCOL allowlist
    920620,  # duplicate Content-Type header count
    920660,  # obsolete Request-Range header count
    921250,  # cookie-name selector plus exact value predicate
    922120,  # multipart Content-Transfer-Encoding part header
    922130,  # multipart part-header name contains a non-printable byte
}

RUNTIME_NATIVE_SCALAR_IDS = {
    921250,
}


@dataclass(frozen=True)
class VarRef:
    raw: str
    base: str
    selector: str
    is_count: bool
    is_excluded: bool


@dataclass
class RuleAudit:
    rule_id: int
    phase: int | None
    paranoia: int | None
    operator: str
    negated: bool
    direct_score_bearing: bool
    chain_head_score_bearing: bool
    score_bearing: bool
    chain: bool
    mechanism: str
    emitted_current: bool
    runtime_covered: bool
    covered_current: bool
    contract_reasons: list[str]
    variables: list[str]
    selectors: list[str]
    tx_refs: list[str]


def parse_var_refs(variables: str | None) -> list[VarRef]:
    if not variables:
        return []
    refs: list[VarRef] = []
    for token in variables.split("|"):
        raw = token.strip()
        if not raw:
            continue
        rest = raw
        is_count = False
        is_excluded = False
        while rest[:1] in ("!", "&"):
            if rest[0] == "&":
                is_count = True
            elif rest[0] == "!":
                is_excluded = True
            rest = rest[1:]
        base, _, selector = rest.partition(":")
        refs.append(
            VarRef(
                raw=raw,
                base=base.strip().upper(),
                selector=selector.strip(),
                is_count=is_count,
                is_excluded=is_excluded,
            )
        )
    return refs


def generated_ids_from(root: Path) -> set[int]:
    ids: set[int] = set()
    for path in sorted(root.glob("parser_rules_*.c")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        ids.update(int(m.group(1)) for m in re.finditer(r"lumina_scan_rule_([0-9]+)\b", text))
    ids.discard(0)
    return ids


def regex_compiles(rule: dict) -> bool:
    if rule.get("operator") != "@rx" or not rule.get("id"):
        return False
    try:
        sidecar.regex_to_c(rule["id"], rule.get("pattern") or "")
        return True
    except Exception:
        return False


def regex_mechanism(rule: dict) -> str:
    if not regex_compiles(rule):
        return "C7_SCANNER_OR_REGEX_REWRITE"
    try:
        fbs = sidecar.first_bytes_of(rule.get("pattern") or "")
        if len(fbs) >= 192:
            return "C3_BLOOM_REGEX"
    except Exception:
        return "C3_BLOOM_REGEX"
    return "C2_AOT_REGEX"


def has_score(rule: dict) -> bool:
    return rule.get("kind") == "SecRule" and bool(ANOMALY_RE.search(rule.get("raw") or ""))


def is_blocking_eval(rule: dict, refs: Iterable[VarRef]) -> bool:
    bases = {r.base for r in refs}
    op = rule.get("operator") or ""
    if "TX" not in bases:
        return False
    return op in {"@ge", "@gt", "@lt", "@eq", "@pm", "@rx"} and not has_score(rule)


def contract_reasons(rule: dict, refs: list[VarRef]) -> list[str]:
    reasons: list[str] = []
    bases = {r.base for r in refs}
    if any(r.selector for r in refs if r.base in {"REQUEST_HEADERS", "REQUEST_HEADERS_NAMES"}):
        reasons.append("named_header_binding")
    if any(r.is_count for r in refs):
        reasons.append("collection_count")
    if "TX" in bases or TX_REF_RE.search(rule.get("raw") or ""):
        reasons.append("tx_state_or_setup")
    for base in ("REQUEST_PROTOCOL", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME"):
        if base in bases:
            reasons.append(base.lower())
    if any(r.base in {"REQUEST_COOKIES", "REQUEST_COOKIES_NAMES"} for r in refs):
        reasons.append("cookie_collection")
    if any(r.base in {"ARGS", "ARGS_NAMES", "ARGS_GET", "ARGS_GET_NAMES", "QUERY_STRING"} for r in refs):
        reasons.append("args_collection")
    if any(r.base in {"XML", "JSON", "REQUEST_BODY"} for r in refs):
        reasons.append("body_collection")
    return sorted(set(reasons))


def classify(rule: dict, refs: list[VarRef], effective_score_bearing: bool = False) -> str:
    if rule.get("kind") != "SecRule":
        return "CONTROL_SECACTION"
    if rule.get("is_gating"):
        return "CONTROL_GATING"
    if is_blocking_eval(rule, refs):
        return "CONTROL_BLOCKING_EVAL"
    rid_s = rule.get("id")
    rid = int(rid_s) if rid_s and str(rid_s).isdigit() else None
    if not effective_score_bearing:
        return "CONTROL_OR_SETUP"

    op = rule.get("operator") or ""
    bases = {r.base for r in refs}

    if rid in RUNTIME_NATIVE_SCALAR_IDS:
        return "C5_NATIVE_SCALAR"
    if rid in RUNTIME_COVERED_IDS:
        return "C4_STRUCTURAL_VALIDATOR"
    if rule.get("chain"):
        return "C6_CHAIN"
    if op in {"@pm", "@pmFromFile"}:
        return "C1_PHRASE"
    if op in {"@detectXSS", "@detectSQLi"}:
        return "C7_SCANNER"
    if bases & STRUCTURAL_VARS:
        return "C4_STRUCTURAL_VALIDATOR"
    if op in SCALAR_OPS or rule.get("negated"):
        return "C5_NATIVE_SCALAR"
    if op == "@rx":
        return regex_mechanism(rule)
    return "UNMAPPED"


def chain_score_heads(rules: list[dict]) -> set[int]:
    heads: set[int] = set()
    current_head: int | None = None
    for rule in rules:
        rid_s = rule.get("id")
        if current_head is None:
            if rid_s and str(rid_s).isdigit() and rule.get("chain"):
                current_head = int(rid_s)
                if has_score(rule):
                    heads.add(current_head)
            continue
        if has_score(rule):
            heads.add(current_head)
        if not rule.get("chain"):
            current_head = None
    return heads


def audit_rules(rules_dir: Path, pl: int, emitted_dir: Path | None = None) -> list[RuleAudit]:
    emitted = generated_ids_from(emitted_dir or (ROOT / "src"))
    parsed_rules = sidecar.parse_conf_files(str(rules_dir))
    scored_chain_heads = chain_score_heads(parsed_rules)
    out: list[RuleAudit] = []
    for rule in parsed_rules:
        rid_s = rule.get("id")
        if not rid_s or not str(rid_s).isdigit():
            continue
        if rule.get("paranoia") is None or rule["paranoia"] > pl:
            continue
        if rule.get("phase") not in (1, 2):
            continue
        refs = parse_var_refs(rule.get("variables"))
        rid = int(rid_s)
        tx_refs = sorted(set(TX_REF_RE.findall(rule.get("raw") or "")))
        runtime_covered = rid in RUNTIME_COVERED_IDS
        emitted_current = rid in emitted
        direct_score = has_score(rule)
        chain_head_score = rid in scored_chain_heads
        # A chain head owns the rule identity even when a later chain member
        # carries the anomaly-score action.
        effective_score = direct_score or chain_head_score
        out.append(
            RuleAudit(
                rule_id=rid,
                phase=rule.get("phase"),
                paranoia=rule.get("paranoia"),
                operator=("!" if rule.get("negated") else "") + (rule.get("operator") or ""),
                negated=bool(rule.get("negated")),
                direct_score_bearing=direct_score,
                chain_head_score_bearing=chain_head_score,
                score_bearing=effective_score,
                chain=bool(rule.get("chain")),
                mechanism=classify(rule, refs, effective_score),
                emitted_current=emitted_current,
                runtime_covered=runtime_covered,
                covered_current=emitted_current or runtime_covered,
                contract_reasons=contract_reasons(rule, refs),
                variables=sorted({r.base for r in refs}),
                selectors=sorted({f"{r.base}:{r.selector}" for r in refs if r.selector}),
                tx_refs=tx_refs,
            )
        )
    return out


def summarize(rows: list[RuleAudit]) -> dict:
    score_rows = [r for r in rows if r.score_bearing]
    not_covered = [r for r in score_rows if not r.covered_current]
    return {
        "total_pl_inbound_rules": len(rows),
        "direct_score_bearing_rules": sum(1 for r in rows if r.direct_score_bearing),
        "chain_head_score_bearing_rules": sum(1 for r in rows if r.chain_head_score_bearing),
        "runtime_covered_chain_head_score_bearing_rules": sum(
            1 for r in rows if r.chain_head_score_bearing and r.runtime_covered
        ),
        "score_bearing_rules": len(score_rows),
        "compared_generated_score_bearing_rules": sum(1 for r in score_rows if r.emitted_current),
        "runtime_covered_score_bearing_rules": sum(1 for r in score_rows if r.runtime_covered),
        "covered_score_bearing_rules": sum(1 for r in score_rows if r.covered_current),
        "score_bearing_not_covered": len(not_covered),
        "by_mechanism_all": dict(collections.Counter(r.mechanism for r in rows).most_common()),
        "by_mechanism_score_bearing": dict(collections.Counter(r.mechanism for r in score_rows).most_common()),
        "not_covered_by_mechanism": dict(collections.Counter(r.mechanism for r in not_covered).most_common()),
        "contract_reasons_score_bearing": dict(
            collections.Counter(reason for r in score_rows for reason in r.contract_reasons).most_common()
        ),
        "operators_score_bearing": dict(collections.Counter(r.operator for r in score_rows).most_common()),
    }


def print_text(rows: list[RuleAudit], limit: int) -> None:
    summary = summarize(rows)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print()
    print("score_bearing_not_covered:")
    missing = [r for r in rows if r.score_bearing and not r.covered_current]
    for r in sorted(missing, key=lambda x: (x.mechanism, x.rule_id))[:limit]:
        reasons = ",".join(r.contract_reasons) or "-"
        selectors = ",".join(r.selectors[:4]) or "-"
        print(
            f"{r.rule_id} {r.mechanism} op={r.operator} "
            f"vars={','.join(r.variables) or '-'} selectors={selectors} contract={reasons}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "rules_dir",
        nargs="?",
        default=str(ROOT / "tests/eval_suite/coreruleset/rules"),
        help="CRS rules directory, default: tests/eval_suite/coreruleset/rules",
    )
    parser.add_argument("--pl", type=int, default=2, help="maximum paranoia level")
    parser.add_argument(
        "--emitted-dir",
        default=None,
        help="directory containing parser_rules_*.c to compare against; default: src",
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    parser.add_argument("--limit", type=int, default=80, help="number of missing rules to print")
    args = parser.parse_args()

    rows = audit_rules(Path(args.rules_dir), args.pl, Path(args.emitted_dir) if args.emitted_dir else None)
    if args.json:
        print(json.dumps({"summary": summarize(rows), "rules": [asdict(r) for r in rows]}, indent=2, sort_keys=True))
    else:
        print_text(rows, args.limit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
