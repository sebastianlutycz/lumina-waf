#!/usr/bin/env python3
"""Emit CRS chain metadata from rule_manifest.json.

The slab can collapse pure generated-rule chains only when every member has an
engine idx and the chain does not depend on capture/TX state. Other chains stay
stateful/native and are not forced through the slab.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sidecar_translator import parse_conf_files


ROOT = Path(__file__).resolve().parents[1]
GEN = ROOT / "src/generated"
DEFAULT_MANIFEST = GEN / "rule_manifest.json"
MAX_MEMBERS = 8


def parse_chains(rules_dir: Path) -> list[dict]:
    """Group SecRule chains using the canonical ModSecurity statement parser."""
    rules = parse_conf_files(str(rules_dir))
    chains: list[dict] = []
    i = 0
    while i < len(rules):
        head = rules[i]
        if not head.get("chain"):
            i += 1
            continue
        members = [head]
        i += 1
        while i < len(rules):
            member = rules[i]
            members.append(member)
            i += 1
            if not member.get("chain"):
                break
        chains.append({
            "head_id": int(head["id"]) if head.get("id") else None,
            "capture": any("capture" in (member.get("actions") or {}) for member in members),
            "tx": any(
                "TX" in {binding.collection for binding in member.get("bindings", [])} or
                "%{tx." in (member.get("pattern") or "").lower()
                for member in members
            ),
            "members": [
                {
                    "ordinal": ordinal,
                    "rule_id": int(member["id"]) if member.get("id") else None,
                    "variables": member.get("variables") or "",
                    "bindings": [
                        {
                            "collection": binding.collection,
                            "selector": binding.selector,
                            "selector_kind": binding.selector_kind,
                            "excluded": binding.excluded,
                            "count": binding.count,
                        }
                        for binding in member.get("bindings", [])
                    ],
                    "operator": ("!" if member.get("negated") else "") + (member.get("operator") or ""),
                    "pattern": member.get("pattern") or "",
                    "transforms": member.get("transforms") or [],
                    "continues": bool(member.get("chain")),
                }
                for ordinal, member in enumerate(members)
            ],
        })
    return chains


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="translator rule manifest")
    parser.add_argument("--rules-dir", default=None, help="CRS rules directory; default from manifest")
    parser.add_argument("--out-dir", default=str(GEN), help="generated output directory")
    parser.add_argument("--diag", action="store_true", help="print diagnostics without writing files")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    ids = [int(x) for x in manifest["generated_rule_ids"]]
    idx_by_crs = {rid: idx for idx, rid in enumerate(ids)}
    rules_dir = Path(args.rules_dir or manifest["rules_dir"])
    chains = parse_chains(rules_dir)
    n = len(ids)

    n_collapsible = 0
    n_stateful = 0
    for chain in chains:
        member_ids = [member["rule_id"] for member in chain["members"]]
        all_in = all(rid is not None and rid in idx_by_crs for rid in member_ids)
        chain["all_in"] = all_in
        chain["collapsible"] = bool(all_in and not chain["capture"] and not chain["tx"])
        if chain["collapsible"]:
            n_collapsible += 1
        else:
            n_stateful += 1

    if args.diag:
        print(f"TOTAL chains parsed: {len(chains)}")
        print(f"  collapsible (pure AND, in-slab): {n_collapsible}")
        print(f"  stateful (capture/tx/out-of-slab): {n_stateful}")
        for chain in chains[:12]:
            print(
                f"  head={chain['head_id']} members={len(chain['members'])} collapsible={chain['collapsible']} "
                f"all_in={chain['all_in']} cap={chain['capture']} tx={chain['tx']}"
            )
        return 0

    records = {i: {"head_idx": -1, "members": [], "is_stateful": 0} for i in range(n)}
    for chain in chains:
        member_ids = [member["rule_id"] for member in chain["members"]]
        member_idxs = [idx_by_crs.get(rid, -1) for rid in member_ids]
        head_idx = idx_by_crs.get(chain["head_id"], -1)
        if head_idx != -1:
            records[head_idx] = {
                "head_idx": head_idx,
                "members": list(member_idxs[1:]),
                "is_stateful": 0 if chain["collapsible"] else 1,
            }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    h_path = out_dir / "crs_chains.h"
    c_path = out_dir / "crs_chains.c"

    h_path.write_text(
        "#ifndef CRS_CHAINS_H\n"
        "#define CRS_CHAINS_H\n"
        "#include <stddef.h>\n"
        "#include \"generated/crs_short_rules.h\"\n\n"
        "/* AUTO-GENERATED by tools/k4_chain_parse.py. Do not edit. */\n"
        "#define CRS_CHAIN_MAX_MEMBERS 8\n"
        "typedef struct {\n"
        "    int head_idx;\n"
        "    int n_members;\n"
        "    int members[CRS_CHAIN_MAX_MEMBERS];\n"
        "    int is_stateful;\n"
        "} CrsChain;\n"
        "extern const CrsChain g_rule_chain[LUMINA_SHORT_RULE_COUNT];\n"
        "#endif\n",
        encoding="utf-8",
    )

    lines: list[str] = []
    lines.append("/* AUTO-GENERATED by tools/k4_chain_parse.py. Do not edit. */")
    lines.append('#include "generated/crs_chains.h"')
    lines.append("")
    lines.append("const CrsChain g_rule_chain[LUMINA_SHORT_RULE_COUNT] = {")
    empty = "-1,-1,-1,-1,-1,-1,-1,-1"
    for idx in range(n):
        record = records[idx]
        if record["head_idx"] == -1:
            lines.append(f"    {{ -1, 0, {{ {empty} }}, 0 }}, /* idx {idx} */")
            continue
        members = record["members"][:MAX_MEMBERS]
        members += [-1] * (MAX_MEMBERS - len(members))
        member_text = ",".join(str(x) for x in members)
        lines.append(
            f"    {{ {record['head_idx']}, {len(record['members'])}, "
            f"{{ {member_text} }}, {record['is_stateful']} }}, /* idx {idx} */"
        )
    lines.append("};")
    c_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_path = out_dir / "crs_chain_manifest.json"
    manifest_path.write_text(json.dumps({
        "schema": "lumina-waf-chain-manifest-v1",
        "chain_count": len(chains),
        "collapsible_count": n_collapsible,
        "stateful_count": n_stateful,
        "chains": chains,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"EMITTED: {h_path}")
    print(f"         {c_path}")
    print(f"         {manifest_path}")
    print(f"chains={len(chains)} collapsible={n_collapsible} stateful={n_stateful} n={n}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
