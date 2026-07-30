#!/usr/bin/env python3
"""Generate absolute, hashable comparator configs from the V1.0 Protocol manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

REQUEST_BODY_PROCESSOR_RULES = (
    "SecRule REQUEST_HEADERS:Content-Type "
    "\"@rx ^(?:application(?:/soap\\+|/)|text/)xml(?:\\s*;|$)\" "
    "\"id:200000,phase:1,pass,nolog,t:none,t:lowercase,"
    "ctl:requestBodyProcessor=XML\"",
    "SecRule REQUEST_HEADERS:Content-Type "
    "\"@rx ^application/(?:[a-z0-9.-]+\\+)?json(?:\\s*;|$)\" "
    "\"id:200001,phase:1,pass,nolog,t:none,t:lowercase,"
    "ctl:requestBodyProcessor=JSON\"",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--module-dir", type=Path, required=True)
    parser.add_argument("--naxsi-source", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    args.output.mkdir(parents=True, exist_ok=True)

    include_paths = [ROOT / item["path"] for item in manifest["crs"]["ordered_includes"]]
    coraza_rules = [
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecResponseBodyAccess Off",
        "SecAuditEngine Off",
        *REQUEST_BODY_PROCESSOR_RULES,
        "",
        *(f"Include {path.resolve()}" for path in include_paths),
        "",
    ]
    coraza_rules_path = args.output / "coraza_crs_pl2.conf"
    coraza_rules_path.write_text("\n".join(coraza_rules), encoding="utf-8")
    modsecurity_rules = [
        "SecRuleEngine On",
        "SecRequestBodyAccess On",
        "SecResponseBodyAccess Off",
        "SecAuditEngine Off",
        "SecPcreMatchLimit 1000",
        "SecPcreMatchLimitRecursion 1000",
        "SecTmpDir /tmp/",
        "SecDataDir /tmp/",
        *REQUEST_BODY_PROCESSOR_RULES,
        "",
        *(f"Include {path.resolve()}" for path in include_paths),
        "",
    ]
    modsecurity_rules_path = args.output / "modsecurity_crs_pl2.conf"
    modsecurity_rules_path.write_text("\n".join(modsecurity_rules), encoding="utf-8")

    common = f"""worker_processes 1;
pid {ROOT}/test_nginx/logs/benchmark_harness_v1_external.pid;
events {{ worker_connections 4096; }}
http {{
    access_log off;
    client_body_temp_path {ROOT}/test_nginx/tmp/client_body;
    {{HTTP_GLOBAL}}
    server {{
        listen 19090;
        location / {{
            root {ROOT}/test_nginx/html;
            try_files $uri =404;
            {{DIRECTIVES}}
        }}
        {{EXTRA}}
    }}
}}
"""
    variants = {
        "baseline": ("", ""),
        "luminawaf": (
            f"load_module {(args.module_dir / 'ngx_http_luminawaf_module.so').resolve()};\n",
            "lumina_waf on;",
        ),
        "luminawaf_loaded_off": (
            f"load_module {(args.module_dir / 'ngx_http_luminawaf_module.so').resolve()};\n",
            "lumina_waf off;",
        ),
        "modsecurity": (
            f"load_module {(args.module_dir / 'ngx_http_modsecurity_module.so').resolve()};\n",
            f"modsecurity on;\n            modsecurity_rules_file {modsecurity_rules_path.resolve()};",
        ),
    }
    for name, (module, directives) in variants.items():
        rendered = (module + common.replace("{DIRECTIVES}", directives)
                    .replace("{EXTRA}", "").replace("{HTTP_GLOBAL}", ""))
        (args.output / f"nginx_{name}.conf").write_text(rendered, encoding="utf-8")

    coraza = (
        f"load_module {(args.module_dir / 'ngx_http_coraza_module.so').resolve()};\n"
        + common.replace("{DIRECTIVES}", f"coraza on;\n            coraza_rules_file {coraza_rules_path.resolve()};")
        .replace("{EXTRA}", "").replace("{HTTP_GLOBAL}", "")
    )
    (args.output / "nginx_coraza.conf").write_text(coraza, encoding="utf-8")

    core_rules = args.naxsi_source / "naxsi_rules/naxsi_core.rules"
    naxsi = (
        f"load_module {(args.module_dir / 'ngx_http_naxsi_module.so').resolve()};\n"
        + common.replace(
            "{DIRECTIVES}",
            "\n            ".join(
                [
                    "SecRulesEnabled;",
                    'DeniedUrl "/RequestDenied";',
                    'CheckRule "$SQL >= 8" BLOCK;',
                    'CheckRule "$RFI >= 8" BLOCK;',
                    'CheckRule "$TRAVERSAL >= 5" BLOCK;',
                    'CheckRule "$UPLOAD >= 5" BLOCK;',
                    'CheckRule "$XSS >= 8" BLOCK;',
                    'CheckRule "$UWA >= 8" BLOCK;',
                    'CheckRule "$EVADE >= 8" BLOCK;',
                ]
            ),
        ).replace("{EXTRA}", "location = /RequestDenied { internal; return 403; }")
        .replace("{HTTP_GLOBAL}", f"include {core_rules.resolve()};")
    )
    (args.output / "nginx_naxsi_stock.conf").write_text(naxsi, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
