# LuminaWAF Integrity and Licensing Markers

LuminaWAF v0.4 is distributed under GNU AGPLv3 and includes passive attribution and provenance
markers. No separate commercial build mode or commercial license is offered for this release.

The markers documented here are passive forensic provenance markers. They do not perform network
telemetry, do not alter request verdicts, do not disable security behavior, and do not implement
hidden request triggers.

## AGPL Attribution Notice

AGPL builds expose an HTTP attribution header on requests processed by the NGINX module:

```text
X-LuminaWAF-Id: lumina-waf/v0.4/agpl/a4e12f09bc8736d5 (AGPLv3)
```

This header is a reasonable legal notice identifying the work and its license.

## Passive Provenance Markers

AGPL builds also include passive source, binary, and generated-artifact provenance markers:

- public C ABI build fingerprint functions;
- ELF `.note.lumina` and `.lumina_fingerprint` sections;
- generated CRS manifest provenance fields;
- source-level registry/version constants;
- verifier tooling under `tools/verify_lumina_markers.py`.

These markers are intended to support origin verification and license-compliance review. They are
not copy-protection mechanisms and are not technological restrictions.

## Verification

Local source and binary verification:

```bash
tools/verify_lumina_markers.py \
  --source-root . \
  --binary build/libluminawaf.so
```

Optional remote HTTP attribution check:

```bash
tools/verify_lumina_markers.py --url https://example.com/
```

The remote check only performs a normal HTTP `HEAD` request. It does not send trigger payloads.
