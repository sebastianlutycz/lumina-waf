# Complete Raw Evidence

The complete canonical evidence is retained as one immutable release asset rather than as 1,399
individual files in Git history.

- Asset: `v0.4.0-rc.11-canonical-20260723T071816Z.tar.zst`
- Expected download:
  `https://github.com/sebastianlutycz/lumina-waf/releases/download/v0.4.0-rc.11/v0.4.0-rc.11-canonical-20260723T071816Z.tar.zst`
- Size: `397310` bytes
- SHA256: `cc8b17f3806ba56ad279459bb89a4cabd32bac1b81aee6fd394c931972727bb3`
- Files covered by the internal evidence manifest: `1399`

The archive includes the original generated report, all raw Google Benchmark JSON and console
logs, wrk/wrk2 output, NGINX configurations, correctness evidence, PMU groups, build provenance,
systemd journal, service exit state and host snapshots from before and after measurement.

Before publication, the archive was checked for credentials, access tokens, private keys, provider
login details, public server addresses, ELF binaries and embedded OWASP CRS rule/data files. None
were found. It retains reproducibility metadata such as `/srv/lumina-canonical` paths, localhost,
the test address `1.2.3.4` and the commit author's public GitHub noreply address.

Verify the downloaded asset:

```bash
printf '%s  %s\n' \
  'cc8b17f3806ba56ad279459bb89a4cabd32bac1b81aee6fd394c931972727bb3' \
  'v0.4.0-rc.11-canonical-20260723T071816Z.tar.zst' \
  | sha256sum -c -
```

The repository bundle intentionally excludes OWASP CRS rule/data files, generated AOT source,
third-party source trees and host build caches.
