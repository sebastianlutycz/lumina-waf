# Security Policy

LuminaWAF processes hostile input but remains experimental, pre-1.0 software. It has not received
an independent security audit and must not be treated as a production security boundary without
additional review and validation.

## Supported Versions

| Version | Security updates |
|---|---|
| `v0.4.x` | Supported during the release-candidate cycle |
| Earlier versions | Not supported |

## Report a Vulnerability

Use GitHub private vulnerability reporting from the repository's **Security** tab and select
**Report a vulnerability**. Do not disclose exploit details in a public issue.


Include:

- the affected commit, tag and architecture;
- the smallest reproducible request or input;
- expected and observed behavior;
- build flags and deployment boundary;
- crash output, sanitizer findings or rule IDs, when applicable;
- an assessment of impact and exploitability.

If private vulnerability reporting is temporarily unavailable, contact the repository maintainer
through their GitHub profile to establish a private channel. Do not include vulnerability details
in that initial message.

Reports will be acknowledged as soon as practical. Validation, remediation and disclosure timing
depend on severity and reproducibility. Please allow coordinated remediation before publication.

## Scope

Security reports may cover the core runtime, translator, generated-code boundary, NGINX module,
clean-room SQL injection operator, benchmark integrity and release tooling. OWASP CRS itself and
third-party benchmark comparators should be reported to their respective upstream projects unless
the issue is caused by LuminaWAF integration.
