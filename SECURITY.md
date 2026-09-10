# Security policy

Wraith manages privileged network and host settings. Reports about unintended egress, unsafe restoration, privilege boundaries or certificate verification are especially useful.

## Report a vulnerability privately

Use **[Report a vulnerability](https://github.com/ByGh00st/wraith/security/advisories/new)** in this repository's Security tab. Do not put exploit details, credentials, private keys or sensitive packet captures in public issues or pull requests.

If the private form is unavailable, open a public issue requesting a private contact channel **without technical vulnerability details**. Do not send a report to an unverified address.

Include:

- Affected commit or version, distribution, kernel and relevant dependency versions.
- The command and configuration, with secrets removed.
- Expected behavior, observed behavior and security impact.
- Minimal reproduction steps using systems you control, preferably a local fixture.
- Relevant sanitized logs and any proposed fix or regression test.

## Review scope

| Code line | Reporting guidance |
| :--- | :--- |
| Current `main` | Primary reference for investigation and fixes |
| Latest tagged release | Report the exact tag and whether current `main` is also affected |
| Older releases or forks | Reports are welcome; independent maintenance and backports are not promised |

There is no published long-term-support or guaranteed response-time commitment. This policy does not represent an independent audit or a promise that the project is free of vulnerabilities.

## Coordination

Use the private advisory to coordinate reproduction, remediation and disclosure. Maintainers may request additional details, develop a fix and publish an advisory when appropriate. Agree on disclosure timing in that conversation; no fixed embargo, bounty or reward is promised. Request attribution there if desired.

Limit testing to authorized systems. Avoid disrupting services, accessing another person's data or running destructive options to demonstrate a report when a non-destructive reproduction is possible.

## Relevant boundaries

See the [threat model](docs/THREAT_MODEL.md) for intended protections and non-goals. In particular, CONNECT preserves application TLS; browser profiles do not imply universal JA3/JA4 camouflage. Live Linux networking remains outside the recorded portable-test validation.

Routine setup problems belong in [Issues](https://github.com/ByGh00st/wraith/issues); see [SUPPORT.md](SUPPORT.md).
