<p align="center"><img src="https://raw.githubusercontent.com/ByGh00st/wraith/main/docs/assets/wraith-banner.svg" alt="Wraith — Your network. Your terms." width="1200"></p>

<h1 align="center">The Wraith field guide</h1>
<p align="center">Set up your environment. Understand your connections. Keep a recovery path.<br>
<b>Practical documentation for the Linux Tor proxy and privacy session manager.</b></p>

<p align="center"><a href="Getting-Started.md"><b>Get started →</b></a> · <a href="Daily-Workflow.md">Commands</a> · <a href="TLS-and-HTTP.md">TLS profiles</a> · <a href="Troubleshooting.md">Troubleshooting</a></p>

---

Wraith brings Tor routing, local DNSSEC validation, browser-profile HTTPS requests and recoverable host controls into one Rust CLI. This wiki follows the current implementation, with examples separated from optional advanced settings.

<table>
<tr><td width="50%" valign="top"><h3>01 · Start here</h3><p>Requirements, installation and your first foreground session.</p><a href="Getting-Started.md">Installation guide →</a></td>
<td width="50%" valign="top"><h3>02 · Build your workflow</h3><p>Status, circuit rotation, interface selection and updates.</p><a href="Daily-Workflow.md">Everyday commands →</a></td></tr>
<tr><td valign="top"><h3>03 · Understand the connection</h3><p>Real TLS profiles, HTTP CONNECT, Tor DoH and DNSSEC.</p><a href="TLS-and-HTTP.md">TLS &amp; HTTP →</a> · <a href="DNS-and-Routing.md">DNS &amp; routing →</a></td>
<td valign="top"><h3>04 · Configure and recover</h3><p>Advanced presets, host requirements and recorded restoration.</p><a href="Advanced-Configuration.md">Advanced settings →</a> · <a href="Troubleshooting.md">Recovery guide →</a></td></tr>
</table>

### Pick a path

| Your goal | Read next |
| :--- | :--- |
| Install Wraith on an existing Linux host | [Getting started](Getting-Started.md) |
| Make HTTPS requests using a supported browser TLS profile | [TLS & HTTP](TLS-and-HTTP.md) |
| Understand how DNS queries travel and are validated | [DNS & routing](DNS-and-Routing.md) |
| Compare deployment approaches and component responsibilities | [Architecture](Architecture.md) |
| Diagnose a failed startup or incomplete cleanup | [Troubleshooting](Troubleshooting.md) |
| Contribute or understand what has been tested | [Development & project information](Development.md) |

### Recent improvements

| Area | Current behavior |
| :--- | :--- |
| Worker ownership | Boot/start-time/executable identity and pidfd-bound shutdown |
| Namespace safety | One pinned descriptor, approved TCP keys and host-alias rejection |
| Profile pairing | Explicit Chrome/Windows, Firefox/Linux and Safari/macOS metadata |
| TCP restoration | Original route metrics restored and read back without deleting the namespace |
| HTTP privacy | Initial-request address headers removed while preserving binary bodies |
| Proxy availability | 10-second setup-write deadline; 120-second relay inactivity limit |

[Read the L4/L7 guide](L4-and-L7.md) · [Validation details](Development.md)

### Project at a glance

**6 Rust crates · 17 locales · GPL-3.0 · x86_64 Linux runtime**

The latest recorded checks include **174 portable tests**, Linux-target test compilation and production Clippy with warnings denied. Live Linux routing and installed-system updates remain outside that validation. See [the validation guide](Development.md).

<p align="center"><a href="https://github.com/ByGh00st/wraith">Repository</a> · <a href="https://github.com/ByGh00st/wraith#privacy-matrix">Tool comparison</a> · <a href="https://github.com/ByGh00st/wraith/issues">Issues</a></p>
