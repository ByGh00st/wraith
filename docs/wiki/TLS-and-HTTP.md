# TLS profiles & HTTP

> **03 / CONNECTIONS** · Know which layer Wraith controls.

## Three distinct paths

| Path | Wraith controls | Application keeps |
| :--- | :--- | :--- |
| Wraith HTTPS client | Actual browser-profile TLS handshake and HTTP/2 settings | The caller chooses the supported request and URL |
| Cleartext HTTP relay | Initial HTTP request header normalization and Tor forwarding | Application behavior and later request semantics |
| HTTPS CONNECT tunnel | Destination parsing and byte transport over Tor | Its own ClientHello, certificate checks and encrypted HTTP |

### Real ClientHello profiles

The native client uses BoringSSL through wreq and supported emulation profiles. These affect the actual TLS connection, rather than only a displayed fingerprint or User-Agent.

| CLI profile | Pinned emulation | Integration |
| :--- | :--- | :--- |
| `chrome` | Chrome 131 | Default fetch, DoH and cover requests |
| `firefox` | Firefox 133 | Fetch and public Rust client API |
| `safari` | Safari 18 | Fetch and public Rust client API |

With a Wraith/Tor session already running:

```bash
wraith fetch https://example.org/ --tls-profile chrome --output page.html
wraith fetch https://example.org/ --tls-profile firefox --output firefox-page.html
wraith fetch --help
```

Fetch runs without root, uses SOCKS5 remote DNS, verifies the certificate chain and hostname, and requires TLS 1.2 or newer. It has bounded timeouts and an **8 MiB** response limit. Redirects are not followed, existing output files are not overwritten, and a failed Tor connection does not fall back to a direct request.

### JA3 / JA4: the scope

JA3 and JA4 describe connection fingerprints. A browser TLS profile does not reproduce browser JavaScript, cookies, user behavior or every network characteristic. Wraith does not promise an exact JA3/JA4 match or non-detection.

Other applications keep their TLS fingerprints when using CONNECT. Wraith does not install a root certificate or perform HTTPS MITM.

### HTTP relay

The local relay listens on **127.0.0.1:9055** and forwards through Tor SOCKS. It supports CONNECT, absolute HTTP URLs, explicit destination ports, IPv6 authority parsing, fragmented headers and binary bodies. CONNECT preserves coalesced first TLS bytes and stream half-close.

Normalization applies to the **initial cleartext HTTP request**. Tool/non-browser User-Agents are normalized. `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `Via`, `Client-IP`, `True-Client-IP`, `X-Client-IP` and `X-Originating-IP` are removed case-insensitively, along with `Proxy-Authorization` and `Proxy-Connection`. Origin authorization, cookies and binary body bytes are preserved.

Later requests on a persistent stream are relayed without reparsing; this is not a complete HTTP traffic anonymizer. CONNECT preserves application TLS. The relay allows at most 128 client tasks, bounds setup writes to 10 seconds and releases established relays after 120 seconds without transferred data.

### Developer integration

Supported callers can invoke `wraith fetch`, or use the public `wraith_tor::BrowserTlsClient` API for bounded HTTPS GET requests. The DNS relay uses the same client for DNS-message POST requests.

**Next:** [DNS and routing →](DNS-and-Routing.md)
