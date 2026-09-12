# 🔒 TLS, DPI & HTTP CAMOUFLAGE

This document covers the in-flight DPI header sanitizer on port 9055, real browser TLS ClientHello spoofing (JA3/JA4), RFC 8701 GREASE, and offensive security signature neutralization.

---

## 🌐 In-Flight DPI Sanitizer (Port 9055)

Many security auditing tools and clearnet applications leak identifiable headers or default User-Agents (e.g. `sqlmap/1.8`, `Nmap Scripting Engine`, `python-requests/2.31`).

Wraith binds an in-flight DPI proxy to `127.0.0.1:9055` (`wraith_core::config::DPI_HTTP_PORT`).

```
[APP / TOOL] ──HTTP:80──► [NETFILTER REDIRECT] ──► [PORT 9055 PROXY]
                                                           │
                                             • Inspect HTTP Request
                                             • Strip Leaking Headers
                                             • Substitute Real Browser UA
                                             • Forward to Tor SOCKS5
```

### Sanitized Headers & Fields:
- `User-Agent`: Replaced with an active desktop browser pool (Chrome 131 / Firefox 133 / Safari 18 on Windows 11 / macOS).
- Leaking Headers Stripped:
  - `X-Forwarded-For`
  - `X-Real-IP`
  - `Via`
  - `Client-IP`
  - `True-Client-IP`
  - Pentest tool signatures (Nmap, Nikto, Nuclei, Ffuf, Masscan, Dirbuster, Sqlmap).

---

## 🔐 Real ClientHello Browser TLS Profiles

Unlike naive privacy proxies that use generic OpenSSL/Rustls handshakes with easily fingerprinted cipher lists, Wraith's native HTTPS client embeds BoringSSL with realistic browser profiles:

| Profile | Target Browser | JA4 Hash Signature | Features |
| :--- | :--- | :--- | :--- |
| **Chrome 131** | Google Chrome on Win11 | `t13d1516h2_...` | ALPN (h2, http/1.1), RFC 8701 GREASE, Post-Quantum Kyber768/X25519 |
| **Firefox 133** | Mozilla Firefox on Linux | `t13d1715h2_...` | Firefox cipher order, curve25519, Extended Master Secret |
| **Safari 18** | Apple Safari on macOS | `t13d2014h2_...` | Apple SecureTransport signature, specific TLS extension order |

---

## 🌊 Cover Request Generation

To prevent network timing and packet-length traffic analysis:
- Wraith optionally synthesizes randomized cover requests through Tor to popular CDNs (Cloudflare, Fastly, Akamai).
- Payload lengths and inter-arrival delays are randomized using Gaussian distributions to resist passive side-channel correlation.
