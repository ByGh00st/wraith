# TLS, DPI & HTTP PROTOCOL CAMOUFLAGE

Technical specifications for cleartext HTTP header normalization (port 9055), BoringSSL browser TLS handshakes (JA3/JA4), RFC 8701 GREASE extensions, and cover traffic generation.

---

## 1. In-Flight Cleartext HTTP Relay (Port 9055)

Many automated command-line utilities, script interpreters, and security testing tools broadcast distinct headers and default User-Agent strings (e.g., `sqlmap/1.8`, `Nmap Scripting Engine`, `python-requests/2.31.0`, `Go-http-client/1.1`). 

To prevent passive network intermediaries and HTTP destinations from identifying client toolchains on unencrypted sessions, Wraith deploys an in-flight HTTP proxy bound to `127.0.0.1:9055` (`wraith_core::config::DPI_HTTP_PORT`).

```
[CLIENT UTILITY] ──HTTP:80──► [NETFILTER REDIRECT] ──► [PORT 9055 PROXY]
                                                            │
                                              • Inspect HTTP Request Framing
                                              • Strip Identifying Headers
                                              • Substitute Desktop Browser UA
                                              • Forward via Tor SOCKS5 (:9050)
```

### Sanitization Specifications:
1. **User-Agent Normalization:** Replaces detected non-browser or tool User-Agents with an active pool of contemporary desktop browser headers (Windows 11 / Linux / macOS).
2. **Identifying Egress Headers Stripped:**
   - `X-Forwarded-For`
   - `X-Real-IP`
   - `Via`
   - `Client-IP`
   - `True-Client-IP`
3. **Signature Catalog Filtering:** Scans headers against a built-in catalog of 1,338 tool signatures across vulnerability scanners, web fuzzers, OSINT frameworks, and HTTP libraries.
4. **HTTPS CONNECT Passthrough:** When handling HTTPS `CONNECT` requests, the proxy establishes an opaque bidirectional TCP tunnel over Tor SOCKS5 without inspecting or decrypting the underlying TLS session. The application's original TLS handshake and end-to-end encryption remain untouched.

---

## 2. Browser TLS Handshake Emulation (BoringSSL)

Unlike proxies that rely on standard OpenSSL or Rustls configurations—which present distinctive cipher suite orderings easily classified by network sensors—Wraith embeds a dedicated HTTPS client backed by **BoringSSL** (via `wreq`).

This client constructs authentic browser-grade TLS ClientHello messages matching contemporary browser releases:

| Emulation Profile | Target Platform | Cryptographic & Protocol Characteristics |
| :--- | :--- | :--- |
| **`chrome` (Chrome 131)** | Google Chrome (Windows 11 / Linux) | ALPN (`h2`, `http/1.1`), RFC 8701 GREASE cipher/extension injection, Post-Quantum Kyber768/X25519 hybrid key exchange. |
| **`firefox` (Firefox 133)** | Mozilla Firefox (Linux / Windows) | Specific Firefox cipher priority, curve25519 key share, Extended Master Secret extension. |
| **`safari` (Safari 18)** | Apple Safari (macOS Sonoma / Sequoia) | Native Apple SecureTransport extension sequence, specific elliptic curve preferences. |

### Operational Scope & Limitations:
- **Direct Client Scope:** Browser TLS profiles apply strictly to requests originated by Wraith itself—specifically `wraith fetch`, local DNS-over-HTTPS (DoH) queries, and applications utilizing the public `wraith_tor::BrowserTlsClient` API.
- **Transparent HTTPS:** Third-party applications communicating over HTTPS via the transparent Tor proxy (`TransPort 9040`) retain their own native TLS handshakes and JA3/JA4 fingerprints. Wraith does not act as a Man-In-The-Middle (MITM) proxy and does not install local root certificate authorities.
- **Handshake vs. Behavior:** Emulating a TLS ClientHello does not simulate browser JavaScript execution, DOM capabilities, cookie persistence, or HTTP/2 priority tree scheduling.

---

## 3. Cover Traffic Generation (Jitter Worker)

To introduce non-deterministic background traffic on active network interfaces, Wraith includes an optional cover request generator:

```bash
sudo wraith -s --jitter --jitter-endpoint https://authorized-endpoint.example/health
```

### Operational Parameters:
- **Transport Route:** Requests are dispatched as authentic HTTPS GET operations through Tor SOCKS5.
- **Randomized Intervals:** Inter-request intervals vary between **15 and 45 seconds**, randomized via uniform distribution to disrupt static polling signatures.
- **Payload Boundaries:** Inbound responses are truncated at **16 KiB** to prevent excessive bandwidth consumption.
- **Authorization Requirement:** Operators must explicitly designate a valid HTTPS target that they own or are authorized to query.

> [!CAUTION]
> **Traffic Correlation Notice:** Background cover requests introduce synthetic HTTP activity, but do not provide formal mathematical or cryptographic resistance against advanced global statistical traffic correlation (e.g., netflow timing analysis performed by autonomous system adversaries observing both ingress and egress Tor relays).
