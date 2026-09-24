# Wraith v1.4.3

**High-Assurance DNS & Network Connectivity Fix for Tor/DoH Sovereign Routing.**

## Fixed

- **DNSSEC Indeterminate Proof Handling**: In `wraith-guard`, the DNSSEC validation layer previously rejected `Proof::Indeterminate` as an error alongside `Proof::Bogus`. Because public recursive DoH resolvers (e.g., Quad9, Cloudflare) do not forward full NSEC3 denial-of-existence chains to stub resolvers, queries for unsigned domains (including `http.kali.org`, `google.com`, `github.com`) failed, causing network isolation and `apt update` failures under strict isolation (`-s`/`-Fs`). `Proof::Indeterminate` and `Proof::Insecure` are now accepted without marking `authentic_data`, and strict rejection is strictly reserved for `Proof::Bogus`.
- **Direct DoH Fallback via Tor**: Added a fallback mechanism to direct DoH resolution over Tor when upstream DNSSEC recursion encounters timeouts or upstream parsing failures, ensuring zero DNS leaks while guaranteeing standard web and package repository reachability.
- **Internal `.onion` Resolution**: Explicitly isolated and routed all `.onion` domain queries directly to Tor's internal DNSPort (`127.0.0.1:5353`), preventing non-routable queries to upstream DoH.
- **Case-Insensitive Question Validation**: Upstream DNS response questions are now validated using case-insensitive ASCII matching, preventing 0x20-bit case-randomization mismatches.

## Upgrade

```bash
sudo apt update
sudo apt install wraith
wraith --version
```

Verify version `1.4.3` and execute with `sudo wraith -Fs`.
