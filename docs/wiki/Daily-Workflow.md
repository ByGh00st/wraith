# Daily workflow

> **02 / OPERATE** · Start, inspect, adjust and stop.

## Session commands

| Command | What it does |
| :--- | :--- |
| `sudo wraith -s` | Start a foreground session |
| `sudo wraith -i` | Inspect status and Tor circuit information |
| `sudo wraith -r` | Request a new identity for eligible new Tor streams |
| `sudo wraith -x` | Stop and restore recorded settings |
| `sudo wraith doctor` | Run diagnostics |
| `sudo wraith -t` | Run the network-check suite |
| `sudo wraith -u` | Update from the official GitHub repository |

NEWNYM does not move existing connections or erase cookies and logins. A successful exit-IP check describes that request, not every application or interface.

## Choose an interface

```bash
wraith interfaces
sudo wraith start -I wlan0
```

Replace `wlan0` with your adapter. MAC changes can interrupt Wi-Fi association or DHCP; see [troubleshooting](Troubleshooting.md).

## Choose a language

Wraith ships **17 locales**:

`ar` · `az` · `de` · `en` · `es` · `fa` · `fr` · `it` · `ja` · `ko` · `nl` · `pl` · `pt` · `ru` · `tr` · `uk` · `zh`

```bash
wraith --select-lang
wraith --lang tr --help
```

## Update source, then install

```bash
cd /path/to/wraith
wraith -u
sudo ./build.sh
```

The updater requires the official origin, `main`, a clean checkout and a fast-forward update. It does not build or replace the installed binary. The build helper compiles as your normal sudo account and installs only after a successful locked build.

A clone predating a history rewrite may be refused as divergent. Preserve your local work and clone into a new directory; the updater never resets the existing checkout. Signed offline artifact installation is not implemented; its CLI options return an explicit error.

## Namespace applications

```bash
sudo wraith start --morph-l4 auto --tls-profile chrome
# In another terminal, from your normal sudo account:
sudo wraith exec -- curl https://example.com
```

Existing applications are not moved into the namespace. Curl still constructs its own TLS handshake. See [L4 and L7](L4-and-L7.md) for the boundary between TCP controls and Wraith-owned TLS.

**Next:** [TLS profiles and HTTP](TLS-and-HTTP.md)
