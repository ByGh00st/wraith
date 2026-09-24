# Daily workflow

> **02 / OPERATE** · Start, inspect, adjust and stop.

## Session commands

| Command | What it does |
| :--- | :--- |
| `sudo wraith -s` | Start a background session (strict/interactive sessions stay foreground) |
| `sudo wraith -Fs` | Start the foreground strict bundle with namespace + Tor access-link L4 auto and matching TLS policy |
| `sudo wraith -i` | Inspect status and Tor circuit information |
| `sudo wraith -r` | Request a new identity for eligible new Tor streams |
| `sudo wraith -x` | Stop and restore recorded settings |
| `sudo wraith doctor` | Run diagnostics |
| `sudo wraith -t` | Run the network-check suite |
| `sudo wraith -u` | Update from the official GitHub repository |

NEWNYM does not move existing connections or erase cookies and logins. A successful exit-IP check describes that request, not every application or interface.

## Flags and shortcuts

Choose one operation. Use `sudo wraith -Fs` or `sudo wraith start -F`; session flags written before a subcommand, such as `wraith -F start`, are rejected. Combining `-s -i`, or attaching session flags to update/status/stop, no longer silently drops options. The explicit `-x -d` and `-c --cleanup-full` combinations remain supported.

`-v` and `--lang` are global: `sudo wraith info -v --lang tr` is valid. `exec -- PROGRAM ...` preserves the application's own `--help`, `--lang` and other flags. Help and completions come from the same parser; aliases such as `wraith nics --help` show their own command options.

Interactive selection runs in the foreground. Without a terminal, provide `--interface` and `--doh` values instead. `--no-killswitch` / `--no-ks` is rejected in every mode because the watchdog is mandatory.

For the required controls, host prerequisites and optional additions to `-Fs`, see the [full-security setup guide](Advanced-Configuration.md#full-security-preset). Change the matched pair with `sudo wraith -Fs --tls-profile safari`; L4 follows automatically.

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

For release packages, rerun `install.sh` or install a newer `.deb` with APT. `-u` remains a source-checkout operation; it does not upgrade an installed package.

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
