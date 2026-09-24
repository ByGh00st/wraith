# Advanced configuration

> **05 / CONFIGURE** · Enable controls with a clear understanding of their scope.

## Full-security preset

`-Fs` combines full-security (`-F`) and start (`-s`). **Namespace isolation and L4 `auto` are included**, alongside the required Tor, DNS, browser/font and host controls. No extra L4 flag is needed.

<table>
<tr><td width="50%"><b>🌐 Network</b><br>Strict Tor egress · DNSSEC/DoH · mandatory kill switch</td><td width="50%"><b>🧬 Profiles</b><br>L4 sysctls · SYN MSS · FIB windows · matching TLS platform</td></tr>
<tr><td><b>🛡️ Host</b><br>MAC/hostname · machine-id · browser preferences · fonts</td><td><b>↩️ Lifecycle</b><br>Required setup checks · live L4 readback · recorded cleanup</td></tr>
</table>

```bash
# On a prepared host; keep this foreground session running
sudo wraith -Fs -I eth0
# Or start a separate session using the Firefox/Linux pair
sudo wraith -Fs -I eth0 --tls-profile firefox
```

| Automatic control | Behavior and boundary |
| :--- | :--- |
| Tor firewall + watchdog | Restrict direct egress, IPv6 and STUN; `--no-killswitch` is rejected |
| DNSSEC + DoH | Local DNSSEC validation with profile-selected TLS upstream |
| Namespace + L4 | Chrome → Windows11 (default), Firefox → LinuxDefault, Safari → MacOS |
| MSS / route windows | Windows: 1460 / 10 / 44; macOS: 1440 / 10 / 45; Linux: kernel MSS/FIB defaults |
| HTTP privacy relay | Sanitize address headers on the first cleartext request; preserve CONNECT TLS |
| Identity controls | Journal and rotate host MAC, hostname and machine-id |
| Browser / fonts | Apply supported discovered browser profiles and Fontconfig restrictions |
| Process / RAM | Require memory lockdown, seccomp and successful encrypted session-copy storage |
| Local process checks | Existing anti-debug probe and process label; no remote fingerprint protection |
| Host prerequisites / observers | Verify the settings below; acquire the IDS socket and start loopback decoys |
| Exit profile | `stealth` unless another geographic exit policy is configured |

Configuration is merged before the strict preset is expanded. Included boolean controls stay enabled even if their saved defaults are `false`. Explicit profile choices remain visible: `--morph-l4 off` or a mismatched L4/TLS pair rejects startup before host mutation. Use `--morph-l4 auto` to override an incompatible saved L4 selection.

Required startup errors refuse activation and initiate recorded cleanup. Incomplete cleanup preserves the recovery record. A final L4 readback must succeed before the session becomes active; this is configuration verification, not a captured p0f/JA3/JA4 measurement.

### Host prerequisites

| Host prerequisite | Required value |
| :--- | :--- |
| Kernel lockdown | `confidentiality` |
| `kernel.kexec_load_disabled` | `1` |
| `kernel.yama.ptrace_scope` | `3` |

These irreversible settings must already be configured by the host administrator. Wraith checks them rather than enabling them irreversibly for a temporary session. Reversible controls are recorded for restoration.

## L4 and TLS profiles

```bash
sudo wraith start --morph-l4 auto --tls-profile safari
sudo wraith -i
```

`auto` maps Chrome/Windows, Firefox/Linux and Safari/macOS. Manual L4 choices are `windows` (or `windows11`), `macos` and `linux`. Use `--namespace --morph-l4 off` to keep isolation without changing TCP settings; `off` conflicts with full-security and `--tcp-mask`. In full-security mode, explicit L4 profiles must match the chosen TLS platform; ordinary sessions retain independent manual selection.

Persist defaults with `wraith config set hardening.morph_l4 auto` and `wraith config set hardening.tls_profile safari`, or add to your existing configuration:

```toml
[hardening]
morph_l4 = "auto"
tls_profile = "safari"
```

Explicit CLI profile values override these defaults. Session TLS selection covers DoH and optional cover requests; arbitrary applications and the `fetch` command keep their own selection. See [L4 and L7](L4-and-L7.md) for live configuration telemetry and scope.

## Persistent settings and validation

`config get` and `config set` share the same key aliases, including `hardening.morph_l4`, `hardening.tls_profile`, `hardening.tcp_mask`, `hardening.browser_shield`, `hardening.honey_ports` and `network.wireguard_config`. Unknown keys return an error. `config set general.lang tr` and the language selector use the same persistent configuration.

Loading is read-only, in this order: `/etc/wraith/config.toml`, `$HOME/.config/wraith/config.toml`, then the legacy `/etc/wraith/config.json`. Malformed files, unknown fields and invalid supported-profile values are errors; they never select empty defaults. Repair a malformed file before using `config set`. A valid legacy configuration is converted to TOML only on an explicit save.

Saving preserves the selected system/user location. A new configuration can fall back to the user path if the system location is not writable; an existing system policy is never hidden by an ignored user copy. Use `sudo` when intentionally modifying the system configuration.

Rotation accepts 1..4294967295 seconds; omit it to disable rotation. The service installer accepts `--rotate 0` as its own disabled setting. Strict defaults are loaded before selecting foreground/background execution. Unsupported bridge transports and invalid onion/DoH arguments are rejected before session setup.

## Use and inspect the strict session

From a second terminal, as your normal sudo user:

```bash
sudo wraith exec -- curl https://example.com
sudo wraith -i
sudo wraith -x
```

`-i` shows the recorded strict/standard policy and reads live L4 settings, MSS rules and route metrics. Legacy records are not presented as confirmed strict sessions. An active record alone does not verify a Tor exit IP.

Only newly launched namespace applications get its TCP settings. They keep their own TLS implementations; the session TLS selection applies to Wraith's DNS and optional cover clients. Managed browser settings require the application to use a supported profile. The RAM vault protects a session copy; the recovery journal remains on disk. See [L4 and L7](L4-and-L7.md) for the host/Tor-exit boundary.

## Optional routes and services

| Option | Purpose | Requirement or boundary |
| :--- | :--- | :--- |
| `-W /path/to/vpn.conf` | Carry Tor's outer connection over WireGuard | WireGuard tools and a valid configuration; trust shifts to the VPN path |
| `--onion 80:8080` | Map onion-service port 80 to local port 8080 | A local service and working Tor transport |
| `--shaper` | Apply owned netem delay settings | No demonstrated resistance to traffic correlation |
| `--display-sandbox` | Create a private virtual display | Xvfb and xauth; applications must use that display |
| `--honey-ports` / `--honey-lan` | Loopback decoys are included in strict mode; LAN binding is opt-in | Observational traps; not malware removal |

Bridges, WireGuard, virtual display, circuit rotation, traffic shaping, cover requests and onion services need explicit CLI/configuration choices. Log/history wiping and self-destruction also remain explicit options. Full-security is a required control bundle, not a complete-anonymity or blocklist-avoidance guarantee.

Use separate sessions to evaluate different configurations. Consult `wraith start --help` and the [full command reference](https://github.com/ByGh00st/wraith#cli-reference).

## Optional cover requests

```bash
sudo wraith -s --jitter --jitter-endpoint https://your-domain.example/cover
```

Use an endpoint you control or are authorized to use. The worker makes a real HTTPS GET through Tor after each randomized **15–45 second** pause, caps responses at **16 KiB**, and cancels on shutdown. It does not fall back to direct traffic and is not automatically enabled by the strict preset. Adding `--jitter` to strict mode also enables its TC shaper.

## Scope of host controls

Browser preferences apply to managed profiles; confirm which profile an application uses. Fontconfig restrictions do not guarantee a universal font count. Seccomp restricts ptrace and alternate-ABI bypasses, but is not a general syscall allowlist. Cgroup membership is bookkeeping; netfilter enforces egress. The experimental physical-interface fastpath is not an active protection layer.

**Next:** [Troubleshooting and recovery →](Troubleshooting.md)
