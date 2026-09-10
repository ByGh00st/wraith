# Wraith

Wraith is a Rust workspace for Linux network privacy experiments. It routes supported TCP traffic through Tor, redirects DNS to a local relay, and applies host firewall and optional browser hardening settings.

**Status:** security fixes are under active development. Portable tests and Linux cross-compilation do not establish that a live machine is leak-free. See [SECURITY_AUDIT.md](SECURITY_AUDIT.md) for findings, unresolved issues, and the Linux validation checklist.

## Platform and installation

The runtime targets **x86_64 Linux**, primarily Debian/Kali-style environments. Network setup requires root, `iproute2` (`ip`, `tc`), iptables/ip6tables and their save/restore commands, Tor, curl, and a dedicated `debian-tor` account. Optional features need their own dependencies, including WireGuard or Xvfb plus `xauth`. Windows is a development/test environment, not a supported network-hardening runtime.

Build as an ordinary user, then install the resulting binary:

```sh
git clone https://github.com/ByGh00st/wraith.git
cd wraith
cargo build --release --locked
sudo install -m 0755 target/release/wraith /usr/local/bin/wraith
```

Inspect `build.sh` and `install-daemon.sh` before using automated host or service setup. The built-in updater requires sudo from a non-root account, builds as that account with supplementary groups cleared, and atomically replaces only `/usr/local/bin/wraith`. It does not verify signed upstream releases.

## Usage

```sh
sudo wraith -s                  # Start a foreground session
sudo wraith -Fs                 # Start strict/full-security preset
sudo wraith -Fs -I eth0         # Select the target interface
sudo wraith -i                  # Session information
sudo wraith -t                  # Limited external connectivity probes
sudo wraith doctor             # Host diagnostics
sudo wraith -x                  # Stop and restore saved session settings
wraith --help
```

Keep the foreground process running. Ctrl+C requests shutdown. `-Fs` combines `-F` (full-security preset) with `-s` (start); it is not a certification or a promise of complete anonymity. Strict mode requires the kill switch and rejects `--no-killswitch`.

Strict mode enables MAC/hostname changes, namespace routing and several host/browser hardening steps. Required setup errors stop activation. Startup errors now attempt saved-state cleanup and abort background tasks. Some host changes remain irreversible until reboot, and startup is not a single transaction. Test this preset in a disposable Linux VM with console access before using it on your primary connection.

Useful options include:

| Option | Purpose |
| --- | --- |
| `-I eth0` | Choose the physical network interface. |
| `-m` | Request MAC and hostname changes outside strict mode. |
| `-n` | Enable the network namespace. |
| `-D quad9` | Select a DNS-over-HTTPS resolver preset. |
| `--bridge --bridge-type obfs4` | Request a Tor bridge transport; availability must be checked. |
| `--wireguard /path/to/config` | Configure a WireGuard outer tunnel for Tor. |
| `--browser-shield` | Write managed browser preferences. |
| `--shaper` | Apply optional netem delay, jitter, loss and rate settings. |
| `--rotate-interval 120` | Request periodic Tor identity changes. Existing streams may retain their circuits. |

Persistent configuration is read from `/etc/wraith/config.toml`; inspect it with `wraith config`. CLI options and stored configuration both affect startup. Consult `wraith start --help` for the complete flag list.

## What the network policy does

- Redirects ordinary IPv4 TCP through Tor. The local HTTP relay is on port 9055 and Tor's transparent port is 9040.
- Redirects UDP and TCP DNS to the local relay on port 5354. Tor DNS upstream uses 5353; configured DoH requests use Tor SOCKS.
- Applies IPv6 firewall blocking during a session.
- Restricts namespace forwarding and uses a dedicated Tor UID exemption. Strict mode removes general LAN exemptions and blanket acceptance of existing outbound connections; DHCP renewal remains allowed.
- Attempts to preserve the active policy across kill-switch failure and recovery, and restores saved firewall/resolver settings on shutdown.

Arbitrary UDP applications, including QUIC, may lose connectivity because Tor does not transport their UDP traffic. MAC changes can also interrupt Wi-Fi or DHCP. These are compatibility constraints to diagnose, not reasons to silently enable direct fallback. Other firewall managers can conflict with the system-wide rule replacement.

## Security boundaries and incomplete features

The HTTP relay sanitizes initial cleartext HTTP headers. It does **not** replace HTTPS ClientHello messages or guarantee that tools, traffic, or users cannot be identified. TLS profile metadata is not wire-level TLS camouflage. The current jitter task does not generate end-to-end Tor cover traffic. Netem changes timing but has no demonstrated traffic-correlation resistance.

DNS responses receive structural checks, but the implementation does not cryptographically validate DNSSEC. cgroup membership is not an attached cgroup eBPF enforcement policy; effective egress controls are the firewall and namespace rules. Packet-monitor counters describe inspected copies and do not prove packets were changed or dropped on the wire.

A successful Tor exit check covers that request only. DNS interception makes a successful resolver query ambiguous; unsuccessful IPv6 probes do not prove complete blocking. The leak report therefore leaves unverified coverage explicit. WebRTC is not tested by that report.

Host root access, privileged raw-packet applications, a compromised kernel, browser account identity and end-to-end traffic correlation are outside the protection established here. There is no guarantee against blacklisting: destinations may restrict Tor exits independently of this software. Browser profile hardening is not a substitute for validating the browser actually in use.

## Recovery and operational limits

Run `sudo wraith -x` to request cleanup of a recorded session after a failed start. Retain console access: changes to firewall rules or MAC addresses can interrupt remote access. If cleanup reports errors, inspect the recorded state and host networking before restarting. Do not assume an error means original settings were restored. Kernel lockdown settings can require a reboot.

A process panic preserves the network policy and state instead of opening direct egress. Normal stop does not perform global log/history destruction. Explicit forensic cleanup and self-destruct options are destructive and are not required for the strict network preset. Xvfb requires a private Xauthority cookie and disables TCP listening; applications must explicitly use its DISPLAY and XAUTHORITY. Optional Xvfb, onion-service, bridge and service-installer paths still need separate runtime validation. The service installer defaults to standard network-online ordering and does not start immediately; unsupported early boot mode is rejected. Uninstall retains configuration/logs and stops on session-cleanup errors.

The traffic shaper uses reserved netem handle `a731:` and refuses to replace an existing configured root qdisc. Cleanup checks that handle and kind before removal. This convention prevents accidental deletion of unrelated queues; it is not protection against another privileged process using the same handle.

## Development and validation

| Crate | Responsibility |
| --- | --- |
| `wraith-core` | Configuration, state, cryptography and process controls |
| `wraith-net` | Firewall, interfaces, namespaces and optional tunnels |
| `wraith-tor` | Tor lifecycle, control protocol and HTTP relay |
| `wraith-guard` | DNS relay, watchdog and connectivity probes |
| `wraith-forensic` | Browser preferences and optional host controls |
| `wraith-cli` | Command line, session lifecycle and diagnostics |

Run the regression suite after changes:

```sh
cargo test --workspace --locked
cargo check --workspace --tests --target x86_64-unknown-linux-gnu --locked
cargo clippy --workspace --tests --target x86_64-unknown-linux-gnu --locked
```

Cross-target commands require the corresponding Rust target. Passing compilation and portable tests does not test Linux routing, DHCP recovery, kernel syscall behavior or firewall teardown. Follow the live-VM checklist in [the audit](SECURITY_AUDIT.md) before relying on the network policy. Report reproducible failures with the command, interface type, distribution and relevant sanitized logs; omit credentials and private keys.

## License

GPL-3.0, as declared in the workspace manifest. Use only on systems and networks you are authorized to administer.
