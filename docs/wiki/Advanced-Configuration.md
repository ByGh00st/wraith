# Advanced configuration

> **05 / CONFIGURE** · Enable controls with a clear understanding of their scope.

## Full-security preset

`-Fs` combines full-security (`-F`) and start (`-s`):

```bash
sudo wraith -Fs
```

Required startup controls must succeed before activation. This preset requires the watchdog and rejects `--no-killswitch`.

| Host prerequisite | Required value |
| :--- | :--- |
| Kernel lockdown | `confidentiality` |
| `kernel.kexec_load_disabled` | `1` |
| `kernel.yama.ptrace_scope` | `3` |

These irreversible settings must already be configured by the host administrator. Wraith checks them rather than enabling them irreversibly for a temporary session. Reversible controls are recorded for restoration.

## Optional routes and services

| Option | Purpose | Requirement or boundary |
| :--- | :--- | :--- |
| `-W /path/to/vpn.conf` | Carry Tor's outer connection over WireGuard | WireGuard tools and a valid configuration; trust shifts to the VPN path |
| `--onion 80:8080` | Map onion-service port 80 to local port 8080 | A local service and working Tor transport |
| `--shaper` | Apply owned netem delay settings | No demonstrated resistance to traffic correlation |
| `--display-sandbox` | Create a private virtual display | Xvfb and xauth; applications must use that display |
| `--honey-ports` / `--honey-lan` | Run optional decoy listeners | Use on authorized systems and networks; not a malware-removal guarantee |

Use separate sessions to evaluate different configurations. Consult `wraith start --help` and the [full command reference](https://github.com/ByGh00st/wraith#cli-reference).

## Optional cover requests

```bash
sudo wraith -s --jitter --jitter-endpoint https://your-domain.example/cover
```

Use an endpoint you control or are authorized to use. The worker makes a real HTTPS GET through Tor after each randomized **15–45 second** pause, caps responses at **16 KiB**, and cancels on shutdown. It does not fall back to direct traffic and is not automatically enabled by the strict preset.

## Scope of host controls

Browser preferences apply to managed profiles; confirm which profile an application uses. Fontconfig restrictions do not guarantee a universal font count. Seccomp restricts ptrace and alternate-ABI bypasses, but is not a general syscall allowlist. Cgroup membership is bookkeeping; netfilter enforces egress. The experimental physical-interface fastpath is not an active protection layer.

**Next:** [Troubleshooting and recovery →](Troubleshooting.md)
