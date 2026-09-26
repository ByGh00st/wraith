# Wraith v1.4.2

**Secure recovery-directory migration for strict namespace startup.**

## Fixed

Older packages could leave `/var/lib/wraith` root-owned but group-writable. Before writing a new ownership lease, Wraith now removes only group and other write bits, then verifies the resulting ownership and mode. It never repairs a foreign-owned path and never follows a symlink.

This resolves `Kernel Namespace Error: Unsafe recovery directory owner/mode` for affected root-owned legacy installations without weakening ownership checks.

## Upgrade

```bash
sudo apt update
sudo apt install wraith
wraith --version
```

Then start a new session with `sudo wraith -Fs`.
