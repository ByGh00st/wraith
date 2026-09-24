#!/usr/bin/env python3
"""Offline installer regressions. All cases use --dry-run and a fake command PATH."""
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
if os.name == "nt" and BASH:
    # Git's bin/bash launcher prepends its own PATH, hiding the fake uname.
    candidate = Path(BASH).parent.parent / "usr" / "bin" / "bash.exe"
    if candidate.is_file():
        BASH = str(candidate)
HANDLER = r'''
import json, os, pathlib, shutil, sys
sys.stdout.reconfigure(newline="\n")
command, *args = sys.argv[1:]
root = pathlib.Path(os.environ["WRAITH_TEST_FIXTURE"])
if command == "uname":
    print(os.environ.get("WRAITH_TEST_OS", "Linux") if args == ["-s"] else os.environ["WRAITH_TEST_ARCH"])
elif command == "ldd":
    print(os.environ["WRAITH_TEST_LIBC"])
elif command == "getconf":
    print("glibc 2.36")
elif command == "dpkg":
    print(os.environ["WRAITH_TEST_DEB_ARCH"])
elif command == "dpkg-deb":
    print({"Package": "wraith", "Version": "1.4.0", "Architecture": os.environ["WRAITH_TEST_DEB_ARCH"]}[args[-1]])
elif command == "curl":
    output = args[args.index("--output") + 1]
    url = args[-1]
    name = "release.json" if url.endswith("/latest") else url.rsplit("/", 1)[1]
    shutil.copyfile(root / name, output)
else:
    raise SystemExit("Unexpected mutating command: " + command)
'''


def shell_path(path):
    return shlex.quote(str(path).replace("\\", "/"))


class InstallerTests(unittest.TestCase):
    def scenario(self, kind="tar", arch="x86_64", libc="gnu", fault=None):
        with tempfile.TemporaryDirectory(prefix="wraith-installer-test-") as directory:
            root = Path(directory)
            commands = root / "bin"
            commands.mkdir()
            handler = root / "handler.py"
            handler.write_text(HANDLER, encoding="utf-8")
            def wrapper(name, body):
                script = commands / name
                script.write_text("#!/bin/bash\n" + body + "\n", encoding="utf-8", newline="\n")
                script.chmod(0o755)
            for name in ["bash", "rm", "mktemp", "chmod"]:
                real = BASH if name == "bash" else shutil.which(name)
                if real is None and os.name == "nt":
                    candidate = Path(shutil.which("bash")).parent.parent / "usr" / "bin" / f"{name}.exe"
                    if candidate.is_file():
                        real = str(candidate)
                self.assertIsNotNone(real, name)
                wrapper(name, f'exec {shell_path(real)} "$@"')
            wrapper("python3", f'exec {shell_path(sys.executable)} "$@"')
            mocks = ["uname", "curl", "ldd", "getconf"]
            if kind == "deb":
                mocks += ["apt-get", "dpkg", "dpkg-deb"]
            for name in mocks:
                wrapper(name, f'exec {shell_path(sys.executable)} {shell_path(handler)} {name} "$@"')
            deb_arch = "amd64" if arch == "x86_64" else "arm64"
            asset = f"wraith_1.4.0_{deb_arch}.deb" if kind == "deb" else f"wraith-1.4.0-{arch}-unknown-linux-{libc}.tar.gz"
            if kind == "deb":
                # Only dpkg metadata control flow is mocked; this is not a .deb build test.
                (root / asset).write_bytes(b"mock Debian package")
            else:
                header = bytearray(64)
                header[:6] = b"\x7fELF\x02\x01"
                machine = 62 if arch == "x86_64" else 183
                header[18:20] = (0 if fault == "wrong_cpu" else machine).to_bytes(2, "little")
                with tarfile.open(root / asset, "w:gz") as tar:
                    for name, data in [("wraith", bytes(header)), ("LICENSE", b"license"), ("README.md", b"readme")]:
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        tar.addfile(member, io.BytesIO(data))
                    if fault in ("traversal", "symlink"):
                        member = tarfile.TarInfo("../escaped" if fault == "traversal" else "evil")
                        if fault == "symlink":
                            member.type = tarfile.SYMTYPE
                            member.linkname = "/etc/passwd"
                        tar.addfile(member)
            digest = hashlib.sha256((root / asset).read_bytes()).hexdigest()
            if fault == "checksum":
                digest = "0" * 64
            checksum = f"{digest}  {asset}\n"
            if fault == "duplicate_checksum":
                checksum *= 2
            (root / "SHA256SUMS.txt").write_text(checksum, encoding="ascii")
            assets = [{"name": name, "state": "uploaded", "browser_download_url": f"https://github.com/ByGh00st/wraith/releases/download/v1.4.0/{name}"} for name in [asset, "SHA256SUMS.txt"]]
            if fault == "missing_asset":
                assets.pop(0)
            if fault == "foreign_url":
                assets[0]["browser_download_url"] = "https://example.invalid/payload"
            if fault == "duplicate_asset":
                assets.append(assets[0])
            release = {"tag_name": "v1.4.0", "draft": False, "prerelease": fault == "prerelease", "assets": assets}
            (root / "release.json").write_text(json.dumps(release), encoding="utf-8")
            environment = dict(os.environ, PATH=str(commands), WRAITH_TEST_FIXTURE=str(root),
                WRAITH_TEST_ARCH=arch, WRAITH_TEST_LIBC=libc, WRAITH_TEST_DEB_ARCH=deb_arch)
            result = subprocess.run([BASH, str(ROOT / "install.sh"), "--dry-run"],
                env=environment, capture_output=True, text=True, timeout=30)
            if fault:
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("would install", result.stdout)
                diagnostic = {
                    "wrong_cpu": "Wrong ELF", "traversal": "Unexpected archive member",
                    "symlink": "Unexpected archive member", "checksum": "SHA256 mismatch",
                    "duplicate_checksum": "Missing or duplicate checksum",
                    "missing_asset": "unique uploaded asset", "foreign_url": "unique uploaded asset",
                    "duplicate_asset": "unique uploaded asset", "prerelease": "stable release metadata",
                }[fault]
                self.assertIn(diagnostic, result.stderr)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("no system changes", result.stdout)
                self.assertIn("/usr/bin/wraith" if kind == "deb" else "/usr/local/bin/wraith", result.stdout)

    def test_platform_selection(self):
        for kind, arch, libc in [("deb", "x86_64", "gnu"), ("deb", "aarch64", "gnu"),
                                ("tar", "x86_64", "gnu"), ("tar", "x86_64", "musl"),
                                ("tar", "aarch64", "musl")]:
            with self.subTest(kind=kind, arch=arch, libc=libc):
                self.scenario(kind, arch, libc)

    def test_untrusted_or_incomplete_assets_are_refused(self):
        for fault in ["wrong_cpu", "traversal", "symlink", "checksum", "duplicate_checksum",
                      "missing_asset", "foreign_url", "duplicate_asset", "prerelease"]:
            with self.subTest(fault=fault):
                self.scenario(fault=fault)


if __name__ == "__main__":
    unittest.main()
