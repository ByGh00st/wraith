#!/usr/bin/env python3
"""Validate Cargo's resolved workspace/deb metadata before packaging or tagging."""
import json
from pathlib import Path
import re
import sys


def validate(metadata, tag=""):
    packages = [p for p in metadata["packages"] if p["id"] in metadata["workspace_members"]]
    versions = {p["version"] for p in packages}
    if len(versions) != 1:
        raise ValueError("Workspace versions differ")
    version = versions.pop()
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or (tag and tag != f"v{version}"):
        raise ValueError("Release tag must equal v + the stable workspace version")
    names = {p["name"] for p in packages}
    for package in packages:
        for dependency in package["dependencies"]:
            if dependency["name"] in names and dependency["req"] not in (version, f"^{version}", f"={version}"):
                raise ValueError(f"Unversioned/mismatched internal dependency in {package['name']}")
    cli = next(p for p in packages if p["name"] == "wraith-cli")
    deb = cli["metadata"]["deb"]
    if deb["name"] != "wraith" or deb["revision"] != "":
        raise ValueError("Unexpected Debian name/revision")
    binary = ["target/release/wraith", "usr/bin/wraith", "0755"]
    if binary not in deb["assets"]:
        raise ValueError("Debian executable must be installed as /usr/bin/wraith, mode 0755")
    for source, destination, mode in deb["assets"]:
        if source.startswith("target/release/"):
            continue
        if not (Path(cli["manifest_path"]).parent / source).is_file():
            raise ValueError(f"Missing package asset: {source}")
        if not destination.startswith("usr/share/doc/wraith/") or mode != "0644":
            raise ValueError("Unexpected documentation asset destination/mode")
    return version


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8-sig") as stream:
        print(validate(json.load(stream), sys.argv[2] if len(sys.argv) > 2 else ""))
