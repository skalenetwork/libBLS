#!/usr/bin/env python3
"""Check whether a package release already exists on PyPI and verify file hashes."""

import argparse
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify local build artifacts against PyPI published release."
    )
    parser.add_argument("package", help="PyPI package name (e.g. t-encrypt)")
    parser.add_argument("version", help="Release version to check")
    parser.add_argument(
        "artifact_dir",
        type=pathlib.Path,
        help="Directory containing local build artifacts",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.artifact_dir.is_dir():
        print(f"Artifact dir not found: {args.artifact_dir}", file=sys.stderr)
        return 2

    expected = {}
    for path in sorted(args.artifact_dir.rglob("*")):
        if path.is_file():
            expected[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()

    url = f"https://pypi.org/pypi/{args.package}/json"
    req = urllib.request.Request(url, headers={"User-Agent": "libBLS-ci-check"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as err:
        if err.code == 404:
            print(f"ABSENT: {args.package}@{args.version} not found on PyPI")
            return 0
        raise

    releases = payload.get("releases", {})
    remote_files = releases.get(args.version, [])
    if not remote_files:
        print(f"ABSENT: {args.package}@{args.version} not found on PyPI")
        return 0

    published = {}
    for meta in remote_files:
        filename = meta.get("filename")
        digest = meta.get("digests", {}).get("sha256")
        if filename and digest:
            published[filename] = digest

    if set(expected) != set(published):
        print(
            f"MISMATCH: expected files {sorted(expected)} but PyPI has {sorted(published)}",
            file=sys.stderr,
        )
        return 1

    for name, digest in sorted(expected.items()):
        if published.get(name) != digest:
            print(f"MISMATCH: {name} hash differs", file=sys.stderr)
            return 1

    print(f"MATCH: {args.package}@{args.version} already published and hashes match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
