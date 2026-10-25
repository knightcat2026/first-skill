#!/usr/bin/env python3
"""Build a deterministic source ZIP from an explicit, reviewable release allowlist."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "phone-clean-guard"
FILES = (
    ".gitignore", ".gitattributes", "LICENSE", "README.md", "CONTRIBUTING.md",
    "skills/phone-clean-guard/SKILL.md",
    "skills/phone-clean-guard/agents/openai.yaml",
    "skills/phone-clean-guard/scripts/phone_guard.py",
    "skills/phone-clean-guard/references/adb-helper.md",
    "skills/phone-clean-guard/references/platforms.md",
    "skills/phone-clean-guard/references/sources.md",
    "skills/phone-clean-guard/references/ui-playbook.md",
    "skills/phone-clean-guard/references/profiles.json",
    "skills/phone-clean-guard/references/contributing-profiles.md",
    "tests/test_phone_guard.py", "tests/test_package_release.py",
    "tools/package_release.py",
)


def build_release(root, output):
    root = Path(root).resolve(strict=True)
    output = Path(output).absolute()
    if output.resolve().is_relative_to(root):
        raise ValueError("Place the release ZIP outside the source repository.")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Release output already exists; refusing to overwrite.")
    # Read every explicit source before creating output. No recursive filesystem walk.
    entries = []
    for name in FILES:
        source = root / name
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(root):
            raise ValueError("Missing, symlinked or out-of-tree release source: " + name)
        entries.append((PREFIX + "/" + name, source.read_bytes()))
    with output.open("xb") as handle:
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None or archive.namelist() != [name for name, _ in entries]:
            raise ValueError("Release archive validation failed.")
        for name, data in entries:
            if archive.read(name) != data:
                raise ValueError("Release content mismatch: " + name)
    return {"files": len(entries), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "bytes": output.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build_release(ROOT, args.out)
    except (OSError, ValueError) as exc:
        parser.exit(2, "Release stopped: " + str(exc) + "\n")
    print(f"Files: {result['files']}\nBytes: {result['bytes']}\nSHA256: {result['sha256']}")


if __name__ == "__main__":
    main()
