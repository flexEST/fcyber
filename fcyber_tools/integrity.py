"""Capture and compare SHA-256 inventories of local directories."""

import hashlib
import json
import os
from pathlib import Path


def snapshot(root):
    if not root.is_dir():
        raise ValueError(f"Not a directory: {root}")
    files = {}
    for directory, subdirectories, names in os.walk(root, onerror=raise_walk_error):
        folder = Path(directory)
        subdirectories[:] = sorted(
            name for name in subdirectories
            if name != ".git" and not (folder / name).is_symlink()
        )
        for name in sorted(names):
            path = folder / name
            if name == ".git" or path.is_symlink() or not path.is_file():
                continue
            with path.open("rb") as stream:
                files[path.relative_to(root).as_posix()] = hashlib.file_digest(
                    stream, "sha256"
                ).hexdigest()
    return files


def raise_walk_error(error):
    raise error


def inventory(args):
    root = args.directory.resolve()
    manifest = args.manifest.resolve()
    if manifest.is_relative_to(root):
        raise ValueError("Store the manifest outside the monitored directory")
    current = snapshot(root)

    if args.action == "create":
        with manifest.open("x", encoding="utf-8") as stream:
            json.dump({"version": 1, "files": current}, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(f"Recorded {len(current)} files")
        return 0

    with manifest.open(encoding="utf-8") as stream:
        baseline = json.load(stream)
    if not isinstance(baseline, dict) or baseline.get("version") != 1:
        raise ValueError("Unrecognized manifest format")
    previous = baseline.get("files")
    if not isinstance(previous, dict) or not all(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
        for value in previous.values()
    ):
        raise ValueError("Invalid manifest file entries")
    report = {
        "added": sorted(current.keys() - previous.keys()),
        "removed": sorted(previous.keys() - current.keys()),
        "changed": sorted(
            name for name in previous.keys() & current.keys() if previous[name] != current[name]
        ),
    }
    print(json.dumps(report, indent=2))
    return int(any(report.values()))
