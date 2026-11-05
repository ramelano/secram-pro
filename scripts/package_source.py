"""Package source/test/docs only; never include runtime DB, secrets or venv."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main() -> int:
    parser = argparse.ArgumentParser(description="SecRam-Pro kaynak arşivi")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    files = [root / name for name in ("pyproject.toml", "requirements-lock.txt", ".gitignore", "README.md",
                                      "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md")]
    for name in ("src/secram", "tests", "scripts", "docs", "resources", "examples", ".github"):
        files.extend(path for path in (root / name).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts)
    files = sorted(set(files))
    if not all(path.is_file() for path in files):
        raise RuntimeError("Required source file is missing")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(args.output, "w", ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, "secram-pro/" + path.relative_to(root).as_posix())
        for path in sorted((root / "resources").rglob("*")):
            if path.is_dir():
                archive.writestr("secram-pro/" + path.relative_to(root).as_posix() + "/", "")
    with ZipFile(args.output) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("Archive integrity check failed")
        names = archive.namelist()
        if any(".venv" in name or "/.env" in name or ".sqlite" in name for name in names):
            raise RuntimeError("Private runtime file found in archive")
    print(json.dumps({"archive": str(args.output.resolve()), "source_files": len(files),
                      "bytes": args.output.stat().st_size,
                      "sha256": hashlib.sha256(args.output.read_bytes()).hexdigest()}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
