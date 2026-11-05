#!/usr/bin/env bash
# Run explicitly on an ONLINE machine matching target Python/ABI/architecture.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
PYTHON=${PYTHON:-python3}
cd "$ROOT"
mkdir -p wheelhouse offline-source
"$PYTHON" -m pip download --dest wheelhouse -r requirements-lock.txt 'setuptools>=69' wheel
"$PYTHON" scripts/package_source.py offline-source/SecRam-Pro-source.zip
"$PYTHON" - <<'PY'
import hashlib,json
from pathlib import Path
files={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for folder in ('wheelhouse','offline-source') for p in sorted(Path(folder).glob('*')) if p.is_file()}
Path('offline-manifest.json').write_text(json.dumps({'files':files,'note':'Fingerprint snapshot, not authenticated signature; native OS packages not included.'},indent=2)+'\n')
PY
printf 'Transfer wheelhouse/, offline-source/ and offline-manifest.json. Native OS packages/Nmap must be prepared separately.\n'
