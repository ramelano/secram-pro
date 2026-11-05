# Offline OSV advisory format

SecRam-Pro accepts an offline JSON snapshot in any of the following forms:

- one OSV vulnerability object;
- a JSON list of OSV vulnerability objects; or
- an object containing a `vulns` list.

The source is read locally only. There are no OSV API calls, package-index lookups, arbitrary command calls, or bundled production advisories. With no imported snapshot, `AdvisoryStore.status()` reports `data_unavailable`; matching is not reported as clean.

## Source and limits

The range and event meanings follow the [official OSV schema](https://ossf.github.io/osv-schema/). The importer records the SHA-256 of the exact source bytes as `importsha` and records the UTC import time as `importtime`. The source must be a regular non-symlink file no larger than 10 MiB and contain no more than 5,000 records. Validation completes before replacement. A rejected source leaves the prior valid snapshot unchanged.

The store is written through a temporary file and atomic replacement. Its file mode is `0600`; its containing directory is `0700`. Existing symlinks in the source or store path are rejected.

## Matching behavior

Only `affected.package.ecosystem == "PyPI"` is supported. Package names are compared with `packaging.utils.canonicalize_name`, and installed versions are parsed with `packaging.version.Version`.

For packaging-comparable `ECOSYSTEM` and `SEMVER` ranges, `introduced` is inclusive, `fixed` is exclusive, `last_affected` is inclusive, and `limit` is exclusive. An omitted closing event has the OSV-defined implicit infinite limit. An explicit `versions` list is compared with `Version` values, so equivalent packaging spellings can match. Withdrawn records are not active candidates.

`GIT` ranges, non-PyPI ecosystems, malformed or unparseable versions, missing `introduced` coverage, and other unsupported coverage produce a limitation and keep the result `clean: false`. A matching record is returned as a `candidate`/`match` with its real OSV `id`, `aliases`, `summary`, `references`, source `importsha`, `importtime`, canonical `matchedname`, installed `version`, and a conservative `reason`. It is an observation from advisory data, not confirmation of compromise or exploitability; no CVE or CVSS score is invented.

`match_installed()` reads the real local `importlib.metadata` distribution inventory. `match_packages()` accepts package dictionaries with `name`/`version` (and also `Name`/`Version` for metadata-shaped input). Both methods are offline.

## Result fields

`status()` reports snapshot availability and record count. `import_osv()` reports whether validation and atomic replacement were accepted. Matching returns `data_available`, `clean`, `candidates`, `matches`, `limitations`, package counts, and the imported source identifiers. `clean` is true only when advisory data is available, no candidate matched, and no unsupported or incomplete coverage was observed.
