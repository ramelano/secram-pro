"""Summarize real recorded userspace tests without claiming native certification."""
import json
import os
from pathlib import Path
import xml.etree.ElementTree as ET


def main():
    root = Path(__file__).resolve().parents[1]
    rows = []
    for label in ("fedora43", "debian13"):
        directory = root / "docs/compat" / label
        suites = ET.parse(directory / "tests.xml").getroot().findall("testsuite")
        counts = {name: sum(int(s.attrib.get(name, 0)) for s in suites)
                  for name in ("tests", "failures", "errors", "skipped")}
        test_exit = int((directory / "test-exit-code.txt").read_text().strip())
        gui_exit = int((directory / "gui-exit-code.txt").read_text().strip())
        os_release = {}
        for line in (directory / "os-release.txt").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1); os_release[key] = value.strip('"')
        image = json.loads((root / "docs/compat" / f"{label}-image.json").read_text())
        passed = test_exit == gui_exit == counts["failures"] == counts["errors"] == 0
        limited = passed and counts["skipped"] > 0
        skipped_tests = [case.attrib.get("name") for case in ET.parse(directory / "tests.xml").getroot().iter("testcase")
                         if case.find("skipped") is not None]
        rows.append({"label": label, "os": os_release.get("PRETTY_NAME"),
                     "python": (directory / "python-version.txt").read_text().strip(),
                     "nmap": (directory / "nmap-version.txt").read_text().splitlines()[0],
                     "image_digest": image.get("Digest"), "tests": counts,
                     "test_exit": test_exit, "gui_exit": gui_exit,
                     "skipped_tests": skipped_tests,
                     "limitations": ["Rootless Lab integration unverified in this chroot/namespace environment: unshare Operation not permitted"] if limited else [],
                     "status": "passed_userspace_limited" if limited else "passed_userspace" if passed else "failed_userspace"})
    output = {"shared_kernel": os.uname().release,
              "execution": "official OCI rootfs in mount/PID/network namespaces; offline loopback tests",
              "native_kernel_selinux_systemd_desktop_verified": False, "results": rows}
    (root / "docs/compat/summary.json").write_text(json.dumps(output, ensure_ascii=False, indent=2)+"\n")
    print(json.dumps(output, ensure_ascii=False, indent=2))
    return 0 if all(row["status"] in {"passed_userspace", "passed_userspace_limited"} for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
