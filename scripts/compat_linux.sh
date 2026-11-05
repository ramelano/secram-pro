#!/usr/bin/env bash
# Finite sandbox-only userspace compatibility checks, not native kernel certification.
set -euo pipefail
PROJECT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${SECRAM_COMPAT_DIR:-/home/ubuntu/secram-compat}
MODE=${1:?Usage: compat_linux.sh prepare|test}
mkdir -p "$BASE" "$PROJECT/docs/compat"

run_root() {
    local root=$1 command=$2 network_mode=${3:-online}
    local ns=(--mount --pid --fork --kill-child)
    if [[ $network_mode == offline ]]; then ns+=(--net); fi
    sudo unshare "${ns[@]}" bash -c '
        set -euo pipefail
        mount --make-rprivate /
        root=$1; command=$2; network_mode=$3
        if [[ $network_mode == offline ]]; then ip link set lo up; fi
        mkdir -p "$root/proc" "$root/dev" "$root/sys"
        mount -t proc proc "$root/proc"
        mount --bind /dev "$root/dev"
        mount -o remount,bind,ro "$root/dev"
        mount --bind /sys "$root/sys"
        mount -o remount,bind,ro "$root/sys"
        chroot "$root" /bin/bash -c "$command"
    ' bash "$root" "$command" "$network_mode"
}

prepare_one() {
    local label=$1 image=$2 root="$BASE/$1-bundle/rootfs"
    echo "$label: downloading official OCI userspace"
    skopeo --command-timeout=240s copy --override-os linux --override-arch amd64 \
        "docker://docker.io/library/$image" "oci:$BASE/$label-oci:compat" \
        > "$BASE/$label-pull.log" 2>&1
    skopeo inspect "oci:$BASE/$label-oci:compat" > "$PROJECT/docs/compat/$label-image.json"
    sudo umoci unpack --image "$BASE/$label-oci:compat" "$BASE/$label-bundle" \
        > "$BASE/$label-unpack.log" 2>&1
    sudo cp --remove-destination /etc/resolv.conf "$root/etc/resolv.conf"
    sudo mkdir -p "$root/opt"
    sudo cp "$PROJECT/requirements-lock.txt" "$root/opt/compat-requirements.txt"
    local packages
    if [[ $label == fedora43 ]]; then
        packages='dnf -y --setopt=install_weak_deps=False install python3 python3-pip nmap mesa-libGL mesa-libEGL libxkbcommon fontconfig dbus-libs glib2 util-linux iproute dejavu-sans-fonts'
    else
        packages='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y --no-install-recommends python3 python3-venv python3-pip nmap libgl1 libegl1 libxkbcommon0 libfontconfig1 libdbus-1-3 libglib2.0-0t64 util-linux iproute2 fonts-dejavu-core'
    fi
    echo "$label: installing distro Python/Nmap/Qt dependencies"
    run_root "$root" "$packages; python3 -m venv /opt/secram-venv; /opt/secram-venv/bin/python -m pip install -r /opt/compat-requirements.txt 'setuptools>=69'" \
        > "$BASE/$label-provision.log" 2>&1
    echo "$label: userspace ready"
}

test_one() {
    local label=$1 root="$BASE/$1-bundle/rootfs"
    if ! sudo chroot "$root" /opt/secram-venv/bin/python --version >/dev/null 2>&1; then
        echo "$label: environment missing"; return 1
    fi
    sudo mkdir -p "$root/opt/project" "$root/opt/results"
    tar -C "$PROJECT" --exclude=__pycache__ --exclude='*.egg-info' -cf - \
        pyproject.toml requirements-lock.txt README.md LICENSE src tests scripts | sudo tar -C "$root/opt/project" -xf -
    echo "$label: testing current source with isolated loopback network"
    local command='cd /opt/project; export QT_QPA_PLATFORM=offscreen PYTHONDONTWRITEBYTECODE=1;
        /opt/secram-venv/bin/python -m pip install --no-deps --no-build-isolation -e . >/opt/results/package-install.txt 2>&1 || exit $?;
        cat /etc/os-release > /opt/results/os-release.txt;
        /opt/secram-venv/bin/python --version > /opt/results/python-version.txt;
        nmap --version > /opt/results/nmap-version.txt;
        /opt/secram-venv/bin/python -m pip freeze --exclude-editable > /opt/results/python-packages.txt;
        /opt/secram-venv/bin/python -m pytest -q -p no:cacheprovider --junitxml=/opt/results/tests.xml > /opt/results/tests.txt 2>&1;
        status=$?; echo "$status" > /opt/results/test-exit-code.txt;
        /opt/secram-venv/bin/python -m secram --data-dir /tmp/gui-smoke --smoke-test > /opt/results/gui-smoke.txt 2>&1;
        echo "$?" > /opt/results/gui-exit-code.txt;
        exit "$status"'
    local status=0
    run_root "$root" "$command" offline > "$BASE/$label-run.log" 2>&1 || status=$?
    mkdir -p "$PROJECT/docs/compat/$label"
    sudo cp -a "$root/opt/results/." "$PROJECT/docs/compat/$label/"
    sudo chown -R "$(id -u):$(id -g)" "$PROJECT/docs/compat/$label"
    echo "$label: compatibility job exit $status"
    [[ -f "$PROJECT/docs/compat/$label/tests.txt" ]] && tail -n 8 "$PROJECT/docs/compat/$label/tests.txt"
    return "$status"
}

case "$MODE" in
    update)
        update_one() {
            local label=$1 root="$BASE/$1-bundle/rootfs" packages
            sudo cp "$PROJECT/requirements-lock.txt" "$root/opt/compat-requirements.txt"
            if [[ $label == fedora43 ]]; then packages='dnf -y --setopt=install_weak_deps=False install util-linux iproute dejavu-sans-fonts';
            else packages='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y --no-install-recommends util-linux iproute2 fonts-dejavu-core'; fi
            echo "$label: updating existing test userspace"
            run_root "$root" "$packages; /opt/secram-venv/bin/python -m pip install -r /opt/compat-requirements.txt" > "$BASE/$label-update.log" 2>&1
            echo "$label: test dependencies updated"
        }
        update_one fedora43 & p1=$!
        update_one debian13 & p2=$!
        status=0; wait "$p1" || status=1; wait "$p2" || status=1; exit "$status" ;;
    prepare)
        prepare_one fedora43 fedora:43 & p1=$!
        prepare_one debian13 debian:13 & p2=$!
        status=0; wait "$p1" || status=1; wait "$p2" || status=1; exit "$status" ;;
    test)
        if [[ ${2:-all} == fedora43 || ${2:-all} == debian13 ]]; then
            test_one "$2"; exit $?
        fi
        test_one fedora43 & p1=$!
        test_one debian13 & p2=$!
        status=0; wait "$p1" || status=1; wait "$p2" || status=1; exit "$status" ;;
    *) echo 'Usage: compat_linux.sh prepare|update|test' >&2; exit 2 ;;
esac
