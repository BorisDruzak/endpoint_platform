#!/bin/bash
set -euo pipefail
umask 022
test "$(id -u)" != 0 || { echo 'Build as a non-root user on a disposable ALT worker' >&2; exit 1; }
readonly kit=$(cd -- "$(dirname -- "$0")" && pwd -P)
readonly build="$PWD/cups-repair-build"
test ! -e "$build" || { echo 'Build directory already exists' >&2; exit 1; }
mkdir -m 0755 "$build"
rpmbuild --rebuild --define "_topdir $build" "$kit/cups-browsed-2.1.1-alt1.endpoint2.src.rpm"
rpm -qp --qf '%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' "$build/RPMS/x86_64/cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm"
sha256sum "$build/RPMS/x86_64/cups-browsed-2.1.1-alt1.endpoint2.x86_64.rpm"
