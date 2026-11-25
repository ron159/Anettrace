#!/usr/bin/env bash
set -euo pipefail

artifact_id=${1:?missing artifact ID}
digest=${2:?missing artifact digest}
destination=${3:?missing destination}
archive="$RUNNER_TEMP/android-build-$artifact_id.zip"

# The run can list a finalized upload before its download URL serves the ZIP.
for delay in 0 2 4 8 16 32 60; do
    sleep "$delay"
    if gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" > "$archive"; then
        printf '%s  %s\n' "${digest#sha256:}" "$archive" | sha256sum --check
        unzip -q "$archive" -d "$destination"
        exit 0
    fi
done
echo "Unable to download Android artifact $artifact_id" >&2
exit 1
