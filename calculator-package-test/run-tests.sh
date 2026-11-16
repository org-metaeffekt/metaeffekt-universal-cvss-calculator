#!/bin/bash

if [ $# -lt 1 ]; then
    echo "Usage: $0 <version|tarball> [test-dir...]"
    exit 1
fi

SOURCE="$1"
shift

if [ -f "${SOURCE}" ]; then
    PACKAGE_SPEC="$(cd "$(dirname "${SOURCE}")" && pwd)/$(basename "${SOURCE}")"
else
    PACKAGE_SPEC="ae-cvss-calculator@${SOURCE}"
fi

cd "$(dirname "$0")" || exit 1

if [ $# -gt 0 ]; then
    TEST_DIRS=("$@")
else
    TEST_DIRS=(commonjs esm consumers/*)
fi

PASSED=()
FAILED=()

for TEST_DIR in "${TEST_DIRS[@]}"; do
    if [ ! -f "${TEST_DIR}/package.json" ]; then
        echo "Skipping ${TEST_DIR}, no package.json"
        continue
    fi

    echo
    echo "=== ${TEST_DIR} with ${PACKAGE_SPEC}"

    if (
        cd "${TEST_DIR}" &&
        rm -rf node_modules package-lock.json dist &&
        npm install --no-save --no-audit --no-fund "${PACKAGE_SPEC}" &&
        npm test
    ); then
        PASSED+=("${TEST_DIR}")
    else
        FAILED+=("${TEST_DIR}")
    fi
done

echo
echo "Package: ${PACKAGE_SPEC}"
echo "Passed: ${#PASSED[@]}"
for TEST_DIR in "${PASSED[@]}"; do
    echo "  ${TEST_DIR}"
done
echo "Failed: ${#FAILED[@]}"
for TEST_DIR in "${FAILED[@]}"; do
    echo "  ${TEST_DIR}"
done

[ ${#FAILED[@]} -eq 0 ]
