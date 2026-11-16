#!/bin/bash
set -e
set -o xtrace

PUBLISH_ARG="$1"
PUBLISH_MODE="--dry-run"

if [ "${PUBLISH_ARG}" == "publish" ]; then
    PUBLISH_MODE=""
    echo "!!! REAL PUBLISH MODE ENABLED !!!"
else
    echo "Running in --dry-run mode. Use './publish-package.sh publish' to actually publish."
fi

cd ae-cvss-calculator

npm i
npm ci
npm run build

TARBALL_NAME=$(npm pack)
TARBALL_PATH="$(pwd)/${TARBALL_NAME}"

bash ../calculator-package-test/run-tests.sh "${TARBALL_PATH}"

cd ..
npm publish "${TARBALL_PATH}" ${PUBLISH_MODE}
rm "${TARBALL_PATH}"

echo "Publish workflow complete."
