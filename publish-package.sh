#!/bin/bash
set -e

PUBLISH_ARG="$1"
PUBLISH_MODE="--dry-run"

if [ "${PUBLISH_ARG}" == "publish" ]; then
    PUBLISH_MODE=""
    echo "!!! REAL PUBLISH MODE ENABLED !!!"
else
    echo "Running in --dry-run mode. Use './publish-package.sh publish' to actually publish."
fi

cd ae-cvss-calculator

npm ci
npm run build

TARBALL_NAME=$(npm pack)
TARBALL_PATH="$(pwd)/${TARBALL_NAME}"

cd ../calculator-package-test
rm -rf node_modules package-lock.json
npm install "${TARBALL_PATH}" --no-save
npm test

cd ..
npm publish "${TARBALL_PATH}" ${PUBLISH_MODE}
rm "${TARBALL_PATH}"

echo "Publish workflow complete."
