#!/bin/bash
set -e

PUBLISH_MODE="--dry-run"
if [ "$1" == "publish" ]; then
    PUBLISH_MODE=""
    echo "!!! REAL PUBLISH MODE ENABLED !!!"
else
    echo "Running in --dry-run mode. Use './publish-package.sh publish' to actually publish."
fi

cd ae-cvss-calculator

npm ci
npm run build

TARBALL_NAME=$(npm pack)
TARBALL_PATH="$(pwd)/$TARBALL_NAME"

echo "Generated tarball: $TARBALL_NAME"

cd ../calculator-package-test
rm -rf node_modules package-lock.json
npm install "$TARBALL_PATH" --no-save
npm test

cd ../ae-cvss-calculator
npm publish "$TARBALL_PATH" $PUBLISH_MODE

cd ../
rm "ae-cvss-calculator/$TARBALL_NAME"

echo "Publish workflow complete."
