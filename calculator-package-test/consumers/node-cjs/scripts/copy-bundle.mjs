import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const packageDir = path.dirname(require.resolve("ae-cvss-calculator/package.json"));
const vendorDir = new URL("../dist/vendor/", import.meta.url);

const copies = [
  [path.join(packageDir, "dist", "ae-cvss-calculator.js"), "ae-cvss-calculator.cjs"],
  [path.join(packageDir, "LICENSE"), "ae-cvss-calculator.LICENSE"],
];

fs.mkdirSync(vendorDir, { recursive: true });
for (const [source, target] of copies) {
  fs.copyFileSync(source, new URL(target, vendorDir));
}
