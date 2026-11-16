import fs from "node:fs";
import path from "node:path";

const vendorDir = path.join(__dirname, "vendor");

const copy = require(path.join(vendorDir, "ae-cvss-calculator.cjs")) as {
  fromVector: (vector: string) => { calculateScores(): { overall: number } } | undefined;
};
const copied = copy.fromVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")?.calculateScores().overall;
if (copied !== 9.8) {
  throw new Error(`Copied bundle: expected 9.8, got ${copied}`);
}

if (!fs.existsSync(path.join(vendorDir, "ae-cvss-calculator.LICENSE"))) {
  throw new Error("Copied LICENSE is missing");
}

console.log(`node-cjs: copied bundle scored ${copied}`);
