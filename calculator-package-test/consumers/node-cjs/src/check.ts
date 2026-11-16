import { summarizeScores } from "./apply-vector";
import { scoreVector } from "./from-vector";
import { severityToNumber } from "./named-classes";
import { overallOf } from "./require-fallback";

const V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V30 = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
const V4 = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H";

const summary = summarizeScores([
  { kind: "v3", vector: V30 },
  { kind: "v4", vector: V4 },
]);

const results: [string, unknown, unknown][] = [
  ["fromVector, 3.1", scoreVector(V31)?.base, 9.8],
  ["fromVector, 4.0 level", scoreVector(V4)?.level, "medium"],
  ["named classes, 3.1", severityToNumber(V31), 9.8],
  ["named classes, 4.0", severityToNumber(V4), 5.9],
  ["applyVector, 3.0", summary.v3, "9.8"],
  ["applyVector, 4.0", summary.v4, "5.9"],
  ["require with fallback, 3.1", overallOf(V31), 9.8],
];

for (const [name, actual, expected] of results) {
  if (actual !== expected) {
    throw new Error(`${name}: expected ${expected}, got ${actual}`);
  }
}

console.log(`node-cjs: ${results.length} checks passed`);
