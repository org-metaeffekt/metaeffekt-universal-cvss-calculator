import { scoreV2, scoreV4 } from "./cvss.js";

const v4 = scoreV4("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H");
if (v4?.score !== 5.9 || v4.label !== "MEDIUM") {
    throw new Error("CVSS 4.0: expected 5.9 MEDIUM, got " + JSON.stringify(v4));
}

const v2 = scoreV2("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P");
if (v2?.score !== 7.5 || v2.label !== "HIGH") {
    throw new Error("CVSS 2.0: expected 7.5 HIGH, got " + JSON.stringify(v2));
}

console.log("node-esm-nodenext default import: CVSS 4.0 " + v4.score + ", CVSS 2.0 " + v2.score);
