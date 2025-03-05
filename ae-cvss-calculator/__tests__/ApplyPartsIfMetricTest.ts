/*
 * Copyright 2024 the original author or authors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { applyVectorPartsIfMetricsHigher, applyVectorPartsIfMetricsLower, fromVector } from "../src";
import { expect } from "@jest/globals";

const jestConsole = console;

beforeEach(() => {
    global.console = require('console');
});

afterEach(() => {
    global.console = jestConsole;
});

describe('CvssVectorTest', () => {

    it('applyPartsIfMetricV2Test', () => {
        // base highest + lowest
        assertPartsLowerHigherApplied(
            "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", "CVSS:2.0/AV:L/AC:H/Au:M/C:N/I:N/A:N",
            "AV:L/AC:H/Au:M/C:N/I:N/A:N",
            "AV:N/AC:L/Au:N/C:C/I:C/A:C"
        );
        // base lowest + not defined
        assertPartsLowerHigherApplied(
            "CVSS:2.0/AV:L/AC:H/Au:M/C:N/I:N/A:N", "CVSS:2.0/AV:ND/AC:ND/Au:ND/C:ND/I:ND/A:ND",
            "",
            "AV:L/AC:H/Au:M/C:N/I:N/A:N"
        );
        // temporal/environmental lowest + highest
        assertPartsLowerHigherApplied(
            "CVSS:2.0/E:U/RL:OF/RC:UC/CDP:N/TD:N/CR:L/IR:L/AR:L", "CVSS:2.0/E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H",
            "E:U/RL:OF/RC:UC/CDP:N/TD:N/CR:L/IR:L/AR:L",
            "E:H/RL:U/RC:C/CDP:H/TD:H/CR:H/IR:H/AR:H"
        );
        // temporal/environmental some interesting values
        assertPartsLowerHigherApplied(
            "CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:W/RC:UR/CDP:LM/TD:M/CR:L/IR:H/AR:M", "CVSS:2.0/AV:A/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:U/RC:ND/CDP:ND/TD:H/CR:ND/IR:ND/AR:ND",
            "AV:A/AC:L/Au:N/C:P/I:P/A:N/E:F/RL:W/RC:UR/CDP:ND/TD:M/CR:L/IR:ND/AR:M",
            "AV:A/AC:L/Au:N/C:P/I:P/A:N/E:ND/RL:U/RC:ND/CDP:LM/TD:H/CR:ND/IR:H/AR:ND"
        );
    });

    it('applyPartsIfMetricV31Test', () => {
        assertPartsLowerHigherApplied(
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N/RL:O/MAC:H", "CVSS:3.1/AV:N/MAV:P/AC:H/MAC:H/E:U/RL:W/CR:M",
            "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N/E:U/RL:O/MAV:P/MAC:H/CR:M",
            "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N/RL:W/MAC:H");
        {
            const i = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C";
            const m = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U";
            const lower = "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U";
            const higher = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C";
            assertPartsLowerHigherApplied(i, m, lower, higher);
            assertPartsLowerHigherApplied(m, i, lower, higher);
        }
        // base lowest possible values + modified highest possible values
        assertPartsLowerHigherApplied(
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "CVSS:3.1/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H/CR:X/IR:X/AR:X",
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
            "CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H");
        // base highest possible values + modified lowest possible values + modified requirement
        assertPartsLowerHigherApplied(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.1/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N/CR:H/IR:M/AR:L",
            // CR:H is not applied, since medium is the center where ND is equals
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N/IR:M/AR:L",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MS:C/CR:H");
        // temporal lowest set values
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:U/RL:O/RC:U", "CVSS:3.1/E:X/RL:X/RC:X",
            "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/");
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:U/RL:O/RC:U", "CVSS:3.1/E:P/RL:T/RC:R",
            "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/E:P/RL:T/RC:R");
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:U/RL:O/RC:U", "CVSS:3.1/E:F/RL:W/RC:C",
            "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/E:F/RL:W/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:U/RL:O/RC:U", "CVSS:3.1/E:H/RL:U/RC:C",
            "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/E:H/RL:U/RC:C");
        // temporal highest
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:H/RL:U/RC:C", "CVSS:3.1/E:F/RL:W/RC:R",
            "CVSS:3.1/E:F/RL:W/RC:R",
            "CVSS:3.1/E:H/RL:U/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:H/RL:U/RC:C", "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/E:U/RL:O/RC:U",
            "CVSS:3.1/E:H/RL:U/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.1/E:H/RL:U/RC:C", "CVSS:3.1/E:X/RL:X/RC:X",
            "CVSS:3.1/E:H/RL:U/RC:C",
            "CVSS:3.1/");
    });

    it('applyPartsIfMetricV30Test', () => {
        assertPartsLowerHigherApplied(
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N/RL:O/MAC:H", "CVSS:3.0/AV:N/MAV:P/AC:H/MAC:H/E:U/RL:W/CR:M",
            "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N/E:U/RL:O/MAV:P/MAC:H/CR:M",
            "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:L/A:N/RL:W/MAC:H");
        {
            const i = "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C";
            const m = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U";
            const lower = "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/E:U/RL:O/RC:U";
            const higher = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H/RL:U/RC:C";
            assertPartsLowerHigherApplied(i, m, lower, higher);
            assertPartsLowerHigherApplied(m, i, lower, higher);
        }
        // base lowest possible values + modified highest possible values
        assertPartsLowerHigherApplied(
            "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", "CVSS:3.0/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H/CR:X/IR:X/AR:X",
            "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N",
            "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N/MAV:N/MAC:L/MPR:N/MUI:N/MS:C/MC:H/MI:H/MA:H");
        // base highest possible values + modified lowest possible values + modified requirement
        assertPartsLowerHigherApplied(
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS:3.0/MAV:P/MAC:H/MPR:H/MUI:R/MS:C/MC:N/MI:N/MA:N/CR:H/IR:M/AR:L",
            // CR:H is not applied, since medium is the center where ND is equals
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MAV:P/MAC:H/MPR:H/MUI:R/MC:N/MI:N/MA:N/IR:M/AR:L",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/MS:C/CR:H");
        // temporal lowest set values
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:U/RL:O/RC:U", "CVSS:3.0/E:X/RL:X/RC:X",
            "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/");
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:U/RL:O/RC:U", "CVSS:3.0/E:P/RL:T/RC:R",
            "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/E:P/RL:T/RC:R");
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:U/RL:O/RC:U", "CVSS:3.0/E:F/RL:W/RC:C",
            "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/E:F/RL:W/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:U/RL:O/RC:U", "CVSS:3.0/E:H/RL:U/RC:C",
            "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/E:H/RL:U/RC:C");
        // temporal highest
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:H/RL:U/RC:C", "CVSS:3.0/E:F/RL:W/RC:R",
            "CVSS:3.0/E:F/RL:W/RC:R",
            "CVSS:3.0/E:H/RL:U/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:H/RL:U/RC:C", "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/E:U/RL:O/RC:U",
            "CVSS:3.0/E:H/RL:U/RC:C");
        assertPartsLowerHigherApplied(
            "CVSS:3.0/E:H/RL:U/RC:C", "CVSS:3.0/E:X/RL:X/RC:X",
            "CVSS:3.0/E:H/RL:U/RC:C",
            "CVSS:3.0/");
    });

    it('applyPartsIfMetricV4Test', () => {
        // base lowest + base highest
        assertPartsLowerHigherApplied(
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        );
        // base highest + environment lowest
        assertPartsLowerHigherApplied(
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", "CVSS:4.0/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/MAV:P/MAC:H/MAT:P/MPR:H/MUI:A/MVC:N/MVI:N/MVA:N/MSC:N/MSI:N/MSA:N",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        );
        // supplemental
        assertPartsLowerHigherApplied(
            "CVSS:4.0/S:N/AU:N/R:A/V:D/RE:L/U:Clear", "CVSS:4.0/S:P/AU:Y/R:I/V:C/RE:H/U:Red",
            "CVSS:4.0/S:N/AU:N/R:A/V:D/RE:L/U:Clear",
            "CVSS:4.0/S:P/AU:Y/R:I/V:C/RE:H/U:Red"
        );
        // environmental security requirement
        assertPartsLowerHigherApplied("CVSS:4.0/E:A/CR:H/IR:H/AR:H", "CVSS:4.0/E:U/CR:L/IR:L/AR:L",
            "CVSS:4.0/E:U/CR:L/IR:L/AR:L",
            "CVSS:4.0/E:A/CR:H/IR:H/AR:H"
        );
        assertPartsLowerHigherApplied("CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H", "CVSS:4.0/CR:L/IR:M/AR:H",
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/CR:L/IR:M/AR:H",
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H"
        );
        assertPartsLowerHigherApplied("CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/CR:L/IR:M/AR:H", "CVSS:4.0/CR:X/IR:X/AR:X",
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H/CR:L/IR:M/AR:H",
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:L/SA:H"
        );
        // random
        assertPartsLowerHigherApplied("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:N/VA:L/SC:N/SI:L/SA:N", "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:N/VC:N/VI:L/VA:L/SC:L/SI:N/SA:L",
            "CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N",
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L"
        );
        assertPartsLowerHigherApplied("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L", "CVSS:4.0/MAV:A/MAC:L/MAT:P/MPR:L/MUI:N/MVC:N/MVI:L/MVA:N/MSC:N/MSI:X/MSA:S",
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/MAT:P/MPR:L/MUI:N/MVC:N/MVI:L/MVA:N/MSC:N",
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:L/SI:L/SA:L/MAV:A/MAC:L/MAT:X/MPR:X/MUI:N/MVC:N/MVI:L/MVA:X/MSC:X/MSI:X/MSA:S"
        );
    });

    function assertPartsLowerHigherApplied(originalVector: string, applyMetrics: string, expectedLower: string, expectedHigher: string) {
        const lower = fromVector(originalVector);
        applyVectorPartsIfMetricsLower(lower, applyMetrics);
        expect(stripXValues(lower.toString())).toBe(stripXValues(expectedLower));

        const higher = fromVector(originalVector);
        applyVectorPartsIfMetricsHigher(higher, applyMetrics);
        expect(stripXValues(higher.toString())).toBe(stripXValues(expectedHigher));
    }

    function stripXValues(vector: string): string {
        return vector.replace(/\/[A-Z]+:X/g, '');
    }
});