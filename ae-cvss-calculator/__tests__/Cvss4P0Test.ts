/*
 * Copyright 2024 the original author or authors.
 *
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
import {Cvss4P0} from "../src";

import fs from "fs";

describe('Cvss4P0', () => {
    it('should create an instance with default values', () => {
        const cvss = new Cvss4P0();
        expect(cvss).toBeDefined();
    });

    it('should calculate the score correctly', () => {
        const cvss = new Cvss4P0("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N");
        expect(cvss.toString()).toEqual("CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N");
        expect(cvss.getMacroVector().toString()).toEqual("102201");
        expect(cvss.getMacroVector().getEq1().getLevel()).toEqual("1");
        expect(cvss.getMacroVector().getLookupTableScore()).toEqual(5.3);
    });

    {
        const data = fs.readFileSync('__tests__/resources/cvss-4.0-validation-vectors-001.txt', 'utf8');
        const lines = data.split('\n');
        lines.forEach(line => {
            if (line.length === 0) {
                return;
            }
            const [vector, macroVector, score] = line.split(' ');
            const cvss = new Cvss4P0(vector);
            it('(1) should evaluate ' + vector + ' correctly to ' + macroVector + ' with score ' + score, () => {
                expect(cvss.getMacroVector().toString()).toEqual(macroVector);
                expect(cvss.calculateOverallScore()).toEqual(parseFloat(score));
            });
        });
    }

    {
        const data = fs.readFileSync('__tests__/resources/cvss-4.0-validation-vectors-002.txt', 'utf8');
        const lines = data.split('\n');
        lines.forEach(line => {
            if (line.length === 0) {
                return;
            }
            const [vector, macroVector, score] = line.split(' ');
            const cvss = new Cvss4P0(vector);
            it('(2) should evaluate ' + vector + ' correctly to ' + macroVector + ' with score ' + score, () => {
                expect(cvss.getMacroVector().toString()).toEqual(macroVector);
                expect(cvss.calculateOverallScore()).toEqual(parseFloat(score));
            });
        });
    }

    it('should evaluate to 101020 with score 7.3', () => {
        const cvss = new Cvss4P0("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:A/VC:L/VI:L/VA:N/SC:L/SI:L/SA:H/S:P/AU:N/R:U/RE:L/U:Clear/MAV:A/MAC:L/MPR:N/MUI:P/MVC:H/MVI:N/MVA:H/MSC:L/MSI:H/MSA:S/CR:H/IR:H/AR:M/E:U");
        expect(cvss.getMacroVector().toString()).toEqual("101020");
        expect(cvss.calculateOverallScore()).toEqual(7.3);
    });

    it('should evaluate to 201121 with score 1.6', () => {
        const cvss = new Cvss4P0("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:L/SI:L/SA:H/S:P/AU:N/R:U/RE:L/U:Clear/MAV:A/MAC:L/MUI:P/MVC:L/MVI:H/MVA:H/MSC:L/MSI:H/MSA:N/CR:H/IR:M/AR:L/E:U");
        expect(cvss.getMacroVector().toString()).toEqual("201121");
        expect(cvss.getMacroVector().getLookupTableScore()).toEqual(1.9);
        expect(cvss.calculateOverallScore()).toEqual(1.6);
    });

    it('should evaluate to 212021 with score 0.9 (toFixed(1) rounding check)', () => {
        const cvss = new Cvss4P0("CVSS:4.0/AV:P/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:H/SI:L/SA:L/S:P/R:I/U:Red/MAT:P/MPR:N/MUI:P/MVC:N/MVI:L/MVA:L/MSC:L/MSI:L/MSA:S/IR:M/AR:H/E:U");
        expect(cvss.getMacroVector().toString()).toEqual("212021");
        expect(cvss.calculateOverallScore()).toEqual(0.9);
    });
});
