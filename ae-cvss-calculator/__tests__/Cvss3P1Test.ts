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
import {Cvss3P1} from "../src";

import fs from "fs";

describe('Cvss3P1', () => {
    it('should create an instance with default values', () => {
        const cvss = new Cvss3P1();
        expect(cvss).toBeDefined();
    });

    function makeNanFromUndefined(value: number | undefined): number {
        return value === undefined ? NaN : (value === -0 ? 0 : value);
    }

    const data = fs.readFileSync('__tests__/resources/cvss-3.1-validation-vectors-001.txt', 'utf8');
    const lines = data.split('\n');
    lines.forEach(line => {
        if (line.length === 0) {
            return;
        }
        const [vector, overallScore, baseScore, impactScore, exploitabilityScore, temporalScore, environmentalScore, adjustedImpactScore] = line.split(' ');
        const cvss = new Cvss3P1(vector);
        it('should evaluate vector correctly to: ' + line, () => {
            const result = cvss.calculateScores();
            expect(makeNanFromUndefined(result.overall)).toEqual(parseFloat(overallScore));
            expect(makeNanFromUndefined(result.base)).toEqual(parseFloat(baseScore));
            expect(makeNanFromUndefined(result.impact)).toEqual(parseFloat(impactScore));
            expect(makeNanFromUndefined(result.exploitability)).toEqual(parseFloat(exploitabilityScore));
            expect(makeNanFromUndefined(result.temporal)).toEqual(parseFloat(temporalScore));
            expect(makeNanFromUndefined(result.environmental)).toEqual(parseFloat(environmentalScore));
            expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(parseFloat(adjustedImpactScore));
        });
    });

    it('should evaluate vector correctly to: CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L/E:H/RC:R/MAV:N/MPR:L/MC:N/MI:H/MA:H/CR:L/IR:H/AR:H 9.6 6.1 2.7 2.8 5.9 9.6 6.1', () => {
        const cvss = new Cvss3P1("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L/E:H/RC:R/MAV:N/MPR:L/MC:N/MI:H/MA:H/CR:L/IR:H/AR:H");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.base)).toEqual(6.1);
        expect(makeNanFromUndefined(result.impact)).toEqual(2.7);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(2.8);
        expect(makeNanFromUndefined(result.temporal)).toEqual(5.9);
        expect(makeNanFromUndefined(result.environmental)).toEqual(9.6);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(6.1);
        expect(makeNanFromUndefined(result.overall)).toEqual(9.6);
    });

    it('should evaluate vector correctly to: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/MAC:H/MPR:N/MUI:N/MC:N/MI:N/MA:N/IR:M 0.0 7.3 5.3 1.5 7.3 0.0 0.0', () => {
        const cvss = new Cvss3P1("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/MAC:H/MPR:N/MUI:N/MC:N/MI:N/MA:N/IR:M");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.base)).toEqual(7.3);
        expect(makeNanFromUndefined(result.impact)).toEqual(5.3);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(1.5);
        expect(makeNanFromUndefined(result.temporal)).toEqual(7.3);
        expect(makeNanFromUndefined(result.environmental)).toEqual(0.0);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(0.0);
        expect(makeNanFromUndefined(result.overall)).toEqual(0.0);
    });

    it('should evaluate vector correctly to: CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N', () => {
        const cvss = new Cvss3P1("CVSS:3.1/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.base)).toEqual(0.0);
        expect(makeNanFromUndefined(result.impact)).toEqual(0.0);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(0.3);
        expect(makeNanFromUndefined(result.temporal)).toEqual(NaN);
        expect(makeNanFromUndefined(result.environmental)).toEqual(NaN);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(NaN);
        expect(makeNanFromUndefined(result.overall)).toEqual(0.0);
    });
});
