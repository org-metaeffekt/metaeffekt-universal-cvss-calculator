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
import { Cvss2, Cvss3P1 } from "../src";

import fs from "fs";

describe('Cvss2', () => {
    it('should create an instance with default values', () => {
        const cvss = new Cvss2();
        expect(cvss).toBeDefined();
    });

    function makeNanFromUndefined(value: number | undefined): number {
        return value === undefined ? NaN : (value === -0 ? 0 : value);
    }

    const data = fs.readFileSync('__tests__/resources/cvss-2.0-validation-vectors-001.txt', 'utf8');
    const lines = data.split('\n');
    lines.forEach(line => {
        if (line.length === 0) {
            return;
        }
        // AV:A/AC:H/Au:M/C:P/I:P/A:N/E:U/RL:OF/RC:UC/CDP:L/TD:M/CR:M/IR:L/AR:H 1.6 2.7 4.9 2.0 1.8 1.6 3.9
        const [vector, overallScore, baseScore, impactScore, exploitabilityScore, temporalScore, environmentalScore, adjustedImpactScore] = line.split(' ');
        const cvss = new Cvss2(vector);
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

    it('should evaluate vector correctly to: AV:N/AC:H/Au:M/C:P/I:P/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:L/CR:M/IR:H/AR:M 1.7 5.8 8.5 3.2 5.0 1.7 8.9', () => {
        const cvss = new Cvss2("AV:N/AC:H/Au:M/C:P/I:P/A:C/E:H/RL:TF/RC:UR/CDP:LM/TD:L/CR:M/IR:H/AR:M");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.overall)).toEqual(1.7);
        expect(makeNanFromUndefined(result.base)).toEqual(5.8);
        expect(makeNanFromUndefined(result.impact)).toEqual(8.5);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(3.2);
        expect(makeNanFromUndefined(result.temporal)).toEqual(5.0);
        expect(makeNanFromUndefined(result.environmental)).toEqual(1.7);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(8.9);
    });

    it('should evaluate vector correctly to: AV:L/AC:H/Au:M/C:P/I:N/A:N/E:H/RL:OF/RC:UC/CDP:N/TD:H/CR:L/IR:L/AR:L -0.1 0.8 2.9 1.2 0.6 -0.1 1.4', () => {
        const cvss = new Cvss2("AV:L/AC:H/Au:M/C:P/I:N/A:N/E:H/RL:OF/RC:UC/CDP:N/TD:H/CR:L/IR:L/AR:L");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.base)).toEqual(0.8);
        expect(makeNanFromUndefined(result.impact)).toEqual(2.9);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(1.2);
        expect(makeNanFromUndefined(result.temporal)).toEqual(0.6);
        expect(makeNanFromUndefined(result.environmental)).toEqual(-0.1);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(1.4);
        expect(makeNanFromUndefined(result.overall)).toEqual(-0.1);
    });

    it("should only apply the lower vector parts AV:N/AC:L/Au:N/C:C/I:C/A:C + AV:A", () => {
        const base = new Cvss2("AV:N/AC:L/Au:N/C:C/I:C/A:C");
        const applyLower = new Cvss2("AV:A");

        base.applyVectorPartsIfLowerVector(applyLower, vector => vector.calculateScores(false).overall);

        expect(base.toStringDefinedParts()).toEqual("AV:A/AC:L/Au:N/C:C/I:C/A:C")
    })
});
