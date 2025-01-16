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
import {Cvss3P0} from "../src";

import fs from "fs";

describe('Cvss3P0', () => {
    it('should create an instance with default values', () => {
        const cvss = new Cvss3P0();
        expect(cvss).toBeDefined();
    });

    function makeNanFromUndefined(value: number | undefined): number {
        return value === undefined ? NaN : (value === -0 ? 0 : value);
    }

    {
        const data = fs.readFileSync('__tests__/resources/cvss-3.0-validation-vectors-002.txt', 'utf8');
        const lines = data.split('\n').filter(line => line.length > 0).filter(line => !line.startsWith('#'));
        lines.forEach(line => {
            if (line.length === 0) {
                return;
            }
            const [vector, baseScore, temporalScore, environmentalScore] = line.split(' ');
            const cvss = new Cvss3P0(vector);
            it('002 should evaluate vector correctly to: ' + line, () => {
                const result = cvss.calculateScores();
                expect(makeNanFromUndefined(result.base)).toEqual(parseFloat(baseScore));
                expect(makeNanFromUndefined(result.temporal)).toEqual(parseFloat(temporalScore));
                expect(makeNanFromUndefined(result.environmental)).toEqual(parseFloat(environmentalScore));
            });
        });
    }

    {
        const data = fs.readFileSync('__tests__/resources/cvss-3.0-validation-vectors-001.txt', 'utf8');
        const lines = data.split('\n').filter(line => line.length > 0).filter(line => !line.startsWith('#'));
        lines.forEach(line => {
            if (line.length === 0) {
                return;
            }
            const [vector, baseScore, temporalScore, environmentalScore] = line.split(' ');
            const cvss = new Cvss3P0(vector);
            it('001 should evaluate vector correctly to: ' + line, () => {
                const result = cvss.calculateScores();
                expect(makeNanFromUndefined(result.base)).toEqual(parseFloat(baseScore));
                expect(makeNanFromUndefined(result.temporal)).toEqual(parseFloat(temporalScore));
                expect(makeNanFromUndefined(result.environmental)).toEqual(parseFloat(environmentalScore));
            });
        });
    }

    it('should evaluate vector correctly to: CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/MAC:H/MPR:N/MUI:N/MC:N/MI:N/MA:N/IR:M', () => {
        const cvss = new Cvss3P0("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/MAC:H/MPR:N/MUI:N/MC:N/MI:N/MA:N/IR:M");
        const result = cvss.calculateScores();
        expect(makeNanFromUndefined(result.base)).toEqual(7.3);
        expect(makeNanFromUndefined(result.impact)).toEqual(5.3);
        expect(makeNanFromUndefined(result.exploitability)).toEqual(1.5);
        expect(makeNanFromUndefined(result.temporal)).toEqual(7.3);
        expect(makeNanFromUndefined(result.environmental)).toEqual(0.0);
        expect(makeNanFromUndefined(result.modifiedImpact)).toEqual(0.0);
        expect(makeNanFromUndefined(result.overall)).toEqual(0.0);
    });

    it('should evaluate vector correctly to: CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N', () => {
        const cvss = new Cvss3P0("CVSS:3.0/AV:P/AC:H/PR:H/UI:N/S:C/C:N/I:N/A:N");
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
