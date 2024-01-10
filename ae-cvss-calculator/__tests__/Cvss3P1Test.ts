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

    // CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L/E:H/RC:R/MAV:N/MPR:L/MC:N/MI:H/MA:H/CR:L/IR:H/AR:H 9.6 6.1 2.7 2.8 5.9 9.6 6.1
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

    // CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L/E:H/MAC:H/MPR:N/MUI:N/MC:N/MI:N/MA:N/IR:M 0.0 7.3 5.3 1.5 7.3 0.0 0.0
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

    console.log(new Cvss3P1("CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:N/MI:N/MA:N/CR:X/IR:X/AR:X").calculateScores());
});
