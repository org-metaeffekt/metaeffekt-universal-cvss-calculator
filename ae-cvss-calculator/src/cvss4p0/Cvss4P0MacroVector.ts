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
import {VectorComponent, VectorComponentValue} from "../CvssVector";
import {EQ} from "./EQ";
import {ICvss4P0} from "./ICvss4P0";
import {Cvss4P0Components} from "./Cvss4P0Components";

export class Cvss4P0MacroVector {

    private readonly eq1: EQ;
    private readonly eq2: EQ;
    private readonly eq3: EQ;
    private readonly eq4: EQ;
    private readonly eq5: EQ;
    private readonly eq6: EQ;
    private readonly jointEq3AndEq6: EQ;

    constructor(eq1: EQ, eq2: EQ, eq3: EQ, eq4: EQ, eq5: EQ, eq6: EQ, jointEq3AndEq6: EQ) {
        this.eq1 = eq1;
        this.eq2 = eq2;
        this.eq3 = eq3;
        this.eq4 = eq4;
        this.eq5 = eq5;
        this.eq6 = eq6;
        this.jointEq3AndEq6 = jointEq3AndEq6;
    }

    public static fromVector(vector: ICvss4P0) {
        const eq1 = Cvss4P0MacroVector.findMatchingEQ("1", Cvss4P0MacroVector.EQ1_DEFINITIONS, vector);
        const eq2 = Cvss4P0MacroVector.findMatchingEQ("2", Cvss4P0MacroVector.EQ2_DEFINITIONS, vector);
        const eq3 = Cvss4P0MacroVector.findMatchingEQ("3", Cvss4P0MacroVector.EQ3_DEFINITIONS, vector);
        const eq4 = Cvss4P0MacroVector.findMatchingEQ("4", Cvss4P0MacroVector.EQ4_DEFINITIONS, vector);
        const eq5 = Cvss4P0MacroVector.findMatchingEQ("5", Cvss4P0MacroVector.EQ5_DEFINITIONS, vector);
        const eq6 = Cvss4P0MacroVector.findMatchingEQ("6", Cvss4P0MacroVector.EQ6_DEFINITIONS, vector);
        const jointEq3AndEq6 = Cvss4P0MacroVector.findMatchingEQ("3,6", Cvss4P0MacroVector.JOINT_EQ3_EQ6_DEFINITIONS, vector);

        return new Cvss4P0MacroVector(eq1, eq2, eq3, eq4, eq5, eq6, jointEq3AndEq6);
    }

    private static findMatchingEQ(eqType: string, definitions: EQ[], sourceVector: ICvss4P0): EQ {
        for (let eq of definitions) {
            if (eq.matchesConstraints(sourceVector)) {
                return eq;
            }
        }
        throw new Error("No matching EQ found for " + eqType + " and vector " + sourceVector);
    }

    public getEq1(): EQ {
        return this.eq1;
    }

    public getEq2(): EQ {
        return this.eq2;
    }

    public getEq3(): EQ {
        return this.eq3;
    }

    public getEq4(): EQ {
        return this.eq4;
    }

    public getEq5(): EQ {
        return this.eq5;
    }

    public getEq6(): EQ {
        return this.eq6;
    }

    public getJointEq3AndEq6(): EQ {
        return this.jointEq3AndEq6;
    }

    public getEQ(i: number): EQ {
        switch (i) {
            case 1:
                return this.eq1;
            case 2:
                return this.eq2;
            case 3:
                return this.eq3;
            case 4:
                return this.eq4;
            case 5:
                return this.eq5;
            case 6:
                return this.eq6;
            case 7:
                return this.jointEq3AndEq6;
            default:
                throw new Error("Invalid EQ index: " + i);
        }
    }

    public getLookupTableScore(): number {
        return Cvss4P0MacroVector.getMacroVectorScore(this);
    }

    public static getMacroVectorScore(macroVector: Cvss4P0MacroVector) {
        const macroVectorString = macroVector.toString();
        const score = Cvss4P0Components.MV_LOOKUP[macroVectorString];
        if (score === undefined) {
            return NaN;
        }
        return score;
    }

    public toString(): string {
        return this.eq1.getLevel() + this.eq2.getLevel() + this.eq3.getLevel() + this.eq4.getLevel() + this.eq5.getLevel() + this.eq6.getLevel();
    }

    public deriveNextLower(i: number): Cvss4P0MacroVector {
        const eq1 = i !== 1 ? this.eq1 : this.getNextLower(Cvss4P0MacroVector.EQ1_DEFINITIONS, this.eq1);
        const eq2 = i !== 2 ? this.eq2 : this.getNextLower(Cvss4P0MacroVector.EQ2_DEFINITIONS, this.eq2);
        const eq3 = i !== 3 ? this.eq3 : this.getNextLower(Cvss4P0MacroVector.EQ3_DEFINITIONS, this.eq3);
        const eq4 = i !== 4 ? this.eq4 : this.getNextLower(Cvss4P0MacroVector.EQ4_DEFINITIONS, this.eq4);
        const eq5 = i !== 5 ? this.eq5 : this.getNextLower(Cvss4P0MacroVector.EQ5_DEFINITIONS, this.eq5);
        const eq6 = i !== 6 ? this.eq6 : this.getNextLower(Cvss4P0MacroVector.EQ6_DEFINITIONS, this.eq6);
        const jointEq3AndEq6 = i !== 7 ? this.jointEq3AndEq6 : this.getNextLower(Cvss4P0MacroVector.JOINT_EQ3_EQ6_DEFINITIONS, this.jointEq3AndEq6);

        return new Cvss4P0MacroVector(eq1, eq2, eq3, eq4, eq5, eq6, jointEq3AndEq6);
    }

    private static getIndexInDefinitions(definitions: EQ[], eq: EQ): number {
        for (let i = 0; i < definitions.length; i++) {
            if (definitions[i] === eq) {
                return i;
            }
        }
        throw new Error("EQ not found in definitions: " + eq);
    }

    private getNextLower(definitions: EQ[], eq: EQ): EQ {
        const index = Cvss4P0MacroVector.getIndexInDefinitions(definitions, eq);
        return definitions.length > index + 1 ? definitions[index + 1] : Cvss4P0MacroVector.EQ_ERROR_DEFINITION;
    }

    private static is(vector: ICvss4P0, attribute: string, value: string): boolean {
        const comparisonValue = Cvss4P0MacroVector.getComparisonMetric(vector, attribute).shortName;
        return value === comparisonValue;
    }

    public static EQ_ERROR_DEFINITION: EQ = new EQ("9", -1, [], () => true);

    public static EQ1_DEFINITIONS: EQ[] = [
        new EQ("0", 1, ["AV:N/PR:N/UI:N"], (vector) => this.is(vector, "AV", "N") && this.is(vector, "PR", "N") && this.is(vector, "UI", "N")),
        new EQ("1", 4, ["AV:A/PR:N/UI:N", "AV:N/PR:L/UI:N", "AV:N/PR:N/UI:P"], (vector) => (this.is(vector, "AV", "N") || this.is(vector, "PR", "N") || this.is(vector, "UI", "N")) && !(this.is(vector, "AV", "N") && this.is(vector, "PR", "N") && this.is(vector, "UI", "N")) && !this.is(vector, "AV", "P")),
        new EQ("2", 5, ["AV:P/PR:N/UI:N", "AV:A/PR:L/UI:P"], (vector) => this.is(vector, "AV", "P") || !(this.is(vector, "AV", "N") || this.is(vector, "PR", "N") || this.is(vector, "UI", "N")))
    ];

    public static EQ2_DEFINITIONS: EQ[] = [
        new EQ("0", 1, ["AC:L/AT:N"], (vector) => this.is(vector, "AC", "L") && this.is(vector, "AT", "N")),
        new EQ("1", 2, ["AC:H/AT:N", "AC:L/AT:P"], (vector) => !(this.is(vector, "AC", "L") && this.is(vector, "AT", "N")))
    ];

    public static EQ3_DEFINITIONS: EQ[] = [
        new EQ("0", -1, ["VC:H/VI:H/VA:H"], (vector) => this.is(vector, "VC", "H") && this.is(vector, "VI", "H")),
        new EQ("1", -1, ["VC:L/VI:H/VA:H", "VC:H/VI:L/VA:H"], (vector) => !(this.is(vector, "VC", "H") && this.is(vector, "VI", "H")) && (this.is(vector, "VC", "H") || this.is(vector, "VI", "H") || this.is(vector, "VA", "H"))),
        new EQ("2", -1, ["VC:L/VI:L/VA:L"], (vector) => !(this.is(vector, "VC", "H") || this.is(vector, "VI", "H") || this.is(vector, "VA", "H")))
    ];

    public static EQ4_DEFINITIONS: EQ[] = [
        new EQ("0", 6, ["SC:H/SI:S/SA:S"], (vector) => this.is(vector, "MSI", "S") || this.is(vector, "MSA", "S")),
        new EQ("1", 5, ["SC:H/SI:H/SA:H"], (vector) => !(this.is(vector, "MSI", "S") && this.is(vector, "MSA", "S")) && (this.is(vector, "SC", "H") || this.is(vector, "SI", "H") || this.is(vector, "SA", "H"))),
        new EQ("2", 4, ["SC:L/SI:L/SA:L"], (vector) => !(this.is(vector, "MSI", "S") && this.is(vector, "MSA", "S")) && !(this.is(vector, "SC", "H") || this.is(vector, "SI", "H") || this.is(vector, "SA", "H")))
    ];

    public static EQ5_DEFINITIONS: EQ[] = [
        new EQ("0", 1, ["E:A"], (vector) => this.is(vector, "E", "A")),
        new EQ("1", 1, ["E:P"], (vector) => this.is(vector, "E", "P")),
        new EQ("2", 1, ["E:U"], (vector) => this.is(vector, "E", "U"))
    ];

    public static EQ6_DEFINITIONS: EQ[] = [
        new EQ("0", -1, ["AV:N/PR:N/UI:N"], (vector) => (this.is(vector, "CR", "H") && this.is(vector, "VC", "H")) || (this.is(vector, "IR", "H") && this.is(vector, "VI", "H")) || (this.is(vector, "AR", "H") && this.is(vector, "VA", "H"))),
        new EQ("1", -1, ["VC:H/VI:H/VA:H/CR:M/IR:M/AR:M", "VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M", "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M", "VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"], (vector) => !((this.is(vector, "CR", "H") && this.is(vector, "VC", "H")) || (this.is(vector, "IR", "H") && this.is(vector, "VI", "H")) || (this.is(vector, "AR", "H") && this.is(vector, "VA", "H"))))
    ];

    public static JOINT_EQ3_EQ6_DEFINITIONS: EQ[] = [
        new EQ("00", 7, ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H"], (vector) => this.is(vector, "VC", "H") && this.is(vector, "VI", "H") && (this.is(vector, "CR", "H") || this.is(vector, "IR", "H") || (this.is(vector, "AR", "H") && this.is(vector, "VA", "H")))),
        new EQ("01", 6, ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M"], (vector) => this.is(vector, "VC", "H") && this.is(vector, "VI", "H") && !(this.is(vector, "CR", "H") || this.is(vector, "IR", "H")) && !(this.is(vector, "AR", "H") && this.is(vector, "VA", "H"))),
        new EQ("10", 8, ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H"], (vector) => !(this.is(vector, "VC", "H") && this.is(vector, "VI", "H")) && (this.is(vector, "VC", "H") || this.is(vector, "VI", "H") || this.is(vector, "VA", "H")) && ((this.is(vector, "CR", "H") && this.is(vector, "VC", "H")) || (this.is(vector, "IR", "H") && this.is(vector, "VI", "H")) || (this.is(vector, "AR", "H") && this.is(vector, "VA", "H")))),
        new EQ("11", 8, ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M"], (vector) => !(this.is(vector, "VC", "H") && this.is(vector, "VI", "H")) && (this.is(vector, "VC", "H") || this.is(vector, "VI", "H") || this.is(vector, "VA", "H")) && !(this.is(vector, "CR", "H") && this.is(vector, "VC", "H")) && !(this.is(vector, "IR", "H") && this.is(vector, "VI", "H")) && !(this.is(vector, "AR", "H") && this.is(vector, "VA", "H"))),
        new EQ("20", 0, [], (vector) => false), // Cannot exist
        new EQ("21", 10, ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H"], (vector) => !(this.is(vector, "VC", "H") || this.is(vector, "VI", "H") || this.is(vector, "VA", "H")) && !(this.is(vector, "CR", "H") && this.is(vector, "VC", "H")) && !(this.is(vector, "IR", "H") && this.is(vector, "VI", "H")) && !(this.is(vector, "AR", "H") && this.is(vector, "VA", "H")))
    ];


    public static getComparisonMetricComponent<T extends VectorComponentValue>(vector: ICvss4P0, component: VectorComponent<T>): VectorComponentValue {
        return Cvss4P0MacroVector.getComparisonMetric(vector, component.shortName);
    }

    public static getComparisonMetric(vector: ICvss4P0, component: string): VectorComponentValue {
        const selectedComponentValue = vector.getComponentByString(component);

        // E:X is the same as E:A
        if ("E" === component && Cvss4P0Components.E_VALUES.X === selectedComponentValue) {
            return Cvss4P0Components.E_VALUES.A;
        }

        // The three security requirements metrics have X equivalent to H.
        // CR:X, IR:X, AR:X are the same as CR:H, IR:H, AR:H
        if (("CR" === component || "IR" === component || "AR" === component) && Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.X === selectedComponentValue) {
            return Cvss4P0Components.TEMPLATE_CIA_REQUIREMENT_MODIFIED_VALUES.H;
        }

        // Special cases for MSI and MSA
        // the SI:S cannot happen in reality, but the reference implementation checks for it, so we do too
        if ("MSI" === component && Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.X === selectedComponentValue
            && "S" === vector.getComponentByString("SI").shortName) {
            return Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.H;
        }
        if ("MSA" === component && Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.X === selectedComponentValue
            && "S" === vector.getComponentByString("SA").shortName) {
            return Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.H;
        }

        // All other environmental metrics just overwrite base score values,
        // so if they’re not defined just use the base score value.
        try {
            const modifiedAttribute = vector.getComponentByString((component.startsWith('M') ? '' : 'M') + component);
            const modifiedSelected = modifiedAttribute.shortName;
            if (modifiedSelected != null && "X" !== modifiedSelected) {
                return modifiedAttribute;
            }
        } catch (e) {
            // ignore; modified version of the attribute does not exist
        }

        return selectedComponentValue;
    }
}
