import {Cvss4P0MacroVector} from "./Cvss4P0MacroVector";
import {EQ} from "./EQ";

export interface EqOperations {
    getHighestSeverityVectors(thisMacroVector: Cvss4P0MacroVector): string[];

    getRelevantAttributes(): string[];

    deriveNextLowerMacro(thisMacroVector: Cvss4P0MacroVector): Cvss4P0MacroVector[];

    lookupScoresForNextLowerMacro(nextLowerMacro: Cvss4P0MacroVector[]): number;

    lookupMacroVectorDepth(thisMacroVector: Cvss4P0MacroVector): number;
}

export const getEqImplementations = (): EqOperations[] => {
    return [
        EqOperations1.getInstance(),
        EqOperations2.getInstance(),
        EqOperations4.getInstance(),
        EqOperations5.getInstance(),
        EqOperations36.getInstance()
    ];
};

export abstract class EqOperations1245 implements EqOperations {
    deriveNextLowerMacro(thisMacroVector: Cvss4P0MacroVector): Cvss4P0MacroVector[] {
        return [thisMacroVector.deriveNextLower(this.getEqNumber())];
    }

    lookupScoresForNextLowerMacro(nextLowerMacro: Cvss4P0MacroVector[]): number {
        return nextLowerMacro[0].getLookupTableScore();
    }

    getHighestSeverityVectors(thisMacroVector: Cvss4P0MacroVector): string[] {
        return this.getEq(thisMacroVector).getHighestSeverityVectorsUnparsed();
    }

    lookupMacroVectorDepth(thisMacroVector: Cvss4P0MacroVector): number {
        return this.getEq(thisMacroVector).getVectorDepth();
    }

    abstract getRelevantAttributes(): string[];

    abstract getEqNumber(): number;

    abstract getEq(thisMacroVector: Cvss4P0MacroVector): EQ;
}

export class EqOperations1 extends EqOperations1245 {

    public static readonly instance: EqOperations1 = new EqOperations1();

    getEq(thisMacroVector: Cvss4P0MacroVector): EQ {
        return thisMacroVector.getEq1();
    }

    getRelevantAttributes(): string[] {
        return ["AV", "PR", "UI"];
    }

    getEqNumber(): number {
        return 1;
    }

    static getInstance(): EqOperations1 {
        return EqOperations1.instance;
    }
}

export class EqOperations2 extends EqOperations1245 {

    public static readonly instance: EqOperations2 = new EqOperations2();

    getEq(thisMacroVector: Cvss4P0MacroVector): EQ {
        return thisMacroVector.getEq2();
    }

    getRelevantAttributes(): string[] {
        return ["AC", "AT"];
    }

    getEqNumber(): number {
        return 2;
    }

    static getInstance(): EqOperations2 {
        return EqOperations2.instance;
    }
}

export class EqOperations4 extends EqOperations1245 {

    public static readonly instance: EqOperations4 = new EqOperations4();

    getEq(thisMacroVector: Cvss4P0MacroVector): EQ {
        return thisMacroVector.getEq4();
    }

    getRelevantAttributes(): string[] {
        return ["SC", "SI", "SA"];
    }

    getEqNumber(): number {
        return 4;
    }

    static getInstance(): EqOperations4 {
        return EqOperations4.instance;
    }
}

export class EqOperations5 extends EqOperations1245 {

    public static readonly instance: EqOperations5 = new EqOperations5();

    getEq(thisMacroVector: Cvss4P0MacroVector): EQ {
        return thisMacroVector.getEq5();
    }

    getRelevantAttributes(): string[] {
        return [];
    }

    getEqNumber(): number {
        return 5;
    }

    static getInstance(): EqOperations5 {
        return EqOperations5.instance;
    }
}

export class EqOperations36 implements EqOperations {
    private static readonly instance: EqOperations36 = new EqOperations36();

    static getInstance(): EqOperations36 {
        return EqOperations36.instance;
    }

    getHighestSeverityVectors(thisMacroVector: Cvss4P0MacroVector): string[] {
        return thisMacroVector.getJointEq3AndEq6().getHighestSeverityVectorsUnparsed();
    }

    getRelevantAttributes(): string[] {
        return ["VC", "VI", "VA", "CR", "IR", "AR"];
    }

    deriveNextLowerMacro(thisMacroVector: Cvss4P0MacroVector): Cvss4P0MacroVector[] {
        const eq3_val = thisMacroVector.getEq3().getLevelAsInt();
        const eq6_val = thisMacroVector.getEq6().getLevelAsInt();

        if (eq3_val === 1 && eq6_val === 1) {
            // 11 -> 21
            return [thisMacroVector.deriveNextLower(3)];
        } else if (eq3_val === 0 && eq6_val === 1) {
            // 01 -> 11
            return [thisMacroVector.deriveNextLower(3)];
        } else if (eq3_val === 1 && eq6_val === 0) {
            // 10 -> 11
            return [thisMacroVector.deriveNextLower(6)];
        } else if (eq3_val === 0 && eq6_val === 0) {
            // 00 -> 01, 10
            const eq3eq6_next_lower_macro_left = thisMacroVector.deriveNextLower(3);
            const eq3eq6_next_lower_macro_right = thisMacroVector.deriveNextLower(6);
            return [eq3eq6_next_lower_macro_left, eq3eq6_next_lower_macro_right];
        } else {
            // 21 -> 32 (cannot not exist)
            return [thisMacroVector.deriveNextLower(3).deriveNextLower(6)];
        }
    }

    lookupScoresForNextLowerMacro(nextLowerMacros: Cvss4P0MacroVector[]): number {
        let score_eq3eq6_next_lower_macro_left = NaN;
        let score_eq3eq6_next_lower_macro_right = NaN;

        if (nextLowerMacros.length > 0 && nextLowerMacros[0] != null) {
            score_eq3eq6_next_lower_macro_left = nextLowerMacros[0].getLookupTableScore();
        }

        if (nextLowerMacros.length > 1 && nextLowerMacros[1] != null) {
            score_eq3eq6_next_lower_macro_right = nextLowerMacros[1].getLookupTableScore();
        }

        if (!isNaN(score_eq3eq6_next_lower_macro_left) && !isNaN(score_eq3eq6_next_lower_macro_right)) {
            return Math.max(score_eq3eq6_next_lower_macro_left, score_eq3eq6_next_lower_macro_right);
        } else if (!isNaN(score_eq3eq6_next_lower_macro_left)) {
            return score_eq3eq6_next_lower_macro_left;
        } else {
            return score_eq3eq6_next_lower_macro_right;
        }
    }

    lookupMacroVectorDepth(thisMacroVector: Cvss4P0MacroVector): number {
        return thisMacroVector.getJointEq3AndEq6().getVectorDepth();
    }
}
