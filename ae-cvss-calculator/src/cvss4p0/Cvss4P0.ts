import {ComponentCategory, CvssVector, SingleScoreResult, VectorComponent, VectorComponentValue} from "../CvssVector";
import {Cvss4P0MacroVector} from "./Cvss4P0MacroVector";
import {getEqImplementations} from "./EqOperations";
import {Cvss4P0Components} from "./Cvss4P0Components";
import {EQ} from "./EQ";

export class Cvss4P0 extends CvssVector<SingleScoreResult> {

    static {
        EQ.createCvssInstance = vector => new Cvss4P0(vector);
    }

    public constructor(initialVector?: string) {
        super(initialVector);
    }

    public getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]> {
        return Cvss4P0Components.REGISTERED_COMPONENTS;
    }

    getVectorPrefix(): string {
        return "CVSS:4.0/";
    }

    getVectorName(): string {
        return "CVSS:4.0";
    }

    fillAverageVector(): void {
        this.applyVector("AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:L/SI:L/SA:L");
    }

    fillRandomBaseVector(): void {
        const baseCategoryComponents = Cvss4P0Components.BASE_CATEGORY_VALUES;
        for (let i = 0; i < baseCategoryComponents.length; i++) {
            const component = baseCategoryComponents[i];
            const value = super.pickRandomDefinedComponentValue(component);
            if (value) {
                this.applyComponent(component, value);
            } else {
                console.warn('Failed to pick random vector component for', component, ', filling average vector instead');
                this.fillAverageVector();
                return;
            }
        }
    }

    calculateScores(normalize: boolean = false): SingleScoreResult {
        return {
            overall: this.calculateOverallScore(),
            vector: this.toString()
        };
    }

    calculateOverallScore(): number {
        if (!this.isBaseFullyDefined()) {
            return 0.0;
        }

        // check for no impact on system
        if (["VC", "VI", "VA", "SC", "SI", "SA"]
            .map(attr => Cvss4P0MacroVector.getComparisonMetric(this, attr))
            .every(value => value.shortName === "N")) {
            return 0.0;
        }

        const thisMacroVector = this.getMacroVector();
        const thisMacroVectorScore = thisMacroVector.getLookupTableScore();
        const eqOperations = getEqImplementations();

        // safety check
        if ((thisMacroVector.getEq3().getLevel() + thisMacroVector.getEq6().getLevel()).toLowerCase() !== thisMacroVector.getJointEq3AndEq6().getLevel().toLowerCase()) {
            console.warn(`CVSS 4.0: Joint Eq3 and Eq6 level [${thisMacroVector.getJointEq3AndEq6().getLevel()}] does not match Eq3 [${thisMacroVector.getEq3().getLevel()}] and Eq6 [${thisMacroVector.getEq6().getLevel()}]`);
        }

        const allHighestSeverityVectors: string[][] = eqOperations.map(eqOp => eqOp.getHighestSeverityVectors(thisMacroVector))

        const highestSeverityVectorCombinations = this.generateCvssPermutations(
            allHighestSeverityVectors[0], allHighestSeverityVectors[1], allHighestSeverityVectors[2],
            allHighestSeverityVectors[3], allHighestSeverityVectors[4]
        );

        if (highestSeverityVectorCombinations.length === 0) {
            console.warn(`No max vectors found for ${thisMacroVector}`);
            return 0.0;
        }

        const highestSeveritySeverityDistances = this.calculateSeverityDistancesByComparingToHighestSeverityVectors(highestSeverityVectorCombinations);

        const meanScoreAdjustment = new Average();
        for (const eqOps of eqOperations) {
            const nextLessSevereMacroVector = eqOps.deriveNextLowerMacro(thisMacroVector);
            const nextLowerMacroScore = eqOps.lookupScoresForNextLowerMacro(nextLessSevereMacroVector);
            const availableSeverityReduction = thisMacroVectorScore - nextLowerMacroScore;

            const macroVectorDepth = eqOps.lookupMacroVectorDepth(thisMacroVector);
            const severityDistanceFromThisToHighestSeverity = eqOps.getRelevantAttributes()
                .map(attr => highestSeveritySeverityDistances.get(attr) || 0)
                .reduce((a, b) => a + b, 0);

            if (!isNaN(availableSeverityReduction) && macroVectorDepth !== 0.0) {
                const percentageToNextSeverityDistance = severityDistanceFromThisToHighestSeverity / macroVectorDepth;
                const normalizedSeverityDistance = percentageToNextSeverityDistance * availableSeverityReduction;
                meanScoreAdjustment.add(normalizedSeverityDistance);
            }
        }

        const adjustedOriginalMacroVectorScore = thisMacroVectorScore - meanScoreAdjustment.get(0.0);

        if (adjustedOriginalMacroVectorScore < 0) {
            return 0.0;
        } else if (adjustedOriginalMacroVectorScore > 10) {
            return 10.0;
        } else {
            return parseFloat(adjustedOriginalMacroVectorScore.toFixed(1));
        }
    }

    private generateCvssPermutations(
        eq1MaxVectors: string[], eq2MaxVectors: string[], eq3Eq6MaxVectors: string[],
        eq4MaxVectors: string[], eq5MaxVectors: string[]): Cvss4P0[] {

        const highestSeverityVectors: Cvss4P0[] = [];

        eq1MaxVectors.forEach(eq1Max => {
            eq2MaxVectors.forEach(eq2Max => {
                eq3Eq6MaxVectors.forEach(eq3Eq6Max => {
                    eq4MaxVectors.forEach(eq4Max => {
                        eq5MaxVectors.forEach(eq5Max => {
                            const combinedVector = `${eq1Max}/${eq2Max}/${eq3Eq6Max}/${eq4Max}/${eq5Max}`;
                            highestSeverityVectors.push(new Cvss4P0(combinedVector));
                        });
                    });
                });
            });
        });

        return highestSeverityVectors;
    }

    private severityDistance(part1Type: VectorComponent<VectorComponentValue>, part1: VectorComponentValue, part2Type: VectorComponent<VectorComponentValue>, part2: VectorComponentValue): number {
        const worseCaseComponent1: VectorComponentValue = part1.shortName === 'X' ? (part1Type.worseCaseValue === undefined ? part1 : part1Type.worseCaseValue as VectorComponent<VectorComponentValue>) : part1;
        const worseCaseComponent2: VectorComponentValue = part2.shortName === 'X' ? (part2Type.worseCaseValue === undefined ? part2 : part2Type.worseCaseValue as VectorComponent<VectorComponentValue>) : part2;

        let effectiveComponentType1: VectorComponent<VectorComponentValue>;
        let effectiveComponent1: VectorComponentValue;
        let effectiveComponentType2: VectorComponent<VectorComponentValue>;
        let effectiveComponent2: VectorComponentValue;

        if (part1Type !== part2Type) {
            const isModifiedAttribute1 = part1Type.name.startsWith("Modified");
            const isModifiedAttribute2 = part2Type.name.startsWith("Modified");

            if (isModifiedAttribute1 && !isModifiedAttribute2) {
                const found: VectorComponentValue | undefined = part1Type.values.find(v => v.shortName === worseCaseComponent2.shortName);
                if (!found) {
                    throw new Error("Cannot find modified value for " + worseCaseComponent2);
                }

                effectiveComponent1 = worseCaseComponent1;
                effectiveComponent2 = found as VectorComponentValue;
                effectiveComponentType1 = part1Type;
                effectiveComponentType2 = part1Type;
            } else if (!isModifiedAttribute1 && isModifiedAttribute2) {
                const found: VectorComponentValue | undefined = part2Type.values.find(v => v.shortName === worseCaseComponent1.shortName);
                if (!found) {
                    throw new Error("Cannot find modified value for " + worseCaseComponent1);
                }

                effectiveComponent1 = found as VectorComponentValue;
                effectiveComponent2 = worseCaseComponent2;
                effectiveComponentType1 = part2Type;
                effectiveComponentType2 = part2Type;
            } else {
                console.warn(`Cannot compute severity distance for [${worseCaseComponent1}] and [${worseCaseComponent2}], assuming distance is 0`);
                return 0;
            }
        } else {
            effectiveComponent1 = worseCaseComponent1;
            effectiveComponent2 = worseCaseComponent2;
            effectiveComponentType1 = part1Type;
            effectiveComponentType2 = part2Type;
        }

        const ordinal1 = effectiveComponentType1.values.indexOf(effectiveComponent1);
        const ordinal2 = effectiveComponentType2.values.indexOf(effectiveComponent2);

        return ordinal1 - ordinal2;
    }

    private severityDistanceBetweenComponents(part1Type: VectorComponent<VectorComponentValue>, part1: VectorComponentValue,
                                              part2Type: VectorComponent<VectorComponentValue>, part2: VectorComponentValue): number {
        const foundPart1 = part1Type.values.find(v => v.shortName === part1.shortName);
        const foundPart2 = part2Type.values.find(v => v.shortName === part2.shortName);
        if (!foundPart1) {
            throw new Error(`Cannot find component values for ${part1Type.name} with short name ${part1.shortName} in ${part1Type.values.map(v => v.shortName).join(", ")}`);
        } else if (!foundPart2) {
            throw new Error(`Cannot find component values for ${part2Type.name} with short name ${part2.shortName} in ${part2Type.values.map(v => v.shortName).join(", ")}`);
        }
        const ordinal1 = part1Type.values.indexOf(foundPart1);
        const ordinal2 = part2Type.values.indexOf(foundPart2);

        return ordinal1 - ordinal2;
    }

    public severityDistanceToVector(other: Cvss4P0): number {
        let totalDistance = 0;

        Cvss4P0Components.REGISTERED_COMPONENTS.forEach((components) => {
            components.forEach((component) => {
                const part1 = this.getComponent(component);
                const part2 = other.getComponent(component);
                totalDistance += this.severityDistanceBetweenComponents(component, part1, component, part2);
            });
        });

        return totalDistance;
    }

    public calculateSeverityDistancesByComparingToHighestSeverityVectors(highestSeverityVectors: Cvss4P0[]): Map<string, number> {
        const severityDistances = new Map<string, number>();

        for (const maxVector of highestSeverityVectors) {
            severityDistances.set("AV", this.severityDistanceBetweenComponents(Cvss4P0Components.AV, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.AV), Cvss4P0Components.AV, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.AV)));
            severityDistances.set("PR", this.severityDistanceBetweenComponents(Cvss4P0Components.PR, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.PR), Cvss4P0Components.PR, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.PR)));
            severityDistances.set("UI", this.severityDistanceBetweenComponents(Cvss4P0Components.UI, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.UI), Cvss4P0Components.UI, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.UI)));
            severityDistances.set("AC", this.severityDistanceBetweenComponents(Cvss4P0Components.AC, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.AC), Cvss4P0Components.AC, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.AC)));
            severityDistances.set("AT", this.severityDistanceBetweenComponents(Cvss4P0Components.AT, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.AT), Cvss4P0Components.AT, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.AT)));
            severityDistances.set("VC", this.severityDistanceBetweenComponents(Cvss4P0Components.VC, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.VC), Cvss4P0Components.VC, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.VC)));
            severityDistances.set("VI", this.severityDistanceBetweenComponents(Cvss4P0Components.VI, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.VI), Cvss4P0Components.VI, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.VI)));
            severityDistances.set("VA", this.severityDistanceBetweenComponents(Cvss4P0Components.VA, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.VA), Cvss4P0Components.VA, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.VA)));
            // SI and SA are handled below
            severityDistances.set("SC", this.severityDistanceBetweenComponents(Cvss4P0Components.SC, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.SC), Cvss4P0Components.SC, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.SC)));
            severityDistances.set("CR", this.severityDistanceBetweenComponents(Cvss4P0Components.CR, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.CR), Cvss4P0Components.CR, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.CR)));
            severityDistances.set("IR", this.severityDistanceBetweenComponents(Cvss4P0Components.IR, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.IR), Cvss4P0Components.IR, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.IR)));
            severityDistances.set("AR", this.severityDistanceBetweenComponents(Cvss4P0Components.AR, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.AR), Cvss4P0Components.AR, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.AR)));

            const isModifiedSubIntegrityImpactSafety = this.getComponent(Cvss4P0Components.SI) === Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.S;
            const isModifiedSubAvailabilityImpactSafety = this.getComponent(Cvss4P0Components.SA) === Cvss4P0Components.TEMPLATE_CIA_SUBSEQUENT_SAFETY_MODIFIED_VALUES.S;

            const subIntegrityImpactKey = isModifiedSubIntegrityImpactSafety ? "MSI" : "SI";
            const subAvailabilityImpactKey = isModifiedSubAvailabilityImpactSafety ? "MSA" : "SA";

            severityDistances.set(subIntegrityImpactKey, this.severityDistanceBetweenComponents(Cvss4P0Components.SI, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.SI), Cvss4P0Components.SI, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.SI)));
            severityDistances.set(subAvailabilityImpactKey, this.severityDistanceBetweenComponents(Cvss4P0Components.SA, Cvss4P0MacroVector.getComparisonMetricComponent(this, Cvss4P0Components.SA), Cvss4P0Components.SA, Cvss4P0MacroVector.getComparisonMetricComponent(maxVector, Cvss4P0Components.SA)));

            const anyNegative = Array.from(severityDistances.values()).some(val => val < 0);

            if (!anyNegative) {
                break;
            } else {
                severityDistances.clear();
            }
        }

        if (severityDistances.size === 0) {
            console.warn(`No severity distances found for [${this.toString()}]`);
        }

        return severityDistances;
    }

    public getMacroVector(): Cvss4P0MacroVector {
        return Cvss4P0MacroVector.fromVector(this);
    }

    public isBaseFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss4P0Components.BASE_CATEGORY);
    }
}

class Average {
    private sum = 0;
    private count = 0;

    public add(value: number) {
        this.sum += value;
        this.count++;
    }

    public get(defaultValue: number) {
        if (this.count == 0) {
            return defaultValue;
        } else {
            return this.sum / this.count;
        }
    }
}
