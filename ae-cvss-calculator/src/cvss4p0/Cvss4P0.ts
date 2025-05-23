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
import {
    ComponentCategory,
    CvssVector,
    SingleScoreResult,
    V4ScoreResult,
    VectorComponent,
    VectorComponentValue
} from "../CvssVector";
import { Cvss4P0MacroVector } from "./Cvss4P0MacroVector";
import { getEqImplementations } from "./EqOperations";
import { Cvss4P0Components } from "./Cvss4P0Components";
import { EQ } from "./EQ";
import { SeverityType } from "../cvss3p1/Cvss3P1";
import { Cvss3P1Components } from "../cvss3p1/Cvss3P1Components";

export class Cvss4P0 extends CvssVector<V4ScoreResult> {

    static {
        EQ.createCvssInstance = vector => new Cvss4P0(vector);
    }

    public constructor(initialVector?: string) {
        super(initialVector);
    }

    public getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]> {
        return Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER;
    }

    public getVectorStringOrderProperties(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]> {
        return Cvss4P0Components.REGISTERED_COMPONENTS_VECTOR_STRING_ORDER;
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

    protected calculateScoresInternal(normalize: boolean = false): V4ScoreResult {
        const hasEnvironmental = this.isAnyEnvironmentalDefined();
        const hasThreat = this.isAnyThreatDefined();

        const overallScore = this.calculateOverallScore();

        let baseScore: number | undefined;
        if (hasEnvironmental || hasThreat) {
            const vector: Cvss4P0 = this.clone() as Cvss4P0;
            vector.clearSpecifiedComponents(Cvss4P0Components.THREAT_CATEGORY_VALUES);
            vector.clearSpecifiedComponents(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES);
            vector.clearSpecifiedComponents(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES);
            baseScore = vector.calculateOverallScore();
        } else {
            baseScore = overallScore;
        }

        let environmentalScore: number | undefined;
        if (hasEnvironmental) {
            if (hasThreat) {
                const vector: Cvss4P0 = this.clone() as Cvss4P0;
                vector.clearSpecifiedComponents(Cvss4P0Components.THREAT_CATEGORY_VALUES);
                environmentalScore = vector.calculateOverallScore();
            } else {
                environmentalScore = overallScore;
            }
        }

        let threatScore: number | undefined;
        if (hasThreat) {
            if (hasEnvironmental) {
                const vector: Cvss4P0 = this.clone() as Cvss4P0;
                vector.clearSpecifiedComponents(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY_VALUES);
                vector.clearSpecifiedComponents(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY_VALUES);
                threatScore = vector.calculateOverallScore();
            } else {
                threatScore = overallScore;
            }
        }

        return {
            normalized: normalize,
            overall: overallScore,
            base: overallScore,
            baseMetricsOnly: baseScore,
            environmental: environmentalScore,
            threat: threatScore,
            vector: this.toString()
        };
    }

    public toString(forceAllComponents = false, categories = this.getVectorStringOrderProperties(), showOnlyDefinedComponents = false): string {
        return super.toString(forceAllComponents, categories, showOnlyDefinedComponents);
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
            return this.roundToDecimalPlaces(adjustedOriginalMacroVectorScore);
        }
    }

    private readonly ROUNDING_EPSILON = Math.pow(10, -6);

    private roundToDecimalPlaces(value: number) {
        return Math.round((value + this.ROUNDING_EPSILON) * 10) / 10;
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

        Cvss4P0Components.REGISTERED_COMPONENTS_EDITOR_ORDER.forEach((components) => {
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

            const isModifiedSubIntegrityImpactSafety = this.getComponent(Cvss4P0Components.SI) === Cvss4P0Components.SUBSEQUENT_SYSTEM_INTEGRITY_MODIFIED_VALUES.S;
            const isModifiedSubAvailabilityImpactSafety = this.getComponent(Cvss4P0Components.SA) === Cvss4P0Components.SUBSEQUENT_SYSTEM_AVAILABILITY_MODIFIED_VALUES.S;

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

    /**
     CVSS Nomenclature 	CVSS Metrics Used
     CVSS-B             Base metrics
     CVSS-BE            Base and Environmental metrics
     CVSS-BT            Base and Threat metrics
     CVSS-BTE           Base, Threat, Environmental metrics
     */
    public getNomenclature(): string {
        // const base = this.isCategoryPartiallyDefined(Cvss4P0Components.BASE_CATEGORY);
        const threat = this.isCategoryPartiallyDefined(Cvss4P0Components.THREAT_CATEGORY);
        const environmental = this.isCategoryPartiallyDefined(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY)
            || this.isCategoryPartiallyDefined(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY);

        let nomenclature = "CVSS-B";
        if (threat) nomenclature += "T";
        if (environmental) nomenclature += "E";

        return nomenclature;
    }

    public getMacroVector(): Cvss4P0MacroVector {
        return Cvss4P0MacroVector.fromVector(this);
    }

    public isBaseFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss4P0Components.BASE_CATEGORY);
    }

    public isAnyBaseDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss3P1Components.BASE_CATEGORY);
    }

    public isThreatFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss4P0Components.THREAT_CATEGORY);
    }

    public isAnyThreatDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss4P0Components.THREAT_CATEGORY);
    }

    public isAnyEnvironmentalDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss4P0Components.ENVIRONMENTAL_MODIFIED_BASE_CATEGORY) ||
            super.isCategoryPartiallyDefined(Cvss4P0Components.ENVIRONMENTAL_SECURITY_REQUIREMENT_CATEGORY);
    }

    private getJsonSchemaSeverity(score: number): SeverityType {
        if (score === 0 || isNaN(score)) {
            return "NONE";
        } else if (score <= 3.9) {
            return "LOW";
        } else if (score <= 6.9) {
            return "MEDIUM";
        } else if (score <= 8.9) {
            return "HIGH";
        } else {
            return "CRITICAL";
        }
    }

    public createJsonSchema(): any {
        const scores = this.calculateScores();
        return {
            version: "4.0",
            vectorString: this.toString(),
            baseScore: scores.overall,
            baseSeverity: this.getJsonSchemaSeverity(scores.overall),
            environmentalScore: scores.environmental,
            environmentalSeverity: this.getJsonSchemaSeverity(scores.environmental || 0.0),
            threatScore: scores.threat,
            threatSeverity: this.getJsonSchemaSeverity(scores.threat || 0.0),

            attackVector: this.getComponent(Cvss4P0Components.AV).jsonSchemaName as AttackVectorType,
            attackComplexity: this.getComponent(Cvss4P0Components.AC).jsonSchemaName as AttackComplexityType,
            attackRequirements: this.getComponent(Cvss4P0Components.AT).jsonSchemaName as AttackRequirementsType,
            privilegesRequired: this.getComponent(Cvss4P0Components.PR).jsonSchemaName as PrivilegesRequiredType,
            userInteraction: this.getComponent(Cvss4P0Components.UI).jsonSchemaName as UserInteractionType,
            vulnConfidentialityImpact: this.getComponent(Cvss4P0Components.VC).jsonSchemaName as VulnCiaType,
            vulnIntegrityImpact: this.getComponent(Cvss4P0Components.VI).jsonSchemaName as VulnCiaType,
            vulnAvailabilityImpact: this.getComponent(Cvss4P0Components.VA).jsonSchemaName as VulnCiaType,
            subConfidentialityImpact: this.getComponent(Cvss4P0Components.SC).jsonSchemaName as SubCiaType,
            subIntegrityImpact: this.getComponent(Cvss4P0Components.SI).jsonSchemaName as SubCiaType,
            subAvailabilityImpact: this.getComponent(Cvss4P0Components.SA).jsonSchemaName as SubCiaType,
            exploitMaturity: this.getComponent(Cvss4P0Components.E).jsonSchemaName as ExploitMaturityType,
            confidentialityRequirement: this.getComponent(Cvss4P0Components.CR).jsonSchemaName as CiaRequirementType,
            integrityRequirement: this.getComponent(Cvss4P0Components.IR).jsonSchemaName as CiaRequirementType,
            availabilityRequirement: this.getComponent(Cvss4P0Components.AR).jsonSchemaName as CiaRequirementType,
            modifiedAttackVector: this.getComponent(Cvss4P0Components.MAV).jsonSchemaName as ModifiedAttackVectorType,
            modifiedAttackComplexity: this.getComponent(Cvss4P0Components.MAC).jsonSchemaName as ModifiedAttackComplexityType,
            modifiedAttackRequirements: this.getComponent(Cvss4P0Components.MAT).jsonSchemaName as ModifiedAttackRequirementsType,
            modifiedPrivilegesRequired: this.getComponent(Cvss4P0Components.MPR).jsonSchemaName as ModifiedPrivilegesRequiredType,
            modifiedUserInteraction: this.getComponent(Cvss4P0Components.MUI).jsonSchemaName as ModifiedUserInteractionType,
            modifiedVulnConfidentialityImpact: this.getComponent(Cvss4P0Components.MVC).jsonSchemaName as ModifiedVulnCiaType,
            modifiedVulnIntegrityImpact: this.getComponent(Cvss4P0Components.MVI).jsonSchemaName as ModifiedVulnCiaType,
            modifiedVulnAvailabilityImpact: this.getComponent(Cvss4P0Components.MVA).jsonSchemaName as ModifiedVulnCiaType,
            modifiedSubConfidentialityImpact: this.getComponent(Cvss4P0Components.MSC).jsonSchemaName as ModifiedSubCType,
            modifiedSubIntegrityImpact: this.getComponent(Cvss4P0Components.MSI).jsonSchemaName as ModifiedSubCType,
            modifiedSubAvailabilityImpact: this.getComponent(Cvss4P0Components.MSA).jsonSchemaName as ModifiedSubCType,
            Safety: this.getComponent(Cvss4P0Components.S).jsonSchemaName as SafetyType,
            Automatable: this.getComponent(Cvss4P0Components.AU).jsonSchemaName as AutomatableType,
            Recovery: this.getComponent(Cvss4P0Components.R).jsonSchemaName as RecoveryType,
            valueDensity: this.getComponent(Cvss4P0Components.V).jsonSchemaName as ValueDensityType,
            vulnerabilityResponseEffort: this.getComponent(Cvss4P0Components.RE).jsonSchemaName as VulnerabilityResponseEffortType,
            providerUrgency: this.getComponent(Cvss4P0Components.U).jsonSchemaName as ProviderUrgencyType,
        };
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

export type JSONSchemaForCommonVulnerabilityScoringSystemVersion40 =
    JSONSchemaForCommonVulnerabilityScoringSystemVersion401
    &
    JSONSchemaForCommonVulnerabilityScoringSystemVersion402
export type JSONSchemaForCommonVulnerabilityScoringSystemVersion401 = (
    | {
    baseScore?: NoneScoreType
    baseSeverity?: NoneSeverityType
    [k: string]: unknown
}
    | {
    baseScore?: LowScoreType
    baseSeverity?: LowSeverityType
    [k: string]: unknown
}
    | {
    baseScore?: MediumScoreType
    baseSeverity?: MediumSeverityType
    [k: string]: unknown
}
    | {
    baseScore?: HighScoreType
    baseSeverity?: HighSeverityType
    [k: string]: unknown
}
    | {
    baseScore?: CriticalScoreType
    baseSeverity?: CriticalSeverityType
    [k: string]: unknown
}
    ) &
    (
        | {
        threatScore?: NoneScoreType
        threatSeverity?: NoneSeverityType
        [k: string]: unknown
    }
        | {
        threatScore?: LowScoreType
        threatSeverity?: LowSeverityType
        [k: string]: unknown
    }
        | {
        threatScore?: MediumScoreType
        threatSeverity?: MediumSeverityType
        [k: string]: unknown
    }
        | {
        threatScore?: HighScoreType
        threatSeverity?: HighSeverityType
        [k: string]: unknown
    }
        | {
        threatScore?: CriticalScoreType
        threatSeverity?: CriticalSeverityType
        [k: string]: unknown
    }
        ) &
    (
        | {
        environmentalScore?: NoneScoreType
        environmentalSeverity?: NoneSeverityType
        [k: string]: unknown
    }
        | {
        environmentalScore?: LowScoreType
        environmentalSeverity?: LowSeverityType
        [k: string]: unknown
    }
        | {
        environmentalScore?: MediumScoreType
        environmentalSeverity?: MediumSeverityType
        [k: string]: unknown
    }
        | {
        environmentalScore?: HighScoreType
        environmentalSeverity?: HighSeverityType
        [k: string]: unknown
    }
        | {
        environmentalScore?: CriticalScoreType
        environmentalSeverity?: CriticalSeverityType
        [k: string]: unknown
    }
        )
export type NoneScoreType = number
export type NoneSeverityType = "NONE"
export type LowScoreType = number
export type LowSeverityType = "LOW"
export type MediumScoreType = number
export type MediumSeverityType = "MEDIUM"
export type HighScoreType = number
export type HighSeverityType = "HIGH"
export type CriticalScoreType = number
export type CriticalSeverityType = "CRITICAL"
export type AttackVectorType = "NETWORK" | "ADJACENT" | "LOCAL" | "PHYSICAL"
export type AttackComplexityType = "HIGH" | "LOW"
export type AttackRequirementsType = "NONE" | "PRESENT"
export type PrivilegesRequiredType = "HIGH" | "LOW" | "NONE"
export type UserInteractionType = "NONE" | "PASSIVE" | "ACTIVE"
export type VulnCiaType = "NONE" | "LOW" | "HIGH"
export type SubCiaType = "NONE" | "LOW" | "HIGH"
export type ExploitMaturityType =
    | "UNREPORTED"
    | "PROOF_OF_CONCEPT"
    | "ATTACKED"
    | "NOT_DEFINED"
export type CiaRequirementType = "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED"
export type ModifiedAttackVectorType =
    | "NETWORK"
    | "ADJACENT"
    | "LOCAL"
    | "PHYSICAL"
    | "NOT_DEFINED"
export type ModifiedAttackComplexityType = "HIGH" | "LOW" | "NOT_DEFINED"
export type ModifiedAttackRequirementsType = "NONE" | "PRESENT" | "NOT_DEFINED"
export type ModifiedPrivilegesRequiredType =
    | "HIGH"
    | "LOW"
    | "NONE"
    | "NOT_DEFINED"
export type ModifiedUserInteractionType =
    | "NONE"
    | "PASSIVE"
    | "ACTIVE"
    | "NOT_DEFINED"
export type ModifiedVulnCiaType = "NONE" | "LOW" | "HIGH" | "NOT_DEFINED"
export type ModifiedSubCType = "NEGLIGIBLE" | "LOW" | "HIGH" | "NOT_DEFINED"
export type ModifiedSubIaType =
    | "NEGLIGIBLE"
    | "LOW"
    | "HIGH"
    | "SAFETY"
    | "NOT_DEFINED"
export type SafetyType = "NEGLIGIBLE" | "PRESENT" | "NOT_DEFINED"
export type AutomatableType = "NO" | "YES" | "NOT_DEFINED"
export type RecoveryType =
    | "AUTOMATIC"
    | "USER"
    | "IRRECOVERABLE"
    | "NOT_DEFINED"
export type ValueDensityType = "DIFFUSE" | "CONCENTRATED" | "NOT_DEFINED"
export type VulnerabilityResponseEffortType =
    | "LOW"
    | "MODERATE"
    | "HIGH"
    | "NOT_DEFINED"
export type ProviderUrgencyType =
    | "CLEAR"
    | "GREEN"
    | "AMBER"
    | "RED"
    | "NOT_DEFINED"

export interface JSONSchemaForCommonVulnerabilityScoringSystemVersion402 {
    /**
     * CVSS Version
     */
    version: "4.0"
    vectorString: string
    attackVector?: AttackVectorType
    attackComplexity?: AttackComplexityType
    attackRequirements?: AttackRequirementsType
    privilegesRequired?: PrivilegesRequiredType
    userInteraction?: UserInteractionType
    vulnConfidentialityImpact?: VulnCiaType
    vulnIntegrityImpact?: VulnCiaType
    vulnAvailabilityImpact?: VulnCiaType
    subConfidentialityImpact?: SubCiaType
    subIntegrityImpact?: SubCiaType
    subAvailabilityImpact?: SubCiaType
    exploitMaturity?: ExploitMaturityType
    confidentialityRequirement?: CiaRequirementType
    integrityRequirement?: CiaRequirementType
    availabilityRequirement?: CiaRequirementType
    modifiedAttackVector?: ModifiedAttackVectorType
    modifiedAttackComplexity?: ModifiedAttackComplexityType
    modifiedAttackRequirements?: ModifiedAttackRequirementsType
    modifiedPrivilegesRequired?: ModifiedPrivilegesRequiredType
    modifiedUserInteraction?: ModifiedUserInteractionType
    modifiedVulnConfidentialityImpact?: ModifiedVulnCiaType
    modifiedVulnIntegrityImpact?: ModifiedVulnCiaType
    modifiedVulnAvailabilityImpact?: ModifiedVulnCiaType
    modifiedSubConfidentialityImpact?: ModifiedSubCType
    modifiedSubIntegrityImpact?: ModifiedSubIaType
    modifiedSubAvailabilityImpact?: ModifiedSubIaType
    Safety?: SafetyType
    Automatable?: AutomatableType
    Recovery?: RecoveryType
    valueDensity?: ValueDensityType
    vulnerabilityResponseEffort?: VulnerabilityResponseEffortType
    providerUrgency?: ProviderUrgencyType

    [k: string]: unknown
}
