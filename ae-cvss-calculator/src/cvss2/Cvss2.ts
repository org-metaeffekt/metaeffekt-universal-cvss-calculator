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
import { ComponentCategory, CvssVector, MultiScoreResult, VectorComponent, VectorComponentValue } from "../CvssVector";
import { Cvss2Components } from "./Cvss2Components";

export class Cvss2 extends CvssVector<MultiScoreResult> {

    public constructor(initialVector?: string) {
        super(initialVector);
    }

    public getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]> {
        return Cvss2Components.REGISTERED_COMPONENTS;
    }

    getVectorPrefix(): string {
        return "";
    }

    getVectorName(): string {
        return "CVSS:2.0";
    }

    fillAverageVector(): void {
        this.applyVector("AV:A/AC:M/Au:N/C:P/I:P/A:P");
    }

    fillRandomBaseVector(): void {
        const baseCategoryComponents = Cvss2Components.BASE_CATEGORY_VALUES;
        for (let i = 0; i < baseCategoryComponents.length; i++) {
            const component = baseCategoryComponents[i];
            const value = super.pickRandomDefinedComponentValue(component);
            if (value) {
                this.applyComponent(component, value);
            } else {
                console.warn('Failed to pick random vector component for', component);
                this.fillAverageVector();
                return;
            }
        }
    }

    calculateScores(normalize: boolean = false): MultiScoreResult {
        const baseFullyDefined = this.isBaseFullyDefined();
        const temporalAnyDefined = this.isAnyTemporalDefined();
        const environmentalAnyDefined = this.isAnyEnvironmentalDefined();
        return {
            base: baseFullyDefined ? super.round(this.calculateExactBaseScore(), 1) : undefined,
            impact: baseFullyDefined ? super.round(this.calculateExactImpactScore(), 1) : undefined,
            exploitability: baseFullyDefined ? super.round(this.calculateExactExploitabilityScore(), 1) : undefined,
            temporal: baseFullyDefined && temporalAnyDefined ? super.round(this.calculateExactTemporalScore(), 1) : undefined,
            environmental: baseFullyDefined && environmentalAnyDefined ? super.round(this.calculateExactEnvironmentalScore(), 1) : undefined,
            modifiedImpact: baseFullyDefined && environmentalAnyDefined ? super.round(this.calculateExactAdjustedImpactScore(), 1) : undefined,
            overall: super.round(this.calculateExactOverallScore(), 1),
            vector: this.toString()
        };
    }

    private calculateExactBaseScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        let impact = this.calculateExactImpactScore();
        let exploitability = this.calculateExactExploitabilityScore();
        let fScore = this.f(impact);
        return ((0.6 * impact) + (0.4 * exploitability) - 1.5) * fScore;
    }

    private calculateExactImpactScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        let confidentialityImpact = (1 - this.getComponent(Cvss2Components.C).value);
        let integrityImpact = (1 - this.getComponent(Cvss2Components.I).value);
        let availabilityImpact = (1 - this.getComponent(Cvss2Components.A).value);
        return 10.41 * (1 - confidentialityImpact * integrityImpact * availabilityImpact);
    }

    private calculateExactExploitabilityScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        let accessComplexity = this.getComponent(Cvss2Components.AC).value;
        let authentication = this.getComponent(Cvss2Components.Au).value;
        let accessVector = this.getComponent(Cvss2Components.AV).value;
        return 20 * accessComplexity * authentication * accessVector;
    }

    private calculateExactTemporalScore(): number {
        if (!this.isAnyTemporalDefined()) return 0;
        let baseScore = super.round(this.calculateExactBaseScore(), 1);
        let exploitability = this.getComponent(Cvss2Components.E).value;
        let remediationLevel = this.getComponent(Cvss2Components.RL).value;
        let reportConfidence = this.getComponent(Cvss2Components.RC).value;
        return baseScore * exploitability * remediationLevel * reportConfidence;
    }

    private calculateExactAdjustedBaseScore(): number {
        let adjustedImpact = this.calculateExactAdjustedImpactScore();
        let exploitability = this.calculateExactExploitabilityScore();
        exploitability = this.round(exploitability, 1);
        let fScore = this.f(adjustedImpact);
        return ((0.6 * adjustedImpact) + (0.4 * exploitability) - 1.5) * fScore;
    }

    private calculateExactAdjustedTemporalScore(): number {
        let adjustedBase = this.calculateExactAdjustedBaseScore();
        let exploitability = this.getComponent(Cvss2Components.E).value;
        let remediationLevel = this.getComponent(Cvss2Components.RL).value;
        let reportConfidence = this.getComponent(Cvss2Components.RC).value;
        return adjustedBase * exploitability * remediationLevel * reportConfidence;
    }

    private calculateExactEnvironmentalScore(): number {
        if (!this.isAnyEnvironmentalDefined()) return 0;
        let adjustedTemporal = this.calculateExactAdjustedTemporalScore();
        let collateralDamagePotential = this.getComponent(Cvss2Components.CDP).value;
        let targetDistribution = this.getComponent(Cvss2Components.TD).value;
        return (adjustedTemporal + (10 - adjustedTemporal) * collateralDamagePotential) * targetDistribution;
    }

    private calculateExactAdjustedImpactScore(): number {
        if (!this.isAnyEnvironmentalDefined()) return 0;

        let confidentialityImpact = this.getComponent(Cvss2Components.C).value;
        let integrityImpact = this.getComponent(Cvss2Components.I).value;
        let availabilityImpact = this.getComponent(Cvss2Components.A).value;
        let confidentialityRequirement = this.getComponent(Cvss2Components.CR).value;
        let integrityRequirement = this.getComponent(Cvss2Components.IR).value;
        let availabilityRequirement = this.getComponent(Cvss2Components.AR).value;

        return Math.min(10,
            10.41 * (1 -
                (1 - confidentialityImpact * confidentialityRequirement)
                * (1 - integrityImpact * integrityRequirement)
                * (1 - availabilityImpact * availabilityRequirement)));
    }

    private calculateExactOverallScore(): number {
        if (this.isAnyEnvironmentalDefined()) return this.calculateExactEnvironmentalScore();
        if (this.isAnyTemporalDefined()) return this.calculateExactTemporalScore();
        return this.calculateExactBaseScore();
    }

    public isBaseFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss2Components.BASE_CATEGORY);
    }

    public isTemporalFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss2Components.TEMPORAL_CATEGORY);
    }

    public isEnvironmentalFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss2Components.ENVIRONMENTAL_CATEGORY);
    }

    public isAnyBaseDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss2Components.BASE_CATEGORY);
    }

    public isAnyTemporalDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss2Components.TEMPORAL_CATEGORY);
    }

    public isAnyEnvironmentalDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss2Components.ENVIRONMENTAL_CATEGORY);
    }

    private f(impact: number): number {
        if (impact === 0) return 0;
        return 1.176;
    }

    public createJsonSchema(): JSONSchemaForCommonVulnerabilityScoringSystemVersion20 {
        const scores = this.calculateScores();
        return {
            version: "2.0",
            vectorString: this.toString(),
            baseScore: scores.base!,
            temporalScore: scores.temporal,
            environmentalScore: scores.environmental,
            accessVector: this.getComponent(Cvss2Components.AV).jsonSchemaName as AccessVectorType,
            accessComplexity: this.getComponent(Cvss2Components.AC).jsonSchemaName as AccessComplexityType,
            authentication: this.getComponent(Cvss2Components.Au).jsonSchemaName as AuthenticationType,
            confidentialityImpact: this.getComponent(Cvss2Components.C).jsonSchemaName as CiaType,
            integrityImpact: this.getComponent(Cvss2Components.I).jsonSchemaName as CiaType,
            availabilityImpact: this.getComponent(Cvss2Components.A).jsonSchemaName as CiaType,
            exploitability: this.getComponent(Cvss2Components.E).jsonSchemaName as ExploitabilityType,
            remediationLevel: this.getComponent(Cvss2Components.RL).jsonSchemaName as RemediationLevelType,
            reportConfidence: this.getComponent(Cvss2Components.RC).jsonSchemaName as ReportConfidenceType,
            collateralDamagePotential: this.getComponent(Cvss2Components.CDP).jsonSchemaName as CollateralDamagePotentialType,
            targetDistribution: this.getComponent(Cvss2Components.TD).jsonSchemaName as TargetDistributionType,
            confidentialityRequirement: this.getComponent(Cvss2Components.CR).jsonSchemaName as CiaRequirementType,
            integrityRequirement: this.getComponent(Cvss2Components.IR).jsonSchemaName as CiaRequirementType,
            availabilityRequirement: this.getComponent(Cvss2Components.AR).jsonSchemaName as CiaRequirementType,
        }
    }
}

export type AccessVectorType = "NETWORK" | "ADJACENT_NETWORK" | "LOCAL"
export type AccessComplexityType = "HIGH" | "MEDIUM" | "LOW"
export type AuthenticationType = "MULTIPLE" | "SINGLE" | "NONE"
export type CiaType = "NONE" | "PARTIAL" | "COMPLETE"
export type ScoreType = number
export type ExploitabilityType =
    | "UNPROVEN"
    | "PROOF_OF_CONCEPT"
    | "FUNCTIONAL"
    | "HIGH"
    | "NOT_DEFINED"
export type RemediationLevelType =
    | "OFFICIAL_FIX"
    | "TEMPORARY_FIX"
    | "WORKAROUND"
    | "UNAVAILABLE"
    | "NOT_DEFINED"
export type ReportConfidenceType =
    | "UNCONFIRMED"
    | "UNCORROBORATED"
    | "CONFIRMED"
    | "NOT_DEFINED"
export type CollateralDamagePotentialType =
    | "NONE"
    | "LOW"
    | "LOW_MEDIUM"
    | "MEDIUM_HIGH"
    | "HIGH"
    | "NOT_DEFINED"
export type TargetDistributionType =
    | "NONE"
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "NOT_DEFINED"
export type CiaRequirementType = "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED"

export interface JSONSchemaForCommonVulnerabilityScoringSystemVersion20 {
    /**
     * CVSS Version
     */
    version: "2.0"
    vectorString: string
    baseScore: ScoreType
    temporalScore?: ScoreType
    environmentalScore?: ScoreType
    accessVector?: AccessVectorType
    accessComplexity?: AccessComplexityType
    authentication?: AuthenticationType
    confidentialityImpact?: CiaType
    integrityImpact?: CiaType
    availabilityImpact?: CiaType
    exploitability?: ExploitabilityType
    remediationLevel?: RemediationLevelType
    reportConfidence?: ReportConfidenceType
    collateralDamagePotential?: CollateralDamagePotentialType
    targetDistribution?: TargetDistributionType
    confidentialityRequirement?: CiaRequirementType
    integrityRequirement?: CiaRequirementType
    availabilityRequirement?: CiaRequirementType

    [k: string]: unknown
}
