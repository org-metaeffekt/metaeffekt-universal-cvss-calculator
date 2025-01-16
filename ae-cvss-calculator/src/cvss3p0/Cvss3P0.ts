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
import {ComponentCategory, CvssVector, MultiScoreResult, VectorComponent, VectorComponentValue} from "../CvssVector";
import {Cvss3P0Components} from "./Cvss3P0Components";

export class Cvss3P0 extends CvssVector<MultiScoreResult> {

    private static readonly SCOPE_CHANGED_FACTOR = 7.52;
    private static readonly SCOPE_UNCHANGED_FACTOR = 6.42;
    private static readonly EXPLOITABILITY_COEFFICIENT = 8.22;
    private static readonly SCOPE_COEFFICIENT = 1.08;

    public constructor(initialVector?: string) {
        super(initialVector);
    }

    public getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]> {
        return Cvss3P0Components.REGISTERED_COMPONENTS;
    }

    getVectorPrefix(): string {
        return "CVSS:3.0/";
    }

    getVectorName(): string {
        return "CVSS:3.0";
    }

    fillAverageVector(): void {
        this.applyVector("AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
    }

    fillRandomBaseVector(): void {
        this.fillRandomComponentsForCategory(Cvss3P0Components.BASE_CATEGORY);
    }

    fillRandomTemporalVector(): void {
        this.fillRandomComponentsForCategory(Cvss3P0Components.TEMPORAL_CATEGORY);
    }

    fillRandomEnvironmentalVector(): void {
        this.fillRandomComponentsForCategory(Cvss3P0Components.ENVIRONMENTAL_CATEGORY);
    }

    fillRandomComponentsForCategory(category: ComponentCategory): void {
        const categoryComponents = Cvss3P0Components.REGISTERED_COMPONENTS.get(category);
        if (!categoryComponents) {
            console.warn('Failed to pick random vector components for', category);
            return;
        }
        for (let i = 0; i < categoryComponents.length; i++) {
            const component = categoryComponents[i];
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

    protected calculateScoresInternal(normalize: boolean = false): MultiScoreResult {
        const baseFullyDefined = this.isBaseFullyDefined();
        const temporalAnyDefined = this.isAnyTemporalDefined();
        const environmentalAnyDefined = this.isAnyEnvironmentalDefined();
        return {
            normalized: normalize,
            base: baseFullyDefined ? super.round(this.calculateExactBaseScore(), 1) : undefined,
            impact: baseFullyDefined ? super.normalizeScore(super.round(this.calculateImpactScore(), 1), normalize ? 6.0 : 10) : undefined,
            exploitability: baseFullyDefined ? super.normalizeScore(super.round(this.calculateExactExploitabilityScore(), 1), normalize ? 3.9 : 10) : undefined,
            temporal: baseFullyDefined && temporalAnyDefined ? super.round(this.calculateExactTemporalScore(), 1) : undefined,
            environmental: baseFullyDefined && environmentalAnyDefined ? super.round(this.calculateExactEnvironmentalScore(), 1) : undefined,
            modifiedImpact: baseFullyDefined && environmentalAnyDefined ? super.normalizeScore(super.round(Math.max(0, this.calculateExactAdjustedImpactScore()), 1), normalize ? 6.1 : 10) : undefined,
            overall: super.round(this.calculateExactOverallScore(), 1),
            vector: this.toString()
        };
    }

    public calculateExactBaseScore(): number {
        if (!this.isBaseFullyDefined()) return 0;

        let impact = this.calculateExactImpactScore();
        if (impact <= 0) return 0;

        let exploitabilityScore = this.calculateExactExploitabilityScore();
        let scope = this.getComponent(Cvss3P0Components.S).value;

        if (!scope) {
            return this.roundUp1(Math.min(impact + exploitabilityScore, 10));
        } else {
            return this.roundUp1(Math.min(Cvss3P0.SCOPE_COEFFICIENT * (impact + exploitabilityScore), 10));
        }
    }

    public calculateImpactScore(): number {
        const exactImpactScore = this.calculateExactImpactScore();
        if (exactImpactScore <= 0) return 0;
        return exactImpactScore;
    }

    public calculateExactImpactScore(): number {
        let iss = this.calculateExactISSScore();
        let scope = this.getComponent(Cvss3P0Components.S).value;

        if (scope) {
            return Cvss3P0.SCOPE_CHANGED_FACTOR * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
        } else {
            return Cvss3P0.SCOPE_UNCHANGED_FACTOR * iss;
        }
    }

    public calculateExactISSScore(): number {
        let confidentiality = this.getComponent(Cvss3P0Components.C).value;
        let integrity = this.getComponent(Cvss3P0Components.I).value;
        let availability = this.getComponent(Cvss3P0Components.A).value;

        return 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));
    }

    public calculateExactMISSScore(): number {
        let mci, mii, mai;
        let crFactor, irFactor, arFactor;

        let confidentialityImpactModified = this.getComponent(Cvss3P0Components.MC);
        let integrityImpactModified = this.getComponent(Cvss3P0Components.MI);
        let availabilityImpactModified = this.getComponent(Cvss3P0Components.MA);

        let confidentialityImpact = this.getComponent(Cvss3P0Components.C);
        let integrityImpact = this.getComponent(Cvss3P0Components.I);
        let availabilityImpact = this.getComponent(Cvss3P0Components.A);

        let confidentialityRequirement = this.getComponent(Cvss3P0Components.CR);
        let integrityRequirement = this.getComponent(Cvss3P0Components.IR);
        let availabilityRequirement = this.getComponent(Cvss3P0Components.AR);

        if (confidentialityImpactModified === Cvss3P0Components.MC.values[0]) {
            mci = confidentialityImpact.value;
        } else {
            mci = confidentialityImpactModified.value;
        }
        if (integrityImpactModified === Cvss3P0Components.MI.values[0]) {
            mii = integrityImpact.value;
        } else {
            mii = integrityImpactModified.value;
        }
        if (availabilityImpactModified === Cvss3P0Components.MA.values[0]) {
            mai = availabilityImpact.value;
        } else {
            mai = availabilityImpactModified.value;
        }

        if (confidentialityRequirement === Cvss3P0Components.CR.values[0]) {
            crFactor = confidentialityRequirement.value;
        } else {
            crFactor = confidentialityRequirement.value;
        }
        if (integrityRequirement === Cvss3P0Components.IR.values[0]) {
            irFactor = integrityRequirement.value;
        } else {
            irFactor = integrityRequirement.value;
        }
        if (availabilityRequirement === Cvss3P0Components.AR.values[0]) {
            arFactor = availabilityRequirement.value;
        } else {
            arFactor = availabilityRequirement.value;
        }

        return Math.min(1 - (
            (1 - crFactor * mci) *
            (1 - irFactor * mii) *
            (1 - arFactor * mai)
        ), 0.915);
    }

    public calculateExactExploitabilityScore(): number {
        const attackVector = this.getComponent(Cvss3P0Components.AV).value;
        const attackComplexity = this.getComponent(Cvss3P0Components.AC).value;
        const userInteraction = this.getComponent(Cvss3P0Components.UI).value;
        const scope = this.getComponent(Cvss3P0Components.S).value;

        let privilegesRequired;
        if (scope) {
            privilegesRequired = this.getComponent(Cvss3P0Components.PR).changedValue;
        } else {
            privilegesRequired = this.getComponent(Cvss3P0Components.PR).value;
        }

        return Cvss3P0.EXPLOITABILITY_COEFFICIENT * attackVector * attackComplexity * privilegesRequired * userInteraction;
    }

    public calculateExactTemporalScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        if (!this.isAnyTemporalDefined()) return 0;

        let exploitCodeMaturityFactor = this.getComponent(Cvss3P0Components.E).value;
        let remediationLevelFactor = this.getComponent(Cvss3P0Components.RL).value;
        let reportConfidenceFactor = this.getComponent(Cvss3P0Components.RC).value;
        let baseScore = this.calculateExactBaseScore();

        return this.roundUp1(baseScore * exploitCodeMaturityFactor * remediationLevelFactor * reportConfidenceFactor);
    }

    public calculateExactEnvironmentalScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        if (!this.isAnyEnvironmentalDefined()) return 0;

        let modifiedImpact = this.calculateExactAdjustedImpactScore();
        if (modifiedImpact <= 0) return 0;

        let modifiedExploitability = this.calculateAdjustedExploitability();
        let exploitCodeMaturityFactor = this.getComponent(Cvss3P0Components.E).value;
        let remediationLevelFactor = this.getComponent(Cvss3P0Components.RL).value;
        let reportConfidenceFactor = this.getComponent(Cvss3P0Components.RC).value;

        if (this.isModifiedScope()) {
            let modifiedFactor = this.roundUp1(Math.min((modifiedImpact + modifiedExploitability), 10));
            return this.roundUp1(modifiedFactor * exploitCodeMaturityFactor * remediationLevelFactor * reportConfidenceFactor);
        } else {
            let modifiedFactor = this.roundUp1(Math.min(Cvss3P0.SCOPE_COEFFICIENT * (modifiedImpact + modifiedExploitability), 10));
            return this.roundUp1(modifiedFactor * exploitCodeMaturityFactor * remediationLevelFactor * reportConfidenceFactor);
        }
    }

    public calculateExactAdjustedImpactScore(): number {
        if (!this.isBaseFullyDefined()) return 0;
        if (!this.isAnyEnvironmentalDefined()) return 0;

        let miss = this.calculateExactMISSScore();

        if (this.isModifiedScope()) {
            return Cvss3P0.SCOPE_UNCHANGED_FACTOR * miss;
        } else {
            return Cvss3P0.SCOPE_CHANGED_FACTOR * (miss - 0.029) - 3.25 * Math.pow(miss - 0.02, 15);
        }
    }

    public calculateAdjustedExploitability(): number {
        let mav = this.getFirstDefinedComponent([Cvss3P0Components.MAV, Cvss3P0Components.AV]).value;
        let mac = this.getFirstDefinedComponent([Cvss3P0Components.MAC, Cvss3P0Components.AC]).value;
        let mui = this.getFirstDefinedComponent([Cvss3P0Components.MUI, Cvss3P0Components.UI]).value;

        let mprComponent = this.getFirstDefinedComponent([Cvss3P0Components.MPR, Cvss3P0Components.PR]);
        let mpr;
        if (this.isModifiedScope()) {
            mpr = mprComponent.value;
        } else {
            mpr = mprComponent.changedValue;
        }

        return Cvss3P0.EXPLOITABILITY_COEFFICIENT * mav * mac * mpr * mui;
    }

    public isModifiedScope(): boolean {
        let scopeComponent = this.getComponent(Cvss3P0Components.S);
        let modifiedScopeComponent = this.getComponent(Cvss3P0Components.MS);

        if (modifiedScopeComponent === Cvss3P0Components.MS.values[0]) {
            return !scopeComponent.value;
        } else {
            return !modifiedScopeComponent.value;
        }
    }

    public calculateExactOverallScore(): number {
        if (this.isAnyEnvironmentalDefined()) return this.calculateExactEnvironmentalScore();
        else if (this.isAnyTemporalDefined()) return this.calculateExactTemporalScore();
        return this.calculateExactBaseScore();
    }


    public isBaseFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss3P0Components.BASE_CATEGORY);
    }

    public isTemporalFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss3P0Components.TEMPORAL_CATEGORY);
    }

    public isEnvironmentalFullyDefined(): boolean {
        return super.isCategoryFullyDefined(Cvss3P0Components.ENVIRONMENTAL_CATEGORY);
    }

    public isAnyBaseDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss3P0Components.BASE_CATEGORY);
    }

    public isAnyTemporalDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss3P0Components.TEMPORAL_CATEGORY);
    }

    public isAnyEnvironmentalDefined(): boolean {
        return super.isCategoryPartiallyDefined(Cvss3P0Components.ENVIRONMENTAL_CATEGORY);
    }

    protected roundUp1(d: number) {
        return Math.ceil(d * 10) / 10;
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

    public createJsonSchema(): JSONSchemaForCommonVulnerabilityScoringSystemVersion30 {
        const scores = this.calculateScores();
        return {
            version: "3.0",
            vectorString: this.toString(),
            baseScore: scores.base!,
            temporalScore: scores.temporal,
            environmentalScore: scores.environmental,
            baseSeverity: this.getJsonSchemaSeverity(scores.base!),
            temporalSeverity: scores.temporal ? this.getJsonSchemaSeverity(scores.temporal) : undefined,
            environmentalSeverity: scores.environmental ? this.getJsonSchemaSeverity(scores.environmental) : undefined,

            attackVector: this.getComponent(Cvss3P0Components.AV).jsonSchemaName as AttackVectorType,
            attackComplexity: this.getComponent(Cvss3P0Components.AC).jsonSchemaName as AttackComplexityType,
            privilegesRequired: this.getComponent(Cvss3P0Components.PR).jsonSchemaName as PrivilegesRequiredType,
            userInteraction: this.getComponent(Cvss3P0Components.UI).jsonSchemaName as UserInteractionType,
            scope: this.getComponent(Cvss3P0Components.S).jsonSchemaName as ScopeType,
            confidentialityImpact: this.getComponent(Cvss3P0Components.C).jsonSchemaName as CiaType,
            integrityImpact: this.getComponent(Cvss3P0Components.I).jsonSchemaName as CiaType,
            availabilityImpact: this.getComponent(Cvss3P0Components.A).jsonSchemaName as CiaType,
            exploitCodeMaturity: this.getComponent(Cvss3P0Components.E).jsonSchemaName as ExploitCodeMaturityType,
            remediationLevel: this.getComponent(Cvss3P0Components.RL).jsonSchemaName as RemediationLevelType,
            reportConfidence: this.getComponent(Cvss3P0Components.RC).jsonSchemaName as ConfidenceType,
            confidentialityRequirement: this.getComponent(Cvss3P0Components.CR).jsonSchemaName as CiaRequirementType,
            integrityRequirement: this.getComponent(Cvss3P0Components.IR).jsonSchemaName as CiaRequirementType,
            availabilityRequirement: this.getComponent(Cvss3P0Components.AR).jsonSchemaName as CiaRequirementType,
            modifiedAttackVector: this.getComponent(Cvss3P0Components.MAV).jsonSchemaName as ModifiedAttackVectorType,
            modifiedAttackComplexity: this.getComponent(Cvss3P0Components.MAC).jsonSchemaName as ModifiedAttackComplexityType,
            modifiedPrivilegesRequired: this.getComponent(Cvss3P0Components.MPR).jsonSchemaName as ModifiedPrivilegesRequiredType,
            modifiedUserInteraction: this.getComponent(Cvss3P0Components.MUI).jsonSchemaName as ModifiedUserInteractionType,
            modifiedScope: this.getComponent(Cvss3P0Components.MS).jsonSchemaName as ModifiedScopeType,
            modifiedConfidentialityImpact: this.getComponent(Cvss3P0Components.MC).jsonSchemaName as ModifiedCiaType,
            modifiedIntegrityImpact: this.getComponent(Cvss3P0Components.MI).jsonSchemaName as ModifiedCiaType,
            modifiedAvailabilityImpact: this.getComponent(Cvss3P0Components.MA).jsonSchemaName as ModifiedCiaType
        };
    }
}

export type AttackVectorType =
    | "NETWORK"
    | "ADJACENT_NETWORK"
    | "LOCAL"
    | "PHYSICAL"
export type AttackComplexityType = "HIGH" | "LOW"
export type PrivilegesRequiredType = "HIGH" | "LOW" | "NONE"
export type UserInteractionType = "NONE" | "REQUIRED"
export type ScopeType = "UNCHANGED" | "CHANGED"
export type CiaType = "NONE" | "LOW" | "HIGH"
export type ScoreType = number
export type SeverityType = "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type ExploitCodeMaturityType =
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
export type ConfidenceType =
    | "UNKNOWN"
    | "REASONABLE"
    | "CONFIRMED"
    | "NOT_DEFINED"
export type CiaRequirementType = "LOW" | "MEDIUM" | "HIGH" | "NOT_DEFINED"
export type ModifiedAttackVectorType =
    | "NETWORK"
    | "ADJACENT_NETWORK"
    | "LOCAL"
    | "PHYSICAL"
    | "NOT_DEFINED"
export type ModifiedAttackComplexityType = "HIGH" | "LOW" | "NOT_DEFINED"
export type ModifiedPrivilegesRequiredType =
    | "HIGH"
    | "LOW"
    | "NONE"
    | "NOT_DEFINED"
export type ModifiedUserInteractionType = "NONE" | "REQUIRED" | "NOT_DEFINED"
export type ModifiedScopeType = "UNCHANGED" | "CHANGED" | "NOT_DEFINED"
export type ModifiedCiaType = "NONE" | "LOW" | "HIGH" | "NOT_DEFINED"

export interface JSONSchemaForCommonVulnerabilityScoringSystemVersion30 {
    /**
     * CVSS Version
     */
    version: "3.0"
    vectorString: string
    baseScore: ScoreType
    temporalScore?: ScoreType
    environmentalScore?: ScoreType
    baseSeverity: SeverityType
    temporalSeverity?: SeverityType
    environmentalSeverity?: SeverityType
    attackVector?: AttackVectorType
    attackComplexity?: AttackComplexityType
    privilegesRequired?: PrivilegesRequiredType
    userInteraction?: UserInteractionType
    scope?: ScopeType
    confidentialityImpact?: CiaType
    integrityImpact?: CiaType
    availabilityImpact?: CiaType
    exploitCodeMaturity?: ExploitCodeMaturityType
    remediationLevel?: RemediationLevelType
    reportConfidence?: ConfidenceType
    confidentialityRequirement?: CiaRequirementType
    integrityRequirement?: CiaRequirementType
    availabilityRequirement?: CiaRequirementType
    modifiedAttackVector?: ModifiedAttackVectorType
    modifiedAttackComplexity?: ModifiedAttackComplexityType
    modifiedPrivilegesRequired?: ModifiedPrivilegesRequiredType
    modifiedUserInteraction?: ModifiedUserInteractionType
    modifiedScope?: ModifiedScopeType
    modifiedConfidentialityImpact?: ModifiedCiaType
    modifiedIntegrityImpact?: ModifiedCiaType
    modifiedAvailabilityImpact?: ModifiedCiaType

    [k: string]: unknown
}
