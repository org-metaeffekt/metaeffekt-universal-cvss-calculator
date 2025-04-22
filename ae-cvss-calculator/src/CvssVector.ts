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
export interface VectorComponentValue {
    name: string;
    shortName: string;
    abbreviatedName?: string;
    jsonSchemaName?: string;
    description: string;
    hide?: boolean;
}

export interface NumberVectorComponentValue extends VectorComponentValue {
    value: number;
}

export interface ChangedNumberVectorComponentValue extends NumberVectorComponentValue {
    changedValue: number;
}

export interface BooleanVectorComponentValue extends VectorComponentValue {
    value: boolean;
}

export interface VectorComponent<T extends VectorComponentValue> {
    readonly name: string;
    readonly shortName: string;
    readonly subCategory?: string;
    description: string;
    readonly values: T[];
    worseCaseValue?: T;
    readonly baseMetricEquivalent?: VectorComponent<VectorComponentValue>;
    readonly baseMetricEquivalentMapper?: (value: VectorComponentValue) => VectorComponentValue;
}

export interface ComponentCategory {
    readonly name: string;
    readonly description: string;
}

export interface BaseScoreResult {
    readonly vector: string;
    readonly overall: number;
    readonly normalized: boolean;
}

export interface MultiScoreResult extends BaseScoreResult {
    readonly base: number | undefined;
    readonly exploitability: number | undefined;
    readonly impact: number | undefined;
    readonly environmental: number | undefined;
    readonly temporal: number | undefined;
    readonly modifiedImpact: number | undefined;
}

export interface SingleScoreResult extends BaseScoreResult {
}

class CachedVectorScores<R extends BaseScoreResult> {
    protected vector: string;
    protected normalize: boolean;
    protected scores: R;

    constructor(vector: string, normalize: boolean, scores: R) {
        this.vector = vector;
        this.normalize = normalize;
        this.scores = scores;
    }

    public isUpToDate(vector: string, normalize: boolean): boolean {
        return this.vector === vector && this.normalize === normalize;
    }

    public getScores(): R {
        return this.scores;
    }
}

export abstract class CvssVector<R extends BaseScoreResult> {
    protected components: Map<VectorComponent<VectorComponentValue>, VectorComponentValue>;
    protected vectorChangedListeners: ((vector: CvssVector<R>) => void)[] = [];
    protected cachedScores: CachedVectorScores<R> | undefined;

    protected constructor(initialVector?: string) {
        this.components = new Map();
        this.clearComponents();

        if (initialVector) {
            this.applyVector(initialVector);
        }
    }

    public calculateScores(normalize: boolean = false): R {
        const vectorString = this.toString(true);

        if (this.cachedScores && this.cachedScores.isUpToDate(vectorString, normalize)) {
            return this.cachedScores.getScores();
        }

        const scores = this.calculateScoresInternal(normalize);
        this.cachedScores = new CachedVectorScores(vectorString, normalize, scores);
        return scores;
    }

    protected abstract calculateScoresInternal(normalize: boolean): R;

    public abstract getVectorPrefix(): string;

    public abstract getVectorName(): string;

    public abstract getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>;

    public abstract createJsonSchema(): any;

    public fillBaseMetrics() {
        for (const [category, components] of this.getRegisteredComponents()) {
            if (category.name === 'base') {
                for (const component of components) {
                    const componentValue = component.values[1];
                    if (componentValue) {
                        this.applyComponent(component, componentValue);
                    }
                }
                return;
            }
        }
        throw new Error('No base category found');
    }

    public abstract fillAverageVector(): void;

    public abstract fillRandomBaseVector(): void;

    public abstract isBaseFullyDefined(): boolean

    public abstract isAnyBaseDefined(): boolean

    public getComponents(): Map<VectorComponent<VectorComponentValue>, VectorComponentValue> {
        return this.components;
    }

    public clearComponents() {
        this.getRegisteredComponents().forEach((components, category) => {
            components.forEach(component => this.components.set(component, component.values[0]));
        });
    }

    public addVectorChangedListener(listener: (vector: CvssVector<R>) => void): void {
        this.vectorChangedListeners.push(listener);
    }

    normalizeVector(vector: string): string {
        return vector
            .replace(/\(/g, '')
            .replace(/\)/g, '')
            .replace(/CVSS:\d+\.?\d?/g, '')
            .replace(/\s/g, '')
            .replace(/\\/g, '')
            .replace(/^\//g, '')
            .replace(/\/$/g, '')
            .trim();
    }

    findComponent(nameOrShortName: string): VectorComponent<VectorComponentValue> | undefined {
        for (const categoryComponents of this.getRegisteredComponents().values()) {
            const component = categoryComponents.find(c => c.name === nameOrShortName || c.shortName === nameOrShortName);
            if (component) {
                return component;
            }
        }

        return Array.from(this.components.keys()).find(c => c.name === nameOrShortName || c.shortName === nameOrShortName);
    }

    public applyVector(vector: string) {
        this.applyVectorCount(vector);
    }

    public applyVectorCount(vector: string): number {
        const normalizedVector = this.normalizeVector(vector);
        const components = normalizedVector.split('/');
        let appliedParts = 0;
        components.forEach(component => {
            if (component.length === 0) {
                return;
            }
            const [identifier, value] = component.split(':');
            if (identifier.length === 0 || value.length === 0) {
                console.warn('Invalid component/value pair', component);
                return;
            }
            if (this.applyComponentString(identifier, value, false)) {
                appliedParts++;
            }
        });
        this.vectorChangedListeners.forEach(listener => listener(this));
        return appliedParts;
    }

    public applyComponentString(setComponent: string, setValue: string, notifyListeners = true): boolean {
        const componentType = this.findComponent(setComponent);
        if (componentType) {
            const componentValue = componentType.values.find(value => value.name === setValue || value.shortName === setValue);
            if (componentValue) {
                if (this.components.get(componentType) === componentValue) {
                    return false;
                }
                this.applyComponent(componentType, componentValue);
                if (notifyListeners) {
                    this.vectorChangedListeners.forEach(listener => listener(this));
                }

                return true;
            } else {
                throw new Error(`Unknown component value ${setValue} for component ${setComponent}`);
            }
        } else {
            throw new Error(`Unknown component ${setComponent} when setting value ${setValue}`);
        }
    }

    public applyComponentStringSilent(setComponent: string, setValue: string, notifyListeners = true): boolean {
        try {
            return this.applyComponentString(setComponent, setValue, notifyListeners);
        } catch (error) {
            return false;
        }
    }

    public applyComponent(setComponent: VectorComponent<VectorComponentValue>, setValue: VectorComponentValue, notifyListeners = true) {
        this.components.set(setComponent, setValue);
        if (notifyListeners) {
            this.vectorChangedListeners.forEach(listener => listener(this));
        }
    }

    // SECTION: apply by score change

    protected applyVectorPartsIf(vector: string, scoreType: (vector: CvssVector<R>) => number, lower: boolean): number {
        if (!vector) return 0;

        const normalizedVector = this.normalizeVector(vector);
        if (normalizedVector.length === 0) return 0;

        const args = normalizedVector.split('/');
        let appliedPartsCount = 0;

        for (const argument of args) {
            if (!argument) continue;
            const parts = argument.split(':', 2);

            const clone = this.clone();

            const currentScore = scoreType(clone);

            if (parts.length === 2) {
                clone.applyComponentStringSilent(parts[0], parts[1]);
                const newScore = scoreType(clone);

                if (lower) {
                    if (newScore <= currentScore) {
                        appliedPartsCount += this.applyComponentStringSilent(parts[0], parts[1]) ? 1 : 0;
                    }
                } else {
                    if (newScore >= currentScore) {
                        appliedPartsCount += this.applyComponentStringSilent(parts[0], parts[1]) ? 1 : 0;
                    }
                }
            } else {
                console.warn('Unknown vector argument:', argument);
            }
        }

        return appliedPartsCount;
    }

    public applyVectorPartsIfLower(vector: string, scoreType: (vector: CvssVector<R>) => number): number {
        return this.applyVectorPartsIf(vector, scoreType, true);
    }

    public applyVectorPartsIfHigher(vector: string, scoreType: (vector: CvssVector<R>) => number): number {
        return this.applyVectorPartsIf(vector, scoreType, false);
    }

    public applyVectorPartsIfLowerVector(vector: CvssVector<R>, scoreType: (vector: CvssVector<R>) => number): number {
        return this.applyVectorPartsIf(vector.toStringDefinedParts(), scoreType, true);
    }

    public applyVectorPartsIfHigherVector(vector: CvssVector<R>, scoreType: (vector: CvssVector<R>) => number): number {
        return this.applyVectorPartsIf(vector.toStringDefinedParts(), scoreType, false);
    }

    // SECTION: other access methods

    public getComponent<T extends VectorComponentValue>(component: VectorComponent<T>): T {
        const componentValue = this.components.get(component);
        if (!componentValue) {
            throw new Error(`Unknown component: ${component.name}`);
        }
        return componentValue as T;
    }

    public getComponentByString(component: string): VectorComponentValue {
        const componentType = this.findComponent(component);
        if (!componentType) {
            throw new Error(`Unknown component: ${component}`);
        }
        const componentValue = this.components.get(componentType);
        if (!componentValue) {
            throw new Error(`Unknown component: ${component}`);
        }
        return componentValue;
    }

    public getComponentByStringOpt(component: string): VectorComponentValue | null {
        try {
            return this.getComponentByString(component);
        } catch (e) {
            return null;
        }
    }

    public size(): number {
        // only include defined components
        return Array.from(this.components.values()).filter(this.isComponentValueDefined).length;
    }

    public getFirstDefinedComponent<T extends VectorComponentValue>(components: VectorComponent<T>[]): T {
        return components
            .map(component => this.components.get(component))
            .find(this.isComponentValueDefined) as T;
    }

    public toString(forceAllComponents = false, categories = this.getRegisteredComponents(), showOnlyDefinedComponents = false): string {
        let result = "";
        for (const [category, components] of categories) {
            if (forceAllComponents || this.isCategoryPartiallyDefined(category)) {
                for (const component of components) {
                    const value = this.components.get(component);
                    if (value) {
                        if (showOnlyDefinedComponents && !this.isComponentValueDefined(value)) {
                            continue;
                        }
                        result += `${component.shortName}:${value.shortName}/`;
                    }
                }
            }
        }
        return this.getVectorPrefix() + result.slice(0, -1);
    }

    public toStringDefinedParts(): string {
        return this.toString(false, this.getRegisteredComponents(), true);
    }

    protected isCategoryFullyDefined(category: ComponentCategory): boolean {
        const components = this.getRegisteredComponents().get(category);
        if (!components) return false;
        return components.every(component =>
            this.components.get(component) !== undefined &&
            this.components.get(component)!.shortName !== 'ND' &&
            this.components.get(component)!.shortName !== 'X'
        );
    }

    public isCategoryPartiallyDefined(category: ComponentCategory): boolean {
        const components = this.getRegisteredComponents().get(category);
        if (!components) return false;
        return components.some(component =>
            this.components.get(component) !== undefined &&
            this.components.get(component)!.shortName !== 'ND' &&
            this.components.get(component)!.shortName !== 'X'
        );
    }

    protected round(value: number, precision: number) {
        let scale = Math.pow(10, precision);
        return Math.round(value * scale) / scale;
    }

    protected roundUp(value: number) {
        let input = Math.round(value * 100000);
        if ((input % 10000) === 0) {
            return input / 100000.0;
        } else {
            return (Math.floor(input / 10000) + 1) / 10.0;
        }
    }

    protected normalizeScore(score: number, max: number): number {
        if (max === 10.0) {
            return score;
        }
        return this.round(this.mapRange(score, 0, max, 0, 10), 1);
    }

    protected mapRange(value: number, min: number, max: number, newMin: number, newMax: number): number {
        return (value - min) / (max - min) * (newMax - newMin) + newMin;
    }

    protected pickRandomDefinedComponentValue(component: VectorComponent<VectorComponentValue>): VectorComponentValue | undefined {
        for (let i = 0; i < 999999; i++) {
            const pick = component.values[Math.floor(Math.random() * component.values.length)];
            if (pick.shortName === 'X' || pick.shortName === 'ND' || pick.hide) {
                continue;
            }
            return pick;
        }

        return undefined;
    }

    public clone(): CvssVector<R> {
        const vector = new (this.constructor as any)();
        vector.components = new Map(this.components);
        return vector;
    }

    public diffVector(checkVector: CvssVector<R>): CvssVector<R> {
        const diffVector = new (this.constructor as any)();

        // only include components that are different:
        // - value differs
        // - value is not defined in A
        // - value is not defined in B

        for (const [category, components] of this.getRegisteredComponents()) {
            for (const component of components) {
                const valueA = this.components.get(component);
                const valueB = checkVector.components.get(component);

                const valueADefined = this.isComponentValueDefined(valueA);
                const valueBDefined = this.isComponentValueDefined(valueB);

                // @ts-ignore
                if (valueADefined && valueBDefined && valueA.shortName !== valueB.shortName) {
                    diffVector.applyComponent(component, valueB);
                } else if (!valueADefined && valueBDefined) {
                    diffVector.applyComponent(component, valueB);
                } else if (valueADefined && !valueBDefined) {
                    diffVector.applyComponent(component, valueA);
                }
            }
        }

        return diffVector;
    }

    public applyEnvironmentalMetricsOntoBase() {
        // iterate over all metrics, use the baseMetricEquivalent to find the base metric and apply the value as string
        for (const [category, components] of this.getRegisteredComponents()) {
            for (const component of components) {
                const value = this.components.get(component);
                if (value) {
                    if (component.baseMetricEquivalent) {
                        if (this.isComponentValueDefined(value)) {
                            if (component.baseMetricEquivalentMapper) {
                                this.applyComponentString(component.baseMetricEquivalent.shortName, component.baseMetricEquivalentMapper(value).shortName, false);
                            } else {
                                this.applyComponentString(component.baseMetricEquivalent.shortName, value.shortName, false);
                            }
                            this.applyComponent(component, component.values[0], false);
                        }
                    }
                }
            }
        }

        this.vectorChangedListeners.forEach(listener => listener(this));
    }

    protected isComponentValueDefined(component: VectorComponentValue | undefined): boolean {
        return component !== undefined && component.shortName !== 'ND' && component.shortName !== 'X';
    }

    static _reorderAttributeSeverityOrder(attributes: VectorComponentValue[]) {
        // check if there is only one key. if so, take each single one value from that one key and add it as a new key with the index as key
        const newAttributes: VectorComponentValue[][] = [];
        attributes.forEach((value, index) => {
            newAttributes.push([value]);
        });
        return newAttributes;
    }
}
