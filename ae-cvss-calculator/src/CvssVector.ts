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
    abbreviatedName?: string;
    shortName: string;
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
}

export interface ComponentCategory {
    readonly name: string;
    readonly description: string;
}

export interface BaseScoreResult {
    readonly vector: string;
    readonly overall: number;
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

export abstract class CvssVector<R extends BaseScoreResult> {
    protected components: Map<VectorComponent<VectorComponentValue>, VectorComponentValue>;
    protected vectorChangedListeners: ((vector: CvssVector<R>) => void)[] = [];

    protected constructor(initialVector?: string) {
        this.components = new Map();
        this.clearComponents();

        if (initialVector) {
            this.applyVector(initialVector);
        }
    }

    public abstract calculateScores(normalize: boolean): R;

    public abstract getVectorPrefix(): string;

    public abstract getVectorName(): string;

    public abstract getRegisteredComponents(): Map<ComponentCategory, VectorComponent<VectorComponentValue>[]>;

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

    public clearComponents() {
        this.getRegisteredComponents().forEach((components, category) => {
            components.forEach(component => this.components.set(component, component.values[0]));
        });
    }

    public addVectorChangedListener(listener: (vector: CvssVector<R>) => void): void {
        this.vectorChangedListeners.push(listener);
    }

    protected normalizeVector(vector: string): string {
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
        const normalizedVector = this.normalizeVector(vector);
        const components = normalizedVector.split('/');
        components.forEach(component => {
            if (component.length === 0) {
                return;
            }
            const [identifier, value] = component.split(':');
            if (identifier.length === 0 || value.length === 0) {
                console.warn('Invalid component/value pair', component);
                return;
            }
            this.applyComponentString(identifier, value, false);
        });
        this.vectorChangedListeners.forEach(listener => listener(this));
    }

    public applyComponentString(setComponent: string, setValue: string, notifyListeners = true) {
        const componentType = this.findComponent(setComponent);
        if (componentType) {
            const componentValue = componentType.values.find(value => value.name === setValue || value.shortName === setValue);
            if (componentValue) {
                this.applyComponent(componentType, componentValue);
                if (notifyListeners) {
                    this.vectorChangedListeners.forEach(listener => listener(this));
                }
            } else {
                throw new Error(`Unknown component value ${setValue} for component ${setComponent}`);
            }
        } else {
            throw new Error(`Unknown component ${setComponent} when setting value ${setValue}`);
        }
    }

    public applyComponent(setComponent: VectorComponent<VectorComponentValue>, setValue: VectorComponentValue, notifyListeners = true) {
        this.components.set(setComponent, setValue);
        if (notifyListeners) {
            this.vectorChangedListeners.forEach(listener => listener(this));
        }
    }

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

    public getFirstDefinedComponent<T extends VectorComponentValue>(components: VectorComponent<T>[]): T {
        return components
            .map(component => this.components.get(component))
            .find(component => component !== undefined && component.shortName !== 'ND' && component.shortName !== 'X') as T;
    }

    public toString(forceAllComponents = false, categories = this.getRegisteredComponents()): string {
        let result = "";
        for (const [category, components] of categories) {
            if (forceAllComponents || this.isCategoryPartiallyDefined(category)) {
                for (const component of components) {
                    const value = this.components.get(component);
                    if (value) {
                        result += `${component.shortName}:${value.shortName}/`;
                    }
                }
            }
        }
        return this.getVectorPrefix() + result.slice(0, -1);
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
}
