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
import {ICvss4P0} from "./ICvss4P0";

export class EQ {
    public static createCvssInstance : (vector: string) => ICvss4P0;

    private readonly level: string;
    private readonly vectorDepth: number;
    private readonly highestSeverityVectorsUnparsed: string[];
    private highestSeverityVectors: ICvss4P0[] = [];
    private readonly predicate: (vector: ICvss4P0) => boolean;

    constructor(level: string, vectorDepth: number, highestSeverityVectors: string[], predicate: (vector: ICvss4P0) => boolean) {
        this.level = level;
        this.vectorDepth = vectorDepth;
        this.highestSeverityVectorsUnparsed = highestSeverityVectors;
        this.predicate = predicate;
    }

    public getLevel(): string {
        return this.level;
    }

    public getLevelAsInt(): number {
        return parseInt(this.level);
    }

    public getVectorDepth(): number {
        return this.vectorDepth;
    }

    public getHighestSeverityVectors(): ICvss4P0[] {
        if (this.highestSeverityVectors.length === 0) {
            this.highestSeverityVectors = this.highestSeverityVectorsUnparsed.map(v => EQ.createCvssInstance(v));
        }
        return this.highestSeverityVectors;
    }

    public getHighestSeverityVectorsUnparsed(): string[] {
        return this.highestSeverityVectorsUnparsed;
    }

    public matchesConstraints(vector: ICvss4P0): boolean {
        return this.predicate(vector);
    }
}
