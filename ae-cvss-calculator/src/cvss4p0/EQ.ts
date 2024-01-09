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
