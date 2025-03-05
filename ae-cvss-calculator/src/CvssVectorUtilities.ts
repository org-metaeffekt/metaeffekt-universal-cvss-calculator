import { Cvss2 } from "./cvss2/Cvss2";
import { Cvss3P0 } from "./cvss3p0/Cvss3P0";
import { Cvss3P1 } from "./cvss3p1/Cvss3P1";
import { Cvss4P0 } from "./cvss4p0/Cvss4P0";
import { CvssVector, VectorComponentValue } from "./CvssVector";
import { Cvss2Components } from "./cvss2/Cvss2Components";
import { Cvss3P0Components } from "./cvss3p0/Cvss3P0Components";
import { Cvss3P1Components } from "./cvss3p1/Cvss3P1Components";
import { Cvss4P0Components } from "./cvss4p0/Cvss4P0Components";


const cvssVersionConstructors: { [key: string]: any } = {
    'CVSS:2.0': Cvss2,
    '2.0': Cvss2,
    'CVSS:3.0': Cvss3P0,
    '3.0': Cvss3P0,
    'CVSS:3.1': Cvss3P1,
    '3.1': Cvss3P1,
    'CVSS:4.0': Cvss4P0,
    '4.0': Cvss4P0,
}

function fromVector(vectorInput: string, forceVersion = undefined) {
    if (forceVersion) {
        const vectorClass = cvssVersionConstructors[forceVersion];
        if (vectorClass) {
            return new vectorClass(vectorInput);
        }
    }
    const vectorClass = cvssVersionConstructors[vectorInput];
    if (vectorClass) {
        return new vectorClass();
    }
    // assume that it is a vector string
    // - first attempt: try to find a CVSS-prefix using the name of the vector
    for (let versionName in cvssVersionConstructors) {
        const specificVectorClass = cvssVersionConstructors[versionName];
        if (vectorInput.startsWith(versionName)) {
            try {
                return new specificVectorClass(vectorInput);
            } catch (e) {
            }
        }
    }
    // - second attempt: just let each class parse the vector string and return the first one that doesn't throw an error
    for (let versionName in cvssVersionConstructors) {
        const specificVectorClass = cvssVersionConstructors[versionName];
        try {
            return new specificVectorClass(vectorInput);
        } catch (e) {
        }
    }
    return null;
}

// SECTION: apply by metric

type ApplyMetricsPredicate = (
    currentAttribute: VectorComponentValue | null,
    unmodifiedAttribute: VectorComponentValue | null,
    modifiedAttribute: VectorComponentValue | null,
    newAttribute: VectorComponentValue | null,
    isNewAttributeModified: boolean
) => boolean;

function applyVectorPartsIfMetric(self: CvssVector<any>, vector: string, predicate: ApplyMetricsPredicate): number {
    if (!vector) return 0;

    const normalizedVector = self.normalizeVector(vector);
    if (normalizedVector.length === 0) return 0;

    const args = normalizedVector.split('/');
    let appliedPartsCount = 0;

    for (const argument of args) {
        if (!argument) continue;
        const parts = argument.split(':', 2);

        if (parts.length === 2) {
            const metric = parts[0];
            const value = parts[1];

            const currentAttribute: VectorComponentValue | null = self.getComponentByStringOpt(metric);
            const isSetAttributeModified = metric.startsWith('M');

            const unmodifiedMetric: string = isSetAttributeModified ? metric.replace('M', '') : metric;
            const unmodifiedAttribute: VectorComponentValue | null = self.getComponentByStringOpt(unmodifiedMetric);
            const modifiedMetric: string = isSetAttributeModified ? metric : `M${metric}`;
            const modifiedAttribute: VectorComponentValue | null = self.getComponentByStringOpt(modifiedMetric);

            const currentValue: string = currentAttribute?.shortName || 'X';
            const applied: boolean = self.applyComponentStringSilent(metric, value);
            const newAttribute: VectorComponentValue | null = self.getComponentByStringOpt(metric);

            // console.log("checking [", metric + ":" + value, "aka", newAttribute?.shortName, "] is [", currentValue, "] aka umod [", unmodifiedAttribute?.shortName, "] aka mod [", modifiedAttribute?.shortName, "]");

            if (applied && predicate(currentAttribute, unmodifiedAttribute, modifiedAttribute, newAttribute, isSetAttributeModified)) {
                // console.log("  applied [", metric + ":" + value, "aka", newAttribute?.shortName, "]");
                appliedPartsCount++;
            } else {
                self.applyComponentStringSilent(metric, currentValue);
            }
        } else {
            console.warn('Unknown vector argument:', argument);
        }
    }

    return appliedPartsCount;
}

function applyVectorPartsIfMetricsLower(self: CvssVector<any>, vector: string): number {
    if (!vector) return 0;
    return applyVectorPartsIfMetric(self, vector, (current, unmodified, modified, newAttr, isNewModified) => {
        const severityOrder = findOldNewSeverityOrder(self, unmodified, modified, newAttr, isNewModified);
        return severityOrder.newSeverity <= severityOrder.oldSeverity;
    });
}

function applyVectorPartsIfMetricsHigher(self: CvssVector<any>, vector: string): number {
    if (!vector) return 0;
    return applyVectorPartsIfMetric(self, vector, (current, unmodified, modified, newAttr, isNewModified) => {
        const severityOrder = findOldNewSeverityOrder(self, unmodified, modified, newAttr, isNewModified);
        return severityOrder.newSeverity >= severityOrder.oldSeverity;
    });
}

function findOldNewSeverityOrder(
    self: CvssVector<any>,
    unmodifiedAttribute: VectorComponentValue | null,
    modifiedAttribute: VectorComponentValue | null,
    newAttribute: VectorComponentValue | null,
    isNewAttributeModified: boolean
): { oldSeverity: number; newSeverity: number } {
    const isModifiedAttributeSet = modifiedAttribute?.name === 'NOT_DEFINED' || modifiedAttribute?.name === 'NULL';
    const oldAttribute = isModifiedAttributeSet && isNewAttributeModified ? modifiedAttribute : unmodifiedAttribute;

    /*const order = {
        oldSeverity: determineAttributeSeverityOrder(self, oldAttribute),
        newSeverity: determineAttributeSeverityOrder(self, newAttribute)
    };
    console.log(" ", order, oldAttribute?.shortName, newAttribute?.shortName)
    return order;*/

    return {
        oldSeverity: determineAttributeSeverityOrder(self, oldAttribute),
        newSeverity: determineAttributeSeverityOrder(self, newAttribute)
    };
}

function determineAttributeSeverityOrder(self: CvssVector<any>, attribute: VectorComponentValue | null): number {
    if (!attribute) return -1;

    let severityOrderList: VectorComponentValue[][] = [];
    if (self instanceof Cvss2) {
        severityOrderList = Cvss2Components.ATTRIBUTE_SEVERITY_ORDER;
    } else if (self instanceof Cvss3P0) {
        severityOrderList = Cvss3P0Components.ATTRIBUTE_SEVERITY_ORDER;
    } else if (self instanceof Cvss3P1) {
        severityOrderList = Cvss3P1Components.ATTRIBUTE_SEVERITY_ORDER;
    } else if (self instanceof Cvss4P0) {
        severityOrderList = Cvss4P0Components.ATTRIBUTE_SEVERITY_ORDER;
    }

    if (severityOrderList.length === 0) {
        console.warn("Unknown", self.getVectorName(), "severity order list for attribute type:", attribute);
        return -1;
    }

    // iterate over all severity orders to find the one that contains the attribute
    for (let i = 0; i < severityOrderList.length; i++) {
        const severityOrder: VectorComponentValue[] = severityOrderList[i];
        if (severityOrder.includes(attribute)) {
            return i;
        }
    }

    console.warn("Unknown", self.getVectorName(), "attribute type:", attribute);
    return -1;
}

export {
    fromVector,
    applyVectorPartsIfMetricsLower,
    applyVectorPartsIfMetricsHigher
}