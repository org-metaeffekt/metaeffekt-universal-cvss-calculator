import {
    CvssVector,
    Cvss2,
    Cvss3P0,
    Cvss3P1,
    Cvss4P0,
    fromVector,
    applyVectorPartsIfMetricsLower,
    applyVectorPartsIfMetricsHigher,
    Cvss2Components,
    Cvss3P0Components,
    Cvss3P1Components,
    Cvss4P0Components,
} from 'ae-cvss-calculator';

new Cvss3P1();
