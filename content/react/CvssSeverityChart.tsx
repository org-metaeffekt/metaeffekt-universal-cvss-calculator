/*
 * Copyright 2021-2024 the original author or authors.
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
import { Legend, PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, ResponsiveContainer } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@shadcn/components/ui/chart"
import type { CvssVector } from "ae-cvss-calculator"
import React from "react";

interface CvssSeverityChartProps {
    vectors: (CvssVector<any> | undefined | null)[];
    colorFunction: (vector: CvssVector<any>, version: string) => string;
}

const labels = {
    base: "Base",
    adjustedImpact: "Adj.",
    impact: "Imp.",
    temporal: "Temp.",
    exploitability: "Expl.",
    environmental: "Env.",
}

const labelMapping: Record<string, string> = {
    Base: "Base Score",
    "Adj.": "Adjusted Impact",
    "Imp.": "Impact",
    "Temp.": "Temporal",
    "Expl.": "Exploitability",
    "Env.": "Environmental",
};

export function CvssSeverityChart({ vectors, colorFunction }: CvssSeverityChartProps) {
    // no undefined or null vectors
    const validVectors = vectors.filter((v): v is CvssVector<any> => v !== undefined && v !== null)

    if (validVectors.length === 0) {
        return <div className="text-center p-4">No CVSS vectors to display</div>
    }

    const metricsMap: Record<string, number[]> = {};
    // @ts-ignore
    Object.keys(labels).forEach(key => metricsMap[labels[key]] = []);

    const vectorNames: string[] = []
    const vectorColors: string[] = []
    const hasValue: boolean[][] = []

    validVectors.forEach((vectorData) => {
        const vectorName = vectorData.getVectorName();
        vectorNames.push(vectorName);

        const color = colorFunction(vectorData, vectorName);
        vectorColors.push(color);

        const scores = vectorData.calculateScores(true)
        const overallScore = scores.overall ?? scores.base ?? 0;
        const baseScore = scores.base ?? scores.overall ?? 0;

        metricsMap[labels.base].push(baseScore);
        metricsMap[labels.impact].push(scores.impact ?? overallScore);
        metricsMap[labels.exploitability].push(scores.exploitability ?? overallScore);
        metricsMap[labels.temporal].push(scores.temporal ?? scores.threat ?? baseScore);
        metricsMap[labels.environmental].push(scores.environmental ?? overallScore);
        metricsMap[labels.adjustedImpact].push(scores.modifiedImpact ?? scores.impact ?? overallScore);

        const hasValuesArray: boolean[] = [];
        hasValue.push(hasValuesArray);

        hasValuesArray.push(isDefined(scores.base));
        hasValuesArray.push(isDefined(scores.modifiedImpact));
        hasValuesArray.push(isDefined(scores.impact));
        hasValuesArray.push(isDefined(scores.temporal) || isDefined(scores.threat));
        hasValuesArray.push(isDefined(scores.exploitability));
        hasValuesArray.push(isDefined(scores.environmental));
    });

    const chartData = Object.keys(metricsMap).map((metric) => {
        const dataPoint: Record<string, any> = { metric };

        validVectors.forEach((_, index) => {
            const vectorName = vectorNames[index];
            dataPoint[vectorName] = metricsMap[metric][index] ?? 0;
        });

        return dataPoint;
    })

    const chartConfig: Record<string, { label: string; color: string }> = {}
    vectorNames.forEach((name, index) => {
        chartConfig[name] = {
            label: name,
            color: vectorColors[index],
        }
    });

    return (
        <div className="w-full">
            <ChartContainer config={chartConfig} className="mx-auto aspect-square max-h-[350px]">
                <ResponsiveContainer width="100%" height="100%">
                    <RadarChart data={chartData}>
                        <PolarGrid/>
                        <PolarAngleAxis dataKey="metric"/>
                        <PolarRadiusAxis style={{ visibility: "hidden" }} angle={60} tickCount={6} domain={[0, 10]}/>
                        <ChartTooltip content={<ChartTooltipContent indicator="line"
                                                                    labelFormatter={(label: any) => labelMapping[label] || label}/>}/>

                        {vectorNames.map((name, index) => (
                            <Radar
                                key={name + "-" + index}
                                name={name}
                                dataKey={name}
                                stroke={vectorColors[index]}
                                fill={vectorColors[index]}
                                fillOpacity={0.1}
                                strokeWidth={2}
                                animationDuration={0}
                                dot={(props) => {
                                    const { dataKey, cx, cy, payload } = props;
                                    const index = vectorNames.indexOf(dataKey as string);
                                    const metricIndex = Object.keys(labels).indexOf(
                                        Object.entries(labels).find(([, v]) => v === payload.name)?.[0] ?? ""
                                    );
                                    const showDot = hasValue[index]?.[metricIndex] ?? false;

                                    if (!showDot) return <g/>;

                                    return React.createElement("circle", {
                                        cx,
                                        cy,
                                        r: 3.5,
                                        fill: vectorColors[index],
                                        stroke: "#fff",
                                        strokeWidth: 1,
                                    });
                                }}
                            />
                        ))}

                        <Legend layout="horizontal" verticalAlign="bottom" height={20}/>
                    </RadarChart>
                </ResponsiveContainer>
            </ChartContainer>
        </div>
    )
}

export function isDefined(value: any): boolean {
    return value !== undefined && value !== null;
}
