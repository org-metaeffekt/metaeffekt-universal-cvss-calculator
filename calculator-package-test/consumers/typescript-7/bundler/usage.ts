import { normalizedOverall, versionOf } from "./cvss";

export function describeVector(vector: string): string {
    return `${versionOf(vector) ?? "unknown"} ${normalizedOverall(vector) ?? "-"}`;
}
