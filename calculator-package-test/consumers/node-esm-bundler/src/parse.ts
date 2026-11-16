export type Version = '2.0' | '3.0' | '3.1' | '4.0';

const PREFIXES: [string, Version][] = [
  ['CVSS:4.0/', '4.0'],
  ['CVSS:3.1/', '3.1'],
  ['CVSS:3.0/', '3.0'],
];

export function versionOf(vector: string): Version {
  return PREFIXES.find(([prefix]) => vector.startsWith(prefix))?.[1] ?? '2.0';
}

export function withoutV2Prefix(vector: string): string {
  return vector.startsWith('CVSS:2.0/') ? vector.slice('CVSS:2.0/'.length) : vector;
}
