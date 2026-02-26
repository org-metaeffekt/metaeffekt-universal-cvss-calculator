<div align="center">
	<h1>{metæffekt} CVSS Calculator</h1>
    <a href="https://www.npmjs.com/package/ae-cvss-calculator"><img src="https://img.shields.io/npm/dm/ae-cvss-calculator?style=for-the-badge&label=npm%20downloads" alt="Weekly NPM downloads"></a>
	<img src="https://img.shields.io/github/license/org-metaeffekt/metaeffekt-universal-cvss-calculator?style=for-the-badge" alt="License Apache-2">
</div>

<br>

The {metæffekt} CVSS Calculator supports all versions of the CVSS standard by FIRST to model CVSS vectors and calculate
their scores.
It consists of the following components:

<table>
  <tr>
    <td align="center">
      <b>TypeScript Library</b>
    </td>
    <td align="center">
      <b>UI</b>
    </td>
  </tr>
  <tr>
    <td>
      Supports CVSS versions 2.0, 3.0, 3.1 and 4.0.
      Available on NPM as <a target="_blank" href="https://www.npmjs.com/package/ae-cvss-calculator">ae-cvss-calculator</a> and installable via:
      <pre>npm install ae-cvss-calculator</pre>
    </td>
    <td>
      <p>
        The calculator is available on <a target="_blank" href="https://www.metaeffekt.com/security/cvss/calculator/index.html?vector=%5B%5B%22CVSS%3A4.0%22%2Ctrue%2C%22CVSS%3A4.0%2FAV%3AP%2FAC%3AL%2FAT%3AN%2FPR%3AN%2FUI%3AN%2FVC%3AH%2FVI%3AL%2FVA%3AL%2FSC%3AH%2FSI%3AH%2FSA%3AH%22%2C%22CVSS%3A4.0%22%5D%2C%5B%223.1+2020-5934+%28nist.gov%29%22%2Ctrue%2C%22CVSS%3A3.1%2FAV%3AN%2FAC%3AL%2FPR%3AL%2FUI%3AN%2FS%3AC%2FC%3AH%2FI%3AL%2FA%3AH%2FE%3AF%2FRL%3AU%2FRC%3AR%22%2C%22CVSS%3A3.1%22%5D%2C%5B%222.0+2020-5934+%28nist.gov%29%22%2Ctrue%2C%22AV%3AL%2FAC%3AH%2FAu%3AS%2FC%3AC%2FI%3AP%2FA%3AN%2FE%3AU%2FRL%3AU%2FRC%3AC%2FCDP%3ALM%2FTD%3AM%2FCR%3AH%2FIR%3AH%2FAR%3AH%22%2C%22CVSS%3A2.0%22%5D%5D&open=temporal&selected=3.1+2020-5934+%28nist.gov%29">our webpage</a> for you to try out and link from your applications.
        The source code can be found in the <a href="https://github.com/org-metaeffekt/metaeffekt-universal-cvss-calculator/tree/master/site">site</a> directory.
      </p>
    </td>
  </tr>
</table>

## Installation

This project implements the following versions of the CVSS standard by FIRST:

- [CVSS:2.0 - https://www.first.org/cvss/v2/guide](https://www.first.org/cvss/v2/guide)
- [CVSS:3.0 - https://www.first.org/cvss/v3.0/specification-document](https://www.first.org/cvss/v3.0/specification-document)
- [CVSS:3.1 - https://www.first.org/cvss/v3.1/specification-document](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS:4.0 - https://www.first.org/cvss/v4.0/specification-document](https://www.first.org/cvss/v4.0/specification-document)

Available on NPM as [ae-cvss-calculator](https://www.npmjs.com/package/ae-cvss-calculator) and installable via:

```bash
npm install ae-cvss-calculator
```

## Usage

The library exports classes for CVSS versions 2.0 (`Cvss2`), 3.0 (`Cvss3P0`), 3.1 (`Cvss3P1`), and 4.0 (`Cvss4P0`), along with utility functions for parsing.

![Depenndency Graph of all Classes and Interfaces in the CVSS Calculator Library](dependency-graph.png)

### Basic Usage (Specific Version)

If you know the specific CVSS version of your vector, you can instantiate the corresponding class directly.

```typescript
// Initialize with a vector string
const cvss = new Cvss3P1('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L');

// Calculate scores
const scores = cvss.calculateScores();
console.log(`Base Score: ${scores.base}`);
console.log(`Vector: ${scores.vector}`);

// Normalize scores to 0-10 scale (useful for visualization)
const normalized = cvss.calculateScores(true);
console.log(`Exploitability: ${normalized.exploitability}`);
```

Depending on the vector version, different scores are exposed via the returned object.

### Generic Vector Parsing

Use `fromVector` to automatically detect the CVSS version and parse the string into the appropriate object instance.

```typescript
const vectorString = 'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L';
const cvss = fromVector(vectorString);

if (cvss) {
  console.log(`Detected: ${cvss.getVectorName()}`); // CVSS:3.1
  console.log(`Score: ${cvss.calculateScores().overall}`);
} else {
  console.error('Invalid or unsupported CVSS vector');
}
```

### Modifying Components

You can modify vector components programmatically using `applyComponentString`.

```typescript
const cvss = new Cvss4P0('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N');

cvss.applyComponentString('AV', 'P');
cvss.applyComponent(Cvss4P0Components.AC, Cvss4P0Components.AC_VALUES.H);
```

## Build

```bash
git clone https://github.com/org-metaeffekt/metaeffekt-universal-cvss-calculator
cd metaeffekt-universal-cvss-calculator/ae-cvss-calculator
npm install
npm run build
```

The minified `ae-cvss-calculator.js` can be found in the `dist` directory.

Otherwise, you can also build the packaged version by running

```bash
npm run pack
```

To publish a new version:

1. Make sure that you pushed all the code related to the release, including the version bump to git, as npm will fetch
   that state for the release.
2. Ensure that you removed all target folders (`dist`) and bundles (`ae-cvss-calculator-1.0.9.tgz`).
3. Run the following commands:

```bash
npm login
npm run pack
npm publish
```

4. Update the dependency in Artifact Analysis in the VAD.
