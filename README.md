# {metæffekt} CVSS Calculator

A TypeScript implementation of:

- [CVSS:2.0](https://www.first.org/cvss/v2/guide)
- [CVSS:3.1](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS:4.0](https://www.first.org/cvss/v4.0/specification-document)

An example UI can be found in the [site](site) directory.

## Build

```bash
cd ae-cvss-calculator
npm install
npm run build
```

The minified `ae-cvss-calculator.js` can be found in the `dist` directory.

## Usage

The different versions are implemented in the following classes:

- `Cvss2`
- `Cvss3P1`
- `Cvss4P0`

They all inherit base functionality from the `CvssVector` class.

### V4.0

```ts
const cvss4 = new Cvss4P0('CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:S/SI:S/SA:S');
cvss4.applyComponentString('MAC', 'L');
cvss4.applyComponent(Cvss4P0Components.AC, Cvss4P0Components.AC_VALUES.H);
const scores = cvss4.calculateScores();
console.log(scores);
```

outputs:

```json
{
  "overall": 5.3,
  "vector": "CVSS:4.0/AV:A/AC:H/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:S/SI:S/SA:S/MAV:X/MAC:L/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X"
}
```

### V3.1

```ts
const cvss3 = new Cvss3P1('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L');
cvss3.applyComponent(Cvss3P1.AC, Cvss3P1.AC.values[1]);
console.log(cvss3.calculateScores(false));
console.log(cvss3.calculateScores(true));
```

outputs

```json
{
  "base": 7.3,
  "impact": 3.4,
  "exploitability": 3.9,
  "temporal": null,
  "environmental": null,
  "modifiedImpact": null,
  "overall": 7.3,
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
}
```

```json
{
  "base": 7.3,
  "impact": 5.7,
  "exploitability": 10,
  "temporal": null,
  "environmental": null,
  "modifiedImpact": null,
  "overall": 7.3,
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"
}
```

## Todo

- Button to export images of the score tables, charts and vectors
