# Package tests

## Known consumers

### Setup

Last checked 16.11.2026.

| Project                    | Package dir                          | `type`   | Build and runtime                      | TS `module` / `moduleResolution` | Version range |
|----------------------------|--------------------------------------|----------|----------------------------------------|----------------------------------|---------------|
| Renovate                   | `/`                                  | module   | tsdown, runs on Node                   | nodenext / nodenext              | `1.0.13`      |
| StackRadar                 | `server`                             | module   | tsc, runs on Node                      | NodeNext / NodeNext              | `^1.0.13`     |
| CSAF Validator Lib         | `/`                                  | module   | plain JS on Node, bundled by consumers | nodenext / nodenext              | `^1.0.13`     |
| vulnsig                    | `/`                                  | module   | tsc, published library, runs on Node   | ESNext / bundler                 | `^1.0.9`      |
| GitDepSec CLI              | `packages/cli`                       | module   | tsc, runs on Bun                       | ESNext / bundler                 | `^1.0.8`      |
| GitDepSec backend          | `backend`                            | commonjs | runs on Bun                            | commonjs / node10                | `^1.0.8`      |
| Secvisogram                | `app`                                | module   | webpack 5                              | ESNext / bundler                 | `^1.0.13`     |
| Security Reporting Toolbox | `/`                                  | module   | SvelteKit, Vite 8                      | from SvelteKit                   | `^1.0.13`     |
| OpenCTI                    | `opencti-platform/opencti-graphql`   | module   | esbuild, runs on Node                  | es2022 / bundler                 | `1.0.13`      |
| OpenCTEM                   | `web`                                | commonjs | Next 16                                | esnext / bundler                 | `1.0.13`      |
| TMI                        | `/`                                  | module   | Angular 22 (`@angular/build`)          | ES2022 / bundler                 | `^1.0.13`     |
| Ghostwriter                | `javascript`                         | module   | Vite 8, also builds a Node server      | ESNext / Bundler                 | `^1.0.4`      |
| ORT Server                 | `ui`                                 | module   | tsc + Vite 8                           | ESNext / bundler                 | `1.0.13`      |
| ORT web app reporter       | `plugins/reporters/web-app-template` | module   | Vite 8                                 | ESNext / bundler                 | `^1.0.13`     |
| CSAF Visualizer            | `/`                                  | module   | tsc + Vite 8                           | ESNext / bundler                 | `^1.0.12`     |
| Taranis NG                 | `src/gui`                            | module   | vue-tsc + Vite 8                       | ESNext / bundler                 | `^1.0.13`     |
| DTVP                       | `frontend`                           | module   | vue-tsc + Vite 8                       | from `@vue/tsconfig`             | `^1.0.13`     |
| ROR Web                    | `apps/web`                           | module   | Next 15, Jest at the root              | esnext / bundler                 | `1.0.11`      |
| AuditForge                 | `frontend`                           | module   | tsc + Vite 5                           | ESNext / bundler                 | `1.0.2`       |
| VulnScout                  | `frontend`                           | module   | tsc + Vite 7, Jest                     | ESNext / bundler                 | `^1.0.8`      |
| npm-userscript             | `/`                                  | module   | Cloudflare worker, wrangler            | none set                         | `^1.0.13`     |
| PwnDoc frontend            | `frontend`                           | module   | Quasar with webpack, Vitest            | none                             | `^1.0.9`      |
| PwnDoc backend             | `backend`                            | commonjs | plain JS on Node, Jest                 | none                             | `^1.0.9`      |
| OCTO SBOM Service          | `/`                                  | commonjs | tsc, runs on Node, Jest                | commonjs / node10                | `^1.0.13`     |
| GuardScan                  | `cli`                                | commonjs | tsc, runs on Node, Jest                | commonjs / node                  | `1.0.13`      |
| Verdaccio Security Filter  | `/`                                  | commonjs | plain JS on Node                       | none                             | `^1.0.13`     |
| Proteus                    | `/`                                  | commonjs | tsc, runs on Node                      | CommonJS / Node                  | `1.0.13`      |

### Imports

| Project                    | Import                                                                                                                                                  |
|----------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Renovate                   | `import aeCvss from`, plus `import type { CvssVector } from`                                                                                            |
| StackRadar                 | `import CvssCalculator from`                                                                                                                            |
| CSAF Validator Lib         | `import aeCvss from`                                                                                                                                    |
| Secvisogram                | `import aeCvss from`                                                                                                                                    |
| vulnsig                    | `import aeCvss from`                                                                                                                                    |
| GitDepSec CLI              | `import cvssCalculator from`                                                                                                                            |
| Security Reporting Toolbox | `import * as calculator from`, falls back to `.default`                                                                                                 |
| Ghostwriter                | named, plus types from `ae-cvss-calculator/dist/types/src/CvssVector` and `.../cvss4p0/Cvss4P0`                                                         |
| ORT Server                 | named, plus types from `ae-cvss-calculator/dist/types/src/CvssVector`                                                                                   |
| TMI                        | named, plus types from `ae-cvss-calculator/dist/types/src/CvssVector`                                                                                   |
| Proteus                    | `require`, and `require.resolve('ae-cvss-calculator/package.json')` in `scripts/sync-plugin-dist.mjs`, copies `dist/ae-cvss-calculator.js` by file path |
| PwnDoc backend             | `require`, `jest.doMock` in tests                                                                                                                       |
| Verdaccio Security Filter  | `require`                                                                                                                                               |
| DTVP                       | named, plus `require` in three `.cjs` scripts                                                                                                           |
| VulnScout                  | named, `jest.mock` and `require` in tests                                                                                                               |
| PwnDoc frontend            | named, `vi.mock` in tests                                                                                                                               |
| all others                 | named                                                                                                                                                   |

### Groups

| Group                                                   | Projects                                                                      | Breaks on                                  |
|---------------------------------------------------------|-------------------------------------------------------------------------------|--------------------------------------------|
| Default import                                          | Renovate, StackRadar, CSAF Validator Lib, Secvisogram, vulnsig, GitDepSec CLI | missing default export in the `.mjs`       |
| Type import from `dist/types` with `bundler` resolution | Ghostwriter, ORT Server, TMI                                                  | `exports` without a `./dist/types/*` entry |
| `package.json` subpath                                  | Proteus                                                                       | `exports` without a `./package.json` entry |
| Mocks in Jest or Vitest                                 | PwnDoc, VulnScout                                                             | nothing found, covered by tests            |
| Bun runtime                                             | GitDepSec                                                                     | nothing found, covered by tests            |
| Named import through a bundler                          | everything with Vite, webpack, Angular, Next, esbuild, wrangler               | expected to work                           |
| `require`                                               | PwnDoc backend, Verdaccio, Proteus, DTVP scripts                              | expected to work                           |

## How to satisfy all consumers

`npm run build` produces these files in `dist/`:

| File                     | Created by          | Used for                        |
|--------------------------|---------------------|---------------------------------|
| `ae-cvss-calculator.js`  | webpack, UMD format | `require`, bundlers, `<script>` |
| `ae-cvss-calculator.mjs` | `generate-mjs.js`   | `import` in Node and bundlers   |
| `types/src/**/*.d.ts`    | `tsc` via ts-loader | TypeScript, `require` path      |
| `types/index.d.mts`      | `generate-mjs.js`   | TypeScript, `import` path       |

`generate-mjs.js` loads the UMD bundle and writes one named export per key it finds, plus the whole object as default export.
It also writes `types/index.d.mts`, which declares the same shape for the `.mjs`.
`add-license.js` then puts the license header on the `.js` and the `.mjs`.

`package.json` points to them like this:

| Field                          | Value                                | Needed for                                                                |
|--------------------------------|--------------------------------------|---------------------------------------------------------------------------|
| `main`                         | `dist/ae-cvss-calculator.js`         | tools that do not read `exports`                                          |
| `types`                        | `dist/types/src/index.d.ts`          | TypeScript with `node10` resolution                                       |
| `exports["."].import.types`    | `./dist/types/index.d.mts`           | TypeScript with `node16`, `nodenext` or `bundler`, importing as ES module |
| `exports["."].import.default`  | `./dist/ae-cvss-calculator.mjs`      | `import` in Node and bundlers                                             |
| `exports["."].require.types`   | `./dist/types/src/index.d.ts`        | TypeScript with `node16` or `nodenext`, importing as CommonJS             |
| `exports["."].require.default` | `./dist/ae-cvss-calculator.js`       | `require`                                                                 |
| `exports["./package.json"]`    | `./package.json`                     | `require.resolve('ae-cvss-calculator/package.json')`                      |
| `exports["./dist/types/*"]`    | `{ "types": "./dist/types/*.d.ts" }` | type imports from `ae-cvss-calculator/dist/types/...` without extension   |
| `exports["./dist/*"]`          | `./dist/*`                           | any other file in `dist`, as before `exports` existed                     |

TypeScript does not add `.d.ts` to a path that comes out of `exports`, so `./dist/*` alone is not enough for the type imports.
Node and TypeScript pick the subpath entry with the longest matching prefix, so the order of the subpath entries does not matter.
Inside `import` and `require` the order does matter, `types` has to come before `default`.
With only one `.d.ts` for both paths, TypeScript reads the `import` path as CommonJS, which "Are the Types Wrong?" reports as "Masquerading as CJS".

## Test folders

| Folder                         | Checks                                                                                                   | Projects                                                                                     |
|--------------------------------|----------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------|
| `commonjs/`                    | `require`, score calculation, `dist/types` present                                                       |                                                                                              |
| `esm/`                         | named exports through `import()`, static `import { ... }`                                                |                                                                                              |
| `consumers/node-esm-nodenext/` | default import with `tsc` and nodenext, `checkJs` with JSDoc type imports, run on Node                   | StackRadar, CSAF Validator Lib                                                               |
| `consumers/typescript-7/`      | default import and `import type` with nodenext, run with type stripping, named import with bundler       | Renovate, ORT web app reporter                                                               |
| `consumers/node-esm-bundler/`  | default import with two kinds of casts, named import, `tsc` with bundler, esbuild, run on Node and Bun   | vulnsig, GitDepSec CLI, OpenCTI                                                              |
| `consumers/node-cjs/`          | `require`, `tsc` with commonjs and node10, `require.resolve` of `package.json`, copying the bundle, Bun  | GuardScan, OCTO SBOM Service, GitDepSec backend, Proteus, Verdaccio Security Filter, DTVP    |
| `consumers/cloudflare-worker/` | wrangler bundle, TypeScript 7                                                                            | npm-userscript                                                                               |
| `consumers/vite-8/`            | named, namespace and `dist/types` imports, Vue components, `vue-tsc`, client and SSR build               | CSAF Visualizer, Ghostwriter, ORT Server, Security Reporting Toolbox, DTVP, Taranis NG       |
| `consumers/vite-5/`            | named import, TypeScript 5.5 project references                                                          | AuditForge                                                                                   |
| `consumers/webpack-5/`         | babel-loader with the default import, vue-loader with a named import                                     | Secvisogram, PwnDoc frontend                                                                 |
| `consumers/jest-29/`           | ts-jest, babel-jest, jsdom, `jest.mock`, swapping a mocked class through `require`, Vite 7 build         | VulnScout                                                                                    |
| `consumers/jest-30/`           | `jest.doMock` in plain JavaScript, ts-jest, run again with `--experimental-vm-modules`                   | PwnDoc backend, GuardScan, OCTO SBOM Service                                                 |
| `consumers/vitest-4/`          | Vue component tests with jsdom, `vi.mock` and the real package                                           | PwnDoc frontend                                                                              |
| `consumers/next-15/`           | Next with webpack, client component                                                                      | ROR Web                                                                                      |
| `consumers/next-16/`           | Next with turbopack, server and client component                                                         | OpenCTEM                                                                                     |
| `consumers/angular-22/`        | Angular application builder, `dist/types` imports                                                        | TMI                                                                                          |

Each folder runs its checks one after the other in `npm test`, the first failing step ends the run.
`run-tests.sh <version|tarball> [folder...]` installs the given package into each folder and runs `npm test`.
`publish-package.sh` calls it with the packed tarball.
