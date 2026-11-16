import * as esbuild from 'esbuild';

await esbuild.build({
  entryPoints: ['src/check.ts'],
  bundle: true,
  platform: 'node',
  target: ['node22'],
  format: 'esm',
  outExtension: { '.js': '.mjs' },
  minifySyntax: true,
  keepNames: true,
  outdir: 'dist/bundle',
});
