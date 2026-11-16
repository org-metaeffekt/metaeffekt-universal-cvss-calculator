import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    outDir: 'dist',
    lib: {
      entry: './src/main.ts',
      formats: ['es'],
      fileName: 'cvss-check',
    },
  },
});
