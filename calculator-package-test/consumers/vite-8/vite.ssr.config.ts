import { defineConfig } from 'vite'

export default defineConfig({
  build: {
    outDir: 'dist/server',
    ssr: './src/ssr-check.ts',
  },
})
