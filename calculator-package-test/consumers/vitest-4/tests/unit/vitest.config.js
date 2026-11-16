import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')

export default defineConfig({
  root: projectRoot,
  plugins: [vue()],
  test: {
    globals: true,
    environment: 'jsdom',
    fileParallelism: false,
    include: ['./tests/unit/**/*.test.js'],
  },
  resolve: {
    extensions: ['.mjs', '.js', '.ts', '.json', '.vue'],
    alias: {
      '@': path.resolve(projectRoot, './src'),
    },
  },
})
