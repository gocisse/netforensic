import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import type { Plugin } from 'vite'

// Vite empties dist/ on every build, which would delete the placeholder that
// keeps the Go package that embeds dist/ compiling on a fresh clone.
function keepDistPlaceholder(): Plugin {
  return {
    name: 'keep-dist-placeholder',
    apply: 'build',
    closeBundle() {
      writeFileSync(fileURLToPath(new URL('./dist/.gitkeep', import.meta.url)), '')
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), keepDistPlaceholder()],
  server: {
    // `npm run dev` talks to a running `netforensic --web :8181`
    proxy: { '/api': 'http://localhost:8181' },
  },
})
