import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// In Docker, API_URL is set to http://backend:3000 via docker-compose.
// Locally it falls back to localhost:3000.
const API_URL = process.env.API_URL ?? 'http://localhost:3000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': API_URL,
      '/config': API_URL,
    },
  },
  build: {
    outDir: '../public-react',
    emptyOutDir: true,
  },
})
