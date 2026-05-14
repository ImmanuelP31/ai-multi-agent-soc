import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // REST calls: /alerts, /alerts/stats etc → backend:8000
      '/alerts': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      // WebSocket: /ws/live-alerts → backend:8000
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})