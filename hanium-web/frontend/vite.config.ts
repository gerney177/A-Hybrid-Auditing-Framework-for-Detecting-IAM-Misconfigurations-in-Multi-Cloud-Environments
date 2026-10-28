import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

// 개발 중에는 /api 요청을 FastAPI(8010)로 넘긴다. 다른 주소를 쓰려면 API_TARGET 으로 지정.
const apiTarget = process.env.API_TARGET ?? 'http://127.0.0.1:8010'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  server: { port: 5173, proxy: { '/api': apiTarget } },
  build: { chunkSizeWarningLimit: 900 },
})
