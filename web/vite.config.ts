import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '127.0.0.1', // 仅绑定 IPv4 本地回环，防止暴露到公网
    proxy: {
      '/api': 'http://127.0.0.1:8080', // 使用 127.0.0.1 避免 IPv6 ::1 解析问题
    },
  },
})
