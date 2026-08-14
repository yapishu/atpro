import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base:'/apps/atpro/',
  plugins:[react()],
  build:{outDir:'../desk/web',emptyOutDir:true,assetsDir:'',rollupOptions:{output:{entryFileNames:'app.js',chunkFileNames:'chunk-[name].js',assetFileNames:'app.[ext]'}}},
  server:{proxy:{'/apps/atpro':{target:'http://localhost',changeOrigin:true},'/xrpc':{target:'http://localhost',changeOrigin:true}}},
});
