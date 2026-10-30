import react from '@vitejs/plugin-react';
import fs from 'fs';
import path from 'path';
import {defineConfig, Plugin} from 'vite';

function netcoAssetFallbackPlugin(): Plugin {
  const rootDir = import.meta.dirname;
  const publicDir = path.join(rootDir, 'public');

  const getMimeType = (filePath: string) => {
    const ext = path.extname(filePath).toLowerCase();
    switch (ext) {
      case '.webp':
        return 'image/webp';
      case '.png':
        return 'image/png';
      case '.jpg':
      case '.jpeg':
        return 'image/jpeg';
      case '.svg':
        return 'image/svg+xml';
      case '.json':
        return 'application/json; charset=utf-8';
      case '.js':
        return 'application/javascript; charset=utf-8';
      case '.mp3':
        return 'audio/mpeg';
      case '.wav':
        return 'audio/wav';
      case '.ttf':
        return 'font/ttf';
      case '.otf':
        return 'font/otf';
      default:
        return 'application/octet-stream';
    }
  };

  const middleware = async (req: any, res: any, next: any) => {
    if (!req.url || (req.method !== 'GET' && req.method !== 'HEAD')) {
      return next();
    }
    const cleanPath = decodeURIComponent(req.url.split('?')[0]);
    if (!cleanPath.startsWith('/assets/') && !cleanPath.startsWith('/js/')) {
      return next();
    }
    const localFile = path.join(publicDir, cleanPath);
    if (fs.existsSync(localFile) && fs.statSync(localFile).isFile()) {
      return next();
    }
    try {
      const upstreamUrl = `https://net-co.pages.dev${cleanPath}`;
      const response = await fetch(upstreamUrl, {
        headers: {
          'User-Agent':
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
      });
      if (!response.ok) {
        return next();
      }
      const buffer = Buffer.from(await response.arrayBuffer());
      fs.mkdirSync(path.dirname(localFile), {recursive: true});
      fs.writeFileSync(localFile, buffer);
      res.statusCode = 200;
      res.setHeader('Content-Type', getMimeType(localFile));
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      res.end(buffer);
    } catch {
      return next();
    }
  };

  return {
    name: 'netco-asset-fallback',
    configureServer(server) {
      server.middlewares.use(middleware);
    },
    configurePreviewServer(server) {
      server.middlewares.use(middleware);
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [netcoAssetFallbackPlugin(), react()],
    resolve: {
      alias: {
        '@': path.resolve(import.meta.dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
