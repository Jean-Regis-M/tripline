// Minimal static server for local use. The app itself is fully client side.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const WEB = fileURLToPath(new URL('../web/', import.meta.url));
const MIME: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png' };

export function createApp() {
  return createServer(async (req, res) => {
    const headers = { 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'" };
    if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405, headers); return res.end('method not allowed'); }
    try {
      const path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
      const full = normalize(join(WEB, path === '/' ? 'index.html' : path));
      if (!full.startsWith(WEB.endsWith(sep) ? WEB : WEB + sep)) { res.writeHead(403, headers); return res.end('forbidden'); }
      const data = await readFile(full);
      res.writeHead(200, { ...headers, 'content-type': MIME[extname(full)] ?? 'application/octet-stream' });
      res.end(req.method === 'HEAD' ? undefined : data);
    } catch {
      res.writeHead(404, headers); res.end('not found');
    }
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const port = Number(process.env.PORT ?? 3000);
  createApp().listen(port, () => console.log(`Tripline running at http://localhost:${port}`));
}
