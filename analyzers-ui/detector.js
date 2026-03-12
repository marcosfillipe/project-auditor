'use strict';

const http  = require('http');
const https = require('https');
const path  = require('path');
const fs    = require('fs');

// ─── Portas candidatas por tipo ───────────────────────────────────────────────

const FRONTEND_PORTS = [3000, 3001, 4000, 4200, 5173, 8080, 8081];
const BACKEND_PORTS  = [3000, 3001, 4000, 4001, 5000, 8000, 8080, 8888];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function probe(url, timeoutMs = 2500) {
  return new Promise(resolve => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, res => {
      resolve({ ok: true, status: res.statusCode, headers: res.headers });
      res.resume();
    });
    req.on('error',   () => resolve({ ok: false }));
    req.on('timeout', () => { req.destroy(); resolve({ ok: false }); });
  });
}

async function findPort(ports, label) {
  for (const port of ports) {
    const result = await probe(`http://localhost:${port}`);
    if (result.ok) return { port, ...result };
  }
  return null;
}

// ─── Detecta tipo de projeto pela estrutura de arquivos ──────────────────────

function detectProjectType(projectRoot) {
  const has = f => fs.existsSync(path.join(projectRoot, f));

  const hasFrontend = has('src/App.jsx') || has('src/App.tsx') || has('src/App.js')
    || has('index.html') || has('public/index.html') || has('vite.config.js')
    || has('vite.config.ts') || has('next.config.js') || has('angular.json');

  const hasBackend = has('src/app.js') || has('src/server.js') || has('app.js')
    || has('server.js') || has('src/index.js');

  const hasFrontDir  = fs.existsSync(path.join(projectRoot, 'frontend'));
  const hasBackDir   = fs.existsSync(path.join(projectRoot, 'backend'));
  const hasClientDir = fs.existsSync(path.join(projectRoot, 'client'));
  const hasServerDir = fs.existsSync(path.join(projectRoot, 'server'));

  // Monorepo com subpastas explícitas
  if (hasFrontDir && hasBackDir)   return 'fullstack-monorepo';
  if (hasClientDir && hasServerDir) return 'fullstack-monorepo';
  if (hasFrontDir && !hasBackDir)  return 'frontend-only';
  if (hasBackDir  && !hasFrontDir) return 'backend-only';
  if (hasFrontend && hasBackend)   return 'fullstack-single';
  if (hasFrontend)                 return 'frontend-only';
  if (hasBackend)                  return 'backend-only';
  return 'unknown';
}

// ─── Detecta comando de start do package.json ────────────────────────────────

function detectStartCommand(dir) {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'));
    const scripts = pkg.scripts || {};

    if (scripts.dev)   return { cmd: 'npm run dev',   script: 'dev' };
    if (scripts.start) return { cmd: 'npm start',     script: 'start' };
    if (scripts.serve) return { cmd: 'npm run serve', script: 'serve' };

    // Detecta vite, next, react-scripts diretamente nas deps
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps['vite'])          return { cmd: 'npx vite', script: null };
    if (deps['next'])          return { cmd: 'npx next dev', script: null };
    if (deps['react-scripts']) return { cmd: 'npx react-scripts start', script: null };

    return null;
  } catch {
    return null;
  }
}

// ─── Detecta sub-diretórios de front e back em monorepo ──────────────────────

function detectMonorepoDirs(projectRoot) {
  const candidates = [
    { front: 'frontend', back: 'backend' },
    { front: 'client',   back: 'server'  },
    { front: 'web',      back: 'api'     },
    { front: 'app',      back: 'api'     },
  ];

  for (const { front, back } of candidates) {
    const frontPath = path.join(projectRoot, front);
    const backPath  = path.join(projectRoot, back);
    if (fs.existsSync(frontPath) && fs.existsSync(backPath)) {
      return { frontDir: frontPath, backDir: backPath };
    }
  }
  return { frontDir: projectRoot, backDir: projectRoot };
}

// ─── Função principal de detecção ────────────────────────────────────────────

async function detect(projectRoot) {
  console.log('🔎 Detectando tipo de projeto...');
  const type = detectProjectType(projectRoot);
  console.log(`   Tipo identificado: ${type}\n`);

  const result = {
    projectType: type,
    frontend: null,
    backend:  null,
    canRunUI: false,
    issues:   [],
  };

  const { frontDir, backDir } = detectMonorepoDirs(projectRoot);

  // ── Verifica se servidores já estão rodando ──
  console.log('🌐 Verificando servidores ativos...');

  const isFrontendType = ['frontend-only', 'fullstack-single', 'fullstack-monorepo'].includes(type);
  const isBackendType  = ['backend-only',  'fullstack-single', 'fullstack-monorepo'].includes(type);

  if (isFrontendType) {
    const running = await findPort(FRONTEND_PORTS, 'frontend');
    if (running) {
      console.log(`   ✅ Frontend detectado em http://localhost:${running.port}`);
      result.frontend = { url: `http://localhost:${running.port}`, port: running.port, status: running.status };
    } else {
      console.log(`   ⚠️  Frontend NÃO está rodando`);
      const startCmd = detectStartCommand(frontDir);
      result.issues.push({
        type: 'frontend-offline',
        message: `Frontend não encontrado em nenhuma das portas: ${FRONTEND_PORTS.join(', ')}`,
        suggestion: startCmd
          ? `Execute "${startCmd.cmd}" na pasta ${path.basename(frontDir)}/ e rode check:ui novamente`
          : `Suba o servidor frontend manualmente e rode check:ui novamente`,
        dir: frontDir,
      });
    }
  }

  if (isBackendType) {
    const running = await findPort(BACKEND_PORTS, 'backend');
    if (running) {
      // Distingue front de back: backend normalmente retorna JSON ou 404/401, não HTML
      const isLikelyBackend = running.status === 404
        || running.status === 401
        || (running.headers['content-type'] || '').includes('application/json');

      const isLikelyFrontend = (running.headers['content-type'] || '').includes('text/html');

      // Se já temos frontend na mesma porta, não conta como backend separado
      const sameAsFront = result.frontend && result.frontend.port === running.port;

      if (!sameAsFront) {
        console.log(`   ✅ Backend detectado em http://localhost:${running.port} (HTTP ${running.status})`);
        result.backend = { url: `http://localhost:${running.port}`, port: running.port, status: running.status };
      } else if (isBackendType && !result.backend) {
        // Tenta próxima porta disponível para backend
        const backendResult = await findPort(BACKEND_PORTS.filter(p => p !== result.frontend?.port), 'backend');
        if (backendResult) {
          console.log(`   ✅ Backend detectado em http://localhost:${backendResult.port}`);
          result.backend = { url: `http://localhost:${backendResult.port}`, port: backendResult.port };
        }
      }
    }

    if (!result.backend && isBackendType) {
      console.log(`   ⚠️  Backend NÃO está rodando`);
      const startCmd = detectStartCommand(backDir);
      result.issues.push({
        type: 'backend-offline',
        message: `Backend não encontrado em nenhuma das portas: ${BACKEND_PORTS.join(', ')}`,
        suggestion: startCmd
          ? `Execute "${startCmd.cmd}" na pasta ${path.basename(backDir)}/ e rode check:ui novamente`
          : `Suba o servidor backend manualmente e rode check:ui novamente`,
        dir: backDir,
      });
    }
  }

  // ── Define se pode rodar análise UI ──
  // Para UI precisamos ao menos do frontend
  result.canRunUI = !!result.frontend;

  // Tipo backend-only: não tem UI para analisar
  if (type === 'backend-only') {
    result.canRunUI = false;
    result.issues.push({
      type: 'no-ui',
      message: 'Projeto identificado como backend-only — análise de UI não se aplica',
      suggestion: 'Use apenas "npm run check" para análise estática',
    });
  }

  console.log('');
  return result;
}

module.exports = { detect, detectProjectType, detectMonorepoDirs, probe };
