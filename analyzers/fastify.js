'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /fastify\.route\s*\(\s*\{(?![^}]*schema)/g,              severity: 'HIGH',     desc: 'Route sem schema JSON — input não validado automaticamente pelo Fastify' },
    { regex: /reply\.raw\.(write|end)\s*\(/g,                          severity: 'MEDIUM',   desc: 'reply.raw usado — bypassa serialização e hooks do Fastify' },
    { regex: /fastify\.decorateRequest[^)]+password|token|secret/gi,   severity: 'MEDIUM',   desc: 'Decorador de request com dado sensível — verifique escopo' },
    { regex: /cors\s*\(\s*\{\s*origin\s*:\s*['"]\*['"]/g,             severity: 'HIGH',     desc: 'CORS com origin: "*" — aceita qualquer origem' },
    { regex: /fastify\.register\s*\(\s*require\s*\(['"]\@fastify\/cors['"]\s*\)\s*\)(?!\s*,\s*\{)/g, severity: 'MEDIUM', desc: 'fastify/cors registrado sem opções — verifique origin e methods' },
  ],
  performance: [
    { regex: /schema\s*:\s*\{[^}]*response\s*:\s*\{(?![^}]*200)/g,   severity: 'LOW',      desc: 'Schema de response sem código 200 definido — serialização automática não ativa' },
    { regex: /fastify\.addHook\s*\(\s*['"]onSend['"]/g,               severity: 'INFO',     desc: 'Hook onSend — verifique se transformação de payload é necessária ou pode ser evitada' },
    { regex: /await\s+fastify\.inject\s*\(/g,                          severity: 'INFO',     desc: 'fastify.inject() em código não-teste — use apenas em testes de integração' },
  ],
  flow: [
    { regex: /fastify\.setErrorHandler\s*\([^)]*\{[^}]*\}\s*\)(?!\s*;?\s*\/)/g, severity: 'INFO', desc: 'Error handler customizado — verifique se não expõe stack trace em produção' },
    { regex: /request\.log\.(?:info|debug)\s*\([^)]*(?:password|token|secret)/gi, severity: 'HIGH', desc: 'Log com dado sensível em request do Fastify' },
    { regex: /preHandler\s*:\s*\[(?![^\]]*authenticate|[^\]]*verifyJWT|[^\]]*auth)/g, severity: 'MEDIUM', desc: 'preHandler sem middleware de autenticação visível — verifique proteção da rota' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                            severity: 'LOW',      desc: 'Débito técnico marcado' },
  ],
};

function analyzeFile(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const lines = src.split('\n');
  const findings = [];

  for (const [label, patterns] of Object.entries(PATTERNS)) {
    for (const { regex, severity, desc } of patterns) {
      lines.forEach((line, i) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ severity, label: `Fastify/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return issues;
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return issues; }
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  if (!deps['@fastify/helmet'])
    issues.push({ severity: 'HIGH', label: 'Fastify/Config', description: '@fastify/helmet não instalado — headers de segurança (CSP, HSTS, X-Frame-Options) ausentes.', file: pkgPath });
  if (!deps['@fastify/rate-limit'])
    issues.push({ severity: 'MEDIUM', label: 'Fastify/Config', description: '@fastify/rate-limit não instalado — endpoints sem proteção contra brute force.', file: pkgPath });
  if (!deps['@fastify/jwt'] && !deps['fastify-jwt'] && !deps['@fastify/auth'])
    issues.push({ severity: 'INFO', label: 'Fastify/Config', description: 'Nenhum plugin de autenticação JWT/auth do Fastify detectado — verifique como auth está implementada.', file: pkgPath });

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
