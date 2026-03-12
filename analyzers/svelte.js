'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /\{@html\s+/g,                                    severity: 'HIGH',   desc: '{@html} — renderiza HTML bruto sem sanitização, risco de XSS' },
    { regex: /localStorage\.(setItem)\s*\(.*(?:token|jwt|password|secret)/gi, severity: 'HIGH', desc: 'Token/senha em localStorage — prefira httpOnly cookies' },
    { regex: /eval\s*\(/g,                                     severity: 'CRITICAL',desc: 'eval() detectado' },
    { regex: /fetch\s*\([^)]+\)(?![^;]*\.catch|[^;]*catch\s*\()/g, severity: 'MEDIUM', desc: 'fetch() sem .catch() — rejeições não tratadas' },
  ],
  performance: [
    { regex: /\$:\s*\{/g,                                      severity: 'LOW',    desc: 'Bloco reativo $: com objeto — pode causar re-execuções desnecessárias' },
    { regex: /{#each\s+\w+\s+as\s+\w+(?!\s*\()/g,            severity: 'HIGH',   desc: '{#each} sem key — Svelte não pode reutilizar elementos DOM, impacta performance' },
    { regex: /import\s+\*\s+as\s+\w+\s+from/g,               severity: 'LOW',    desc: 'Wildcard import — impede tree-shaking' },
    { regex: /onMount\s*\(\s*\(\s*\)\s*=>\s*\{[^}]*addEventListener/g, severity: 'MEDIUM', desc: 'addEventListener em onMount — verifique remoção em onDestroy' },
  ],
  flow: [
    { regex: /onDestroy\s*\(\s*\(\s*\)\s*=>\s*\{\s*\}\s*\)/g, severity: 'MEDIUM', desc: 'onDestroy com callback vazio — cleanup não realizado' },
    { regex: /writable\s*\([^)]*\)(?![^;]*subscribe|[^;]*set|[^;]*update)/g, severity: 'LOW', desc: 'Store writable criado mas uso não detectado no escopo' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                    severity: 'LOW',    desc: 'Débito técnico marcado' },
    { regex: /catch\s*\(\s*\w*\s*\)\s*\{\s*\}/g,              severity: 'HIGH',   desc: 'Catch vazio — erros silenciados' },
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
          findings.push({ severity, label: `Svelte/${label}`, description: desc, file: filePath, line: i + 1 });
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

  if (!deps['@sveltejs/kit'] && !deps['svelte-routing'])
    issues.push({ severity: 'INFO', label: 'Svelte/Config', description: 'Nenhum roteador detectado — se aplicação tem múltiplas páginas, considere SvelteKit.', file: pkgPath });

  if (deps['@sveltejs/kit']) {
    // SvelteKit: hooks.server.ts é ponto de auth centralizado
    const hooksPath = [
      path.join(projectRoot, 'src', 'hooks.server.ts'),
      path.join(projectRoot, 'src', 'hooks.server.js'),
    ].find(fs.existsSync);
    if (!hooksPath)
      issues.push({ severity: 'MEDIUM', label: 'Svelte/Config', description: 'SvelteKit sem hooks.server.ts — autenticação centralizada pode estar ausente.', file: pkgPath });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
