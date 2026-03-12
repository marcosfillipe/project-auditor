'use strict';
const fs = require('fs');
const path = require('path');

// ─── Padrões Vue.js ───────────────────────────────────────────────────────────

const PATTERNS = {
  security: [
    { regex: /v-html\s*=\s*["'`]/g,                           severity: 'HIGH',   desc: 'v-html com variável — risco de XSS (equivalente a innerHTML)' },
    { regex: /\$el\.innerHTML\s*=/g,                           severity: 'HIGH',   desc: 'Manipulação direta de innerHTML via $el' },
    { regex: /eval\s*\(/g,                                     severity: 'CRITICAL',desc: 'eval() detectado' },
    { regex: /localStorage\.(setItem|getItem)\s*\(.*(?:token|password|secret)/gi, severity: 'HIGH', desc: 'Dado sensível em localStorage — use httpOnly cookie' },
    { regex: /axios\.defaults\.headers\.common\[.Authorization.\]/g, severity: 'MEDIUM', desc: 'Token JWT em header global do axios — verifique exposição' },
  ],
  performance: [
    { regex: /watch\s*:\s*\{[^}]*deep\s*:\s*true/g,           severity: 'MEDIUM', desc: 'watch deep:true — pode gerar re-renders excessivos em objetos grandes' },
    { regex: /\$forceUpdate\s*\(\s*\)/g,                       severity: 'MEDIUM', desc: '$forceUpdate() — indica problema de reatividade, revise a lógica' },
    { regex: /created\s*\(\s*\)[^{]*\{[^}]*fetch|axios/g,     severity: 'LOW',    desc: 'Fetch em created() — prefira onMounted ou Suspense para UX melhor' },
    { regex: /v-for(?!.*:key)/g,                               severity: 'HIGH',   desc: 'v-for sem :key definido — causa problemas de reconciliação no DOM' },
    { regex: /import\s+\*\s+as\s+\w+\s+from/g,               severity: 'LOW',    desc: 'Wildcard import — impede tree-shaking' },
  ],
  flow: [
    { regex: /this\.\$store\.state\.\w+\.\w+/g,               severity: 'LOW',    desc: 'Acesso direto ao state do Vuex — use getters para desacoplar' },
    { regex: /this\.\$store\.commit\s*\(/g,                    severity: 'LOW',    desc: 'commit() direto do componente — prefira actions para lógica assíncrona' },
    { regex: /beforeDestroy\s*\(\s*\)(?![^}]*clearInterval|[^}]*removeEventListener)/g, severity: 'MEDIUM', desc: 'beforeDestroy sem limpeza de timers/listeners — memory leak em potencial' },
    { regex: /mounted\s*\(\s*\)\s*\{[^}]*addEventListener/g,  severity: 'MEDIUM', desc: 'addEventListener em mounted sem remoção em beforeDestroy' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME|\/\/\s*HACK/gi,        severity: 'LOW',    desc: 'Comentário de débito técnico' },
  ],
};

function analyzeFile(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const lines = src.split('\n');
  const findings = [];
  const rel = filePath;

  for (const [label, patterns] of Object.entries(PATTERNS)) {
    for (const { regex, severity, desc } of patterns) {
      lines.forEach((line, i) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ severity, label: `Vue/${label}`, description: desc, file: rel, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

// Checagens a nível de projeto Vue
function analyzeProject(projectRoot) {
  const issues = [];
  const pkgPath = path.join(projectRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) return issues;

  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); } catch { return issues; }
  const deps = { ...pkg.dependencies, ...pkg.devDependencies };

  if (!deps['vue-router'] && !deps['@nuxtjs/router'])
    issues.push({ severity: 'LOW', label: 'Vue/Config', description: 'vue-router não detectado — verifique se a navegação está protegida por guards de autenticação.', file: pkgPath });

  if (!deps['pinia'] && !deps['vuex'])
    issues.push({ severity: 'INFO', label: 'Vue/Config', description: 'Nenhum gerenciador de estado (Pinia/Vuex) detectado — OK para apps simples.', file: pkgPath });

  if (deps['vue'] && !deps['@vue/test-utils'])
    issues.push({ severity: 'LOW', label: 'Vue/Config', description: '@vue/test-utils não encontrado — testes de componente podem estar ausentes.', file: pkgPath });

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
