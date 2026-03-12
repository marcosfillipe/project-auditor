#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');

// ─── Analyzers base (sempre rodam em arquivos JS/TS) ──────────────────────────
const security    = require('./analyzers/security');
const performance = require('./analyzers/performance');
const flow        = require('./analyzers/flow');

// ─── Analyzers de framework (carregados sob demanda) ─────────────────────────
const ANALYZER_MAP = {
  vue:       () => require('./analyzers/vue'),
  angular:   () => require('./analyzers/angular'),
  nextjs:    () => require('./analyzers/nextjs'),
  svelte:    () => require('./analyzers/svelte'),
  html:      () => require('./analyzers/html'),
  python:    () => require('./analyzers/python'),
  wordpress: () => require('./analyzers/wordpress'),
  laravel:   () => require('./analyzers/laravel'),
  fastify:   () => require('./analyzers/fastify'),
  nestjs:    () => require('./analyzers/nestjs'),
  prisma:    () => require('./analyzers/prisma'),
  typeorm:   () => require('./analyzers/typeorm'),
};

const reporter        = require('./reporter');
const promptGenerator = require('./prompt-generator');

// ─── Grupos de extensão ───────────────────────────────────────────────────────
const EXT_JS     = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']);
const EXT_VUE    = new Set(['.vue']);
const EXT_SVELTE = new Set(['.svelte']);
const EXT_HTML   = new Set(['.html', '.htm', '.css', '.scss', '.sass', '.less']);
const EXT_PY     = new Set(['.py']);
const EXT_PHP    = new Set(['.php']);

const ALL_EXTENSIONS = new Set([
  ...EXT_JS, ...EXT_VUE, ...EXT_SVELTE,
  ...EXT_HTML, ...EXT_PY, ...EXT_PHP,
]);

const SKIP_DIRS_BASE = [
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '.cache', '.nuxt', 'vendor', '__pycache__',
  '.venv', 'venv', 'env', 'storage', 'bootstrap/cache',
];

const MAX_FILE_SIZE_KB = 500;

// ─── Detecção de frameworks ───────────────────────────────────────────────────

function detectFrameworks(projectRoot) {
  const detected = new Set();

  const pkgPath = path.join(projectRoot, 'package.json');
  let deps = {};
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
    deps = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
  } catch {}

  const composerPath = path.join(projectRoot, 'composer.json');
  let phpDeps = {};
  try {
    const composer = JSON.parse(fs.readFileSync(composerPath, 'utf8'));
    phpDeps = { ...composer.require, ...composer['require-dev'] };
  } catch {}

  if (deps['vue'] || deps['@vue/core'])               detected.add('vue');
  if (deps['@angular/core'])                          detected.add('angular');
  if (deps['next'])                                   detected.add('nextjs');
  if (deps['svelte'] || deps['@sveltejs/kit'])        detected.add('svelte');
  if (deps['fastify'])                                detected.add('fastify');
  if (deps['@nestjs/core'])                           detected.add('nestjs');
  if (deps['@prisma/client'] || deps['prisma'])       detected.add('prisma');
  if (deps['typeorm'] || deps['sequelize'])           detected.add('typeorm');

  const exists = (...files) => files.some(f => fs.existsSync(path.join(projectRoot, f)));

  if (exists('requirements.txt','pyproject.toml','setup.py','Pipfile','manage.py','app.py')) detected.add('python');
  if (exists('wp-config.php','wp-config-sample.php','wp-login.php'))  detected.add('wordpress');
  if (phpDeps['laravel/framework'] || exists('artisan'))               detected.add('laravel');

  try {
    const entries = fs.readdirSync(projectRoot);
    if (entries.some(f => f.endsWith('.py')))     detected.add('python');
    if (entries.some(f => f.endsWith('.vue')))    detected.add('vue');
    if (entries.some(f => f.endsWith('.svelte'))) detected.add('svelte');
    if (entries.some(f => f.endsWith('.php'))) {
      if (!detected.has('wordpress') && !detected.has('laravel')) {
        if (exists('wp-config.php'))  detected.add('wordpress');
        else if (exists('artisan'))   detected.add('laravel');
      }
    }
  } catch {}

  detected.add('html'); // sempre ativo; só processa se encontrar .html/.css
  return detected;
}

// ─── Coleta de arquivos ───────────────────────────────────────────────────────

function collectFiles(dir, auditorDirName) {
  const skipDirs = new Set([...SKIP_DIRS_BASE, auditorDirName]);
  const files    = [];

  function walk(current) {
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (skipDirs.has(entry.name)) continue;
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile() && ALL_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        try {
          const stat = fs.statSync(fullPath);
          if (stat.size / 1024 < MAX_FILE_SIZE_KB) files.push(fullPath);
        } catch {}
      }
    }
  }

  walk(dir);
  return files;
}

// ─── Progress bar ─────────────────────────────────────────────────────────────

function progress(current, total, label) {
  const pct    = Math.round((current / total) * 100);
  const filled = Math.round(pct / 5);
  const bar    = '█'.repeat(filled) + '░'.repeat(20 - filled);
  process.stdout.write(`\r  [${bar}] ${pct}%  ${label.substring(0, 50).padEnd(50)}`);
}

// ─── Decide quais analyzers rodar por extensão de arquivo ────────────────────

function pickAnalyzers(filePath, frameworks, loaded) {
  const ext  = path.extname(filePath).toLowerCase();
  const list = [];

  if (EXT_JS.has(ext)) {
    list.push(security, performance, flow);
    for (const fw of ['vue','angular','nextjs','svelte','fastify','nestjs','prisma','typeorm']) {
      if (frameworks.has(fw) && loaded[fw]) list.push(loaded[fw]);
    }
  }
  if (EXT_VUE.has(ext)    && loaded['vue'])    list.push(loaded['vue']);
  if (EXT_SVELTE.has(ext) && loaded['svelte']) list.push(loaded['svelte']);
  if (EXT_HTML.has(ext)   && loaded['html'])   list.push(loaded['html']);
  if (EXT_PY.has(ext)     && loaded['python']) list.push(loaded['python']);
  if (EXT_PHP.has(ext)) {
    if (loaded['wordpress']) list.push(loaded['wordpress']);
    if (loaded['laravel'])   list.push(loaded['laravel']);
  }

  return list;
}

// ─── Deduplica findings ───────────────────────────────────────────────────────

function dedup(arr) {
  const seen = new Set();
  return arr.filter(f => {
    const key = `${f.file}:${f.line}:${f.description}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ─── Proteção Git ─────────────────────────────────────────────────────────────

function protectGitignore(projectRoot) {
  const auditorDirName = path.basename(__dirname);
  const gitignorePath  = path.join(projectRoot, '.gitignore');
  const hasGit         = fs.existsSync(path.join(projectRoot, '.git'));
  const hasGitignore   = fs.existsSync(gitignorePath);
  if (!hasGit && !hasGitignore) return;

  let content = '';
  if (hasGitignore) content = fs.readFileSync(gitignorePath, 'utf8');

  const alreadyIgnored = content.split('\n').some(l => {
    const t = l.trim().replace(/\/$/, '');
    return t === auditorDirName || t === `/${auditorDirName}`;
  });
  if (alreadyIgnored) return;

  try {
    fs.appendFileSync(gitignorePath, `\n# Project Auditor — remova após usar\n${auditorDirName}/\n`);
    console.log(`🔒 .gitignore atualizado: "${auditorDirName}/" adicionado automaticamente.\n`);
  } catch {
    console.warn(`⚠️  Adicione "${auditorDirName}/" ao .gitignore manualmente.\n`);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args        = process.argv.slice(2);
  const targetArg   = args[0];
  const projectRoot = targetArg ? path.resolve(targetArg) : path.resolve(__dirname, '..');
  const projectName = path.basename(projectRoot);
  const auditorDir  = path.basename(__dirname);

  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║        🛡️  PROJECT AUDITOR AGENT v2.0            ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);
  console.log(`📁 Projeto:   ${projectName}`);
  console.log(`📂 Diretório: ${projectRoot}\n`);

  if (!fs.existsSync(projectRoot)) {
    console.error(`❌ Diretório não encontrado: ${projectRoot}`);
    process.exit(1);
  }

  protectGitignore(projectRoot);

  // ── Detecta frameworks ──
  process.stdout.write('🔎 Detectando frameworks e stacks...');
  const frameworks = detectFrameworks(projectRoot);
  const fwList = [...frameworks].filter(f => f !== 'html').join(', ') || 'JS/TS genérico';
  console.log(` ${fwList}\n`);

  // ── Carrega analyzers ativos ──
  const loaded = {};
  for (const fw of frameworks) {
    if (ANALYZER_MAP[fw]) {
      try { loaded[fw] = ANALYZER_MAP[fw](); }
      catch (e) { console.warn(`⚠️  Falha ao carregar analyzer [${fw}]: ${e.message}`); }
    }
  }

  const startTime = Date.now();

  // ── Coleta arquivos ──
  process.stdout.write('🔍 Coletando arquivos...');
  const files = collectFiles(projectRoot, auditorDir);
  console.log(` ${files.length} arquivo(s) encontrado(s)\n`);

  if (files.length === 0) {
    console.log('⚠️  Nenhum arquivo encontrado para análise.\n');
    process.exit(0);
  }

  // ── Análise ──
  const securityFindings    = [];
  const performanceFindings = [];
  const flowFindings        = [];
  const frameworkFindings   = [];

  console.log('🔬 Analisando arquivos...\n');

  for (let i = 0; i < files.length; i++) {
    const file      = files[i];
    const analyzers = pickAnalyzers(file, frameworks, loaded);
    progress(i + 1, files.length, path.relative(projectRoot, file));

    for (const analyzer of analyzers) {
      if (typeof analyzer.analyzeFile !== 'function') continue;
      const found = analyzer.analyzeFile(file);
      for (const f of found) {
        if      (analyzer === security)     securityFindings.push(f);
        else if (analyzer === performance)  performanceFindings.push(f);
        else if (analyzer === flow)         flowFindings.push(f);
        else                                frameworkFindings.push(f);
      }
    }
  }

  process.stdout.write('\n\n');

  // ── Verificações de projeto ──
  console.log('🏗️  Verificações de configuração...');
  securityFindings.push(...security.analyzeGitignore(projectRoot));
  securityFindings.push(...security.checkSensitiveFiles(projectRoot));
  securityFindings.push(...security.checkDependencyAudit(projectRoot));
  performanceFindings.push(...performance.analyzeProjectConfig(projectRoot));
  flowFindings.push(...flow.analyzeProjectStructure(projectRoot));

  for (const [, analyzer] of Object.entries(loaded)) {
    if (typeof analyzer.analyzeProject === 'function') {
      try { frameworkFindings.push(...analyzer.analyzeProject(projectRoot)); } catch {}
    }
  }

  // ── Deduplicação ──
  const allSecurity    = dedup(securityFindings);
  const allPerformance = dedup(performanceFindings);
  const allFlow        = dedup(flowFindings);
  const allFramework   = dedup(frameworkFindings);
  const allFindings    = [...allSecurity, ...allPerformance, ...allFlow, ...allFramework];

  const duration = Date.now() - startTime;
  const critical = allFindings.filter(f => f.severity === 'CRITICAL').length;
  const high     = allFindings.filter(f => f.severity === 'HIGH').length;
  const total    = allFindings.length;

  console.log(`\n✅ Análise concluída em ${duration}ms\n`);
  console.log(`┌──────────────────────────────────────────┐`);
  console.log(`│  🔒 Segurança:       ${String(allSecurity.length).padEnd(20)}│`);
  console.log(`│  ⚡ Performance:     ${String(allPerformance.length).padEnd(20)}│`);
  console.log(`│  🔄 Fluxo:           ${String(allFlow.length).padEnd(20)}│`);
  console.log(`│  🧩 Framework:       ${String(allFramework.length).padEnd(20)}│`);
  console.log(`│  ──────────────────────────────────────  │`);
  console.log(`│  📊 Total:           ${String(total).padEnd(20)}│`);
  console.log(`│  🔴 Críticos:        ${String(critical).padEnd(20)}│`);
  console.log(`│  🟠 Altos:           ${String(high).padEnd(20)}│`);
  console.log(`└──────────────────────────────────────────┘\n`);

  const reportContent = reporter.generate({
    projectRoot, projectName,
    securityFindings: allSecurity, performanceFindings: allPerformance,
    flowFindings: allFlow, frameworkFindings: allFramework,
    filesScanned: files.length, duration,
    frameworks: [...frameworks].filter(f => f !== 'html'),
  });

  const reportDir = path.join(__dirname, 'reports');
  fs.mkdirSync(reportDir, { recursive: true });

  const dateStr        = new Date().toISOString().split('T')[0];
  const reportFilename = `audit-report-${projectName}-${dateStr}.md`;
  fs.writeFileSync(path.join(reportDir, reportFilename), reportContent, 'utf8');

  const counts = {};
  for (const f of allFindings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const penalty = (counts.CRITICAL||0)*25 + (counts.HIGH||0)*10 + (counts.MEDIUM||0)*4 + (counts.LOW||0)*1;
  const score   = Math.max(0, 100 - penalty);
  const grade   = score >= 85 ? 'A' : score >= 65 ? 'B' : score >= 40 ? 'C' : 'D';
  const verdict = score >= 85 ? '✅ Projeto em bom estado'
                : score >= 65 ? '⚠️  Atenção necessária'
                : score >= 40 ? '🔶 Riscos significativos'
                :               '🚨 Vulnerabilidades críticas detectadas';

  const playbookContent  = promptGenerator.buildPromptDoc({ projectName, projectRoot, allFindings, counts, rating: { score, grade, verdict }, reportFilename });
  const playbookFilename = `audit-playbook-${projectName}-${dateStr}.md`;
  fs.writeFileSync(path.join(reportDir, playbookFilename), playbookContent, 'utf8');

  console.log(`📄 Relatório:  ${auditorDir}/reports/${reportFilename}`);
  console.log(`🤖 Playbook:   ${auditorDir}/reports/${playbookFilename}\n`);

  if (critical > 0) {
    console.log(`🚨 ATENÇÃO: ${critical} vulnerabilidade(s) CRÍTICA(s) encontrada(s)!`);
    console.log(`   Revise o relatório e corrija antes de ir para produção.\n`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('\n❌ Erro durante a análise:', err.message);
  process.exit(1);
});
