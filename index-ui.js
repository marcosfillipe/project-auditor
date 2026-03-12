#!/usr/bin/env node
'use strict';

const fs      = require('fs');
const path    = require('path');
const { chromium } = require('playwright');

const detector      = require('./analyzers-ui/detector');
const formSecurity  = require('./analyzers-ui/form-security');
const networkInspector = require('./analyzers-ui/network-inspector');
const domObserver   = require('./analyzers-ui/dom-observer');
const rateLimitProbe = require('./analyzers-ui/rate-limit-probe');
const browserResolver = require('./analyzers-ui/browser-resolver');

// ─── Config ───────────────────────────────────────────────────────────────────

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEVERITY_EMOJI = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: '⚪' };

// ─── Args ─────────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const urlArg = args.find(a => a.startsWith('--url='))?.split('=')[1]
    || (args[args.indexOf('--url') + 1] !== undefined && !args[args.indexOf('--url') + 1]?.startsWith('--')
      ? args[args.indexOf('--url') + 1] : null);
  return { url: urlArg || null };
}

// ─── Progress ─────────────────────────────────────────────────────────────────

function step(emoji, label) {
  console.log(`${emoji}  ${label}`);
}

// ─── Report builder ───────────────────────────────────────────────────────────

function buildReport({ projectName, frontendUrl, findings, duration }) {
  const all = findings.flat();
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of all) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const penalty = counts.CRITICAL * 25 + counts.HIGH * 10 + counts.MEDIUM * 4 + counts.LOW * 1;
  const score   = Math.max(0, 100 - penalty);
  const grade   = score >= 85 ? 'A' : score >= 65 ? 'B' : score >= 40 ? 'C' : 'D';

  const ts = new Date().toLocaleString('pt-BR', { timeZone: 'America/Fortaleza', dateStyle: 'full', timeStyle: 'short' });
  const dateStr = new Date().toISOString().split('T')[0];

  const sorted = [...all].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));

  const grouped = {};
  for (const f of sorted) {
    if (!grouped[f.label]) grouped[f.label] = [];
    grouped[f.label].push(f);
  }

  const lines = [
    `# 🖥️ Relatório de Auditoria UI — ${projectName}`,
    ``,
    `> **Gerado em:** ${ts}`,
    `> **Frontend analisado:** ${frontendUrl}`,
    `> **Tempo de análise:** ${duration}ms`,
    `> **Ferramenta:** Project Auditor Agent — Módulo UI (Playwright)`,
    ``,
    `---`,
    ``,
    `## 📊 Resumo Executivo`,
    ``,
    `| Indicador | Valor |`,
    `|-----------|-------|`,
    `| **Score de Saúde UI** | **${score}/100 (${grade})** |`,
    `| 🔴 Crítico | ${counts.CRITICAL} |`,
    `| 🟠 Alto    | ${counts.HIGH} |`,
    `| 🟡 Médio   | ${counts.MEDIUM} |`,
    `| 🔵 Baixo   | ${counts.LOW} |`,
    `| ⚪ Info    | ${counts.INFO} |`,
    `| **Total**  | **${all.length}** |`,
    ``,
    `---`,
    ``,
    `## 🔒 Formulários`,
    ``,
    ...buildSection(findings[0]),
    ``,
    `---`,
    ``,
    `## 🌐 Rede & Headers`,
    ``,
    ...buildSection(findings[1]),
    ``,
    `---`,
    ``,
    `## 🔍 DOM & Storage`,
    ``,
    ...buildSection(findings[2]),
    ``,
    `---`,
    ``,
    `## ⏱️ Rate Limiting`,
    ``,
    ...buildSection(findings[3]),
    ``,
    `---`,
    ``,
    `_Relatório gerado pelo Project Auditor Agent — Módulo UI. Análise realizada em browser headless real (Chromium ${dateStr})._`,
  ];

  return lines.join('\n');
}

function buildSection(sectionFindings) {
  if (!sectionFindings || sectionFindings.length === 0) {
    return ['> ✅ Nenhum problema encontrado nesta categoria.'];
  }

  const sorted = [...sectionFindings].sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
  );

  return sorted.map(f => {
    const emoji = SEVERITY_EMOJI[f.severity];
    const loc = f.url ? ` — \`${f.url.substring(0, 80)}\`` : f.location ? ` — ${f.location}` : '';
    return `- ${emoji} **${f.label}** \`[${f.severity}]\`\n  ${f.detail}${loc}`;
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
  const { url: urlOverride } = parseArgs();
  const projectRoot = path.resolve(__dirname, '..');
  const projectName = path.basename(projectRoot);
  const startTime   = Date.now();

  console.log(`\n╔══════════════════════════════════════════════════╗`);
  console.log(`║     🖥️  PROJECT AUDITOR — Módulo UI v1.0         ║`);
  console.log(`╚══════════════════════════════════════════════════╝\n`);
  console.log(`📁 Projeto: ${projectName}`);
  console.log(`📂 Raiz:    ${projectRoot}\n`);

  // Garante que o auditor está no .gitignore do projeto
  protectGitignore(projectRoot);

  // ── Detecção de servidores ──
  const detection = await detector.detect(projectRoot);

  // Mostra problemas de detecção se houver
  if (detection.issues.length > 0) {
    for (const issue of detection.issues) {
      if (issue.type === 'no-ui') {
        console.log(`\nℹ️  ${issue.message}`);
        console.log(`   ${issue.suggestion}\n`);
        process.exit(0);
      }
      if (issue.type === 'frontend-offline' || issue.type === 'backend-offline') {
        console.log(`\n⚠️  ${issue.message}`);
        if (issue.suggestion) console.log(`   💡 ${issue.suggestion}`);
      }
    }
  }

  // Determina URL alvo
  const targetUrl = urlOverride || detection.frontend?.url;

  if (!targetUrl) {
    const frontIssue = detection.issues.find(i => i.type === 'frontend-offline');
    console.log(`\n❌ Não foi possível iniciar a análise UI.\n`);
    console.log(`   Motivo: Frontend não está acessível.`);
    if (frontIssue?.suggestion) {
      console.log(`\n   O que fazer:`);
      console.log(`   1. ${frontIssue.suggestion}`);
      console.log(`   2. npm run check:ui\n`);
    } else {
      console.log(`\n   Alternativa: npm run check:ui -- --url http://localhost:PORTA\n`);
    }
    process.exit(1);
  }

  if (detection.backend) {
    console.log(`ℹ️  Backend detectado em ${detection.backend.url} — endpoints serão incluídos na análise\n`);
  }

  console.log(`🎯 Analisando: ${targetUrl}\n`);

  // ── Lança browser ──
  step('🌐', 'Iniciando browser headless...');

  // Resolve o executável do browser de forma cross-platform (Windows, macOS, Linux)
  const resolved = await browserResolver.resolve(chromium);
  if (!resolved.source) {
    console.error(browserResolver.installInstructions());
    process.exit(1);
  }
  console.log(`   Browser: ${resolved.source}\n`);

  let browser;
  try {
    const launchOptions = {
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    };
    if (resolved.executablePath) launchOptions.executablePath = resolved.executablePath;

    browser = await chromium.launch(launchOptions);
  } catch (err) {
    console.error(`\n❌ Falha ao iniciar o browser: ${err.message}`);
    console.error(browserResolver.installInstructions());
    process.exit(1);
  }

  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    userAgent: 'Mozilla/5.0 (compatible; ProjectAuditor/1.0)',
  });

  const allFindings = [[], [], [], []];

  try {
    // ── 1. Formulários ──
    step('📋', 'Analisando formulários (XSS, injection, campos ocultos)...');
    const formPage = await context.newPage();
    allFindings[0] = await formSecurity.analyze(formPage, targetUrl);
    await formPage.close();
    console.log(`   ${allFindings[0].length} ponto(s) encontrado(s)\n`);

    // ── 2. Rede & Headers ──
    step('🌐', 'Inspecionando headers e requisições de rede...');
    const netPage = await context.newPage();
    allFindings[1] = await networkInspector.analyze(netPage, targetUrl);
    await netPage.close();
    console.log(`   ${allFindings[1].length} ponto(s) encontrado(s)\n`);

    // ── 3. DOM & Storage ──
    step('🔍', 'Observando DOM, Storage e console...');
    const domPage = await context.newPage();
    allFindings[2] = await domObserver.analyze(domPage, targetUrl);
    await domPage.close();
    console.log(`   ${allFindings[2].length} ponto(s) encontrado(s)\n`);

    // ── 4. Rate Limiting ──
    step('⏱️ ', 'Testando rate limiting em endpoints de autenticação...');
    const ratePage = await context.newPage();
    allFindings[3] = await rateLimitProbe.analyze(ratePage, targetUrl);
    await ratePage.close();
    console.log(`   ${allFindings[3].length} ponto(s) encontrado(s)\n`);

  } catch (err) {
    console.error(`\n❌ Erro durante análise: ${err.message}\n`);
  } finally {
    await context.close();
    await browser.close();
  }

  const duration = Date.now() - startTime;
  const allFlat  = allFindings.flat();
  const critical = allFlat.filter(f => f.severity === 'CRITICAL').length;
  const high     = allFlat.filter(f => f.severity === 'HIGH').length;

  // ── Resumo no console ──
  console.log(`✅ Análise UI concluída em ${duration}ms\n`);
  console.log(`┌─────────────────────────────────────┐`);
  console.log(`│  📋 Formulários:   ${String(allFindings[0].length).padEnd(16)}│`);
  console.log(`│  🌐 Rede/Headers:  ${String(allFindings[1].length).padEnd(16)}│`);
  console.log(`│  🔍 DOM/Storage:   ${String(allFindings[2].length).padEnd(16)}│`);
  console.log(`│  ⏱️  Rate Limiting: ${String(allFindings[3].length).padEnd(15)}│`);
  console.log(`│  ─────────────────────────────────  │`);
  console.log(`│  📊 Total:         ${String(allFlat.length).padEnd(16)}│`);
  console.log(`│  🔴 Críticos:      ${String(critical).padEnd(16)}│`);
  console.log(`│  🟠 Altos:         ${String(high).padEnd(16)}│`);
  console.log(`└─────────────────────────────────────┘\n`);

  // ── Salva relatório ──
  const reportDir = path.join(__dirname, 'reports');
  fs.mkdirSync(reportDir, { recursive: true });

  const dateStr    = new Date().toISOString().split('T')[0];
  const reportName = `audit-ui-report-${projectName}-${dateStr}.md`;
  const reportPath = path.join(reportDir, reportName);

  const reportContent = buildReport({ projectName, frontendUrl: targetUrl, findings: allFindings, duration });
  fs.writeFileSync(reportPath, reportContent, 'utf8');

  console.log(`📄 Relatório UI gerado: auditor/reports/${reportName}\n`);

  if (critical > 0) {
    console.log(`🚨 ATENÇÃO: ${critical} vulnerabilidade(s) CRÍTICA(s) encontrada(s) na UI!`);
    console.log(`   Revise o relatório antes de fazer deploy.\n`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('\n❌ Erro inesperado:', err.message);
  process.exit(1);
});
