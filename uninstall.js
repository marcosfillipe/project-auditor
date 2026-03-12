#!/usr/bin/env node
'use strict';

const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const cp     = require('child_process');

const AGENT_PACKAGE_NAME    = 'project-auditor';
const AGENT_SIGNATURE_FILES = [
  'index.js', 'reporter.js', 'prompt-generator.js',
  path.join('analyzers', 'security.js'),
  path.join('analyzers', 'performance.js'),
  path.join('analyzers', 'flow.js'),
];

// ── Utilitários ───────────────────────────────────────────────────────────────

function line(char = '─', len = 52) { return char.repeat(len); }

function formatSize(b) {
  if (b < 1024)       return `${b} B`;
  if (b < 1_048_576)  return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1_048_576).toFixed(1)} MB`;
}

function getDirSize(d) {
  let t = 0;
  try {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name);
      t += e.isDirectory() ? getDirSize(f) : fs.statSync(f).size;
    }
  } catch {}
  return t;
}

function listContents(dir) {
  const out = [];
  function walk(d, pre = '') {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      out.push(pre + e.name + (e.isDirectory() ? '/' : ''));
      if (e.isDirectory()) walk(path.join(d, e.name), pre + '  ');
    }
  }
  walk(dir);
  return out;
}

// ── Remoção robusta no Windows ────────────────────────────────────────────────
// Dois problemas combinados no Windows:
//
// 1. npm mantém handles em node_modules/.bin/*.cmd enquanto o processo Node
//    está vivo → fs.rmSync falha com EBUSY.
//    Fix: processo .bat desacoplado que aguarda o pai morrer antes de remover.
//
// 2. git clone cria arquivos com atributos READ-ONLY / SYSTEM / HIDDEN dentro
//    de .git/ → rd /s /q falha silenciosamente nesses arquivos.
//    Fix: attrib -r -s -h /s /d remove todos os atributos restritivos
//    recursivamente ANTES do rd — garante remoção completa incluindo .git/.

function removeWindows(agentDir, parentDir, auditorDirName) {
  // Estratégia de 3 etapas para contornar os locks do Windows:
  //
  // ETAPA 1 — Rename para fora do CWD (feito AGORA, com Node ainda vivo)
  //   npm/Node mantêm o CWD project-auditor/ aberto. Mas rename() numa
  //   pasta diferente é permitido mesmo com handles abertos no diretório
  //   original. Renomeia para _auditor-rm-<ts>/ no diretório pai.
  //   Resultado: project-auditor/ desaparece imediatamente para o usuário.
  //
  // ETAPA 2 — .bat desacoplado remove a pasta renomeada
  //   O .bat aguarda 3s (npm/Node já morreram), roda attrib para tirar
  //   atributos read-only do .git/, e então rd /s /q sem nenhum handle ativo.
  //
  // ETAPA 3 — .bat se auto-deleta

  const ts         = Date.now();
  const stagingDir = path.join(parentDir, `_auditor-rm-${ts}`);
  const batPath    = path.join(os.tmpdir(), `auditor-rm-${ts}.bat`);

  // Tenta o rename — se falhar (raro), cai no .bat direto
  let targetDir = agentDir;
  try {
    fs.renameSync(agentDir, stagingDir);
    targetDir = stagingDir;
  } catch {
    // Rename falhou (ex: cross-device) — usa agentDir original
    targetDir = agentDir;
  }

  const bat = [
    '@echo off',
    'timeout /t 3 /nobreak >nul',
    `attrib -r -s -h "${targetDir}\*" /s /d >nul 2>&1`,
    `rd /s /q "${targetDir}"`,
    // Remove também o agentDir original caso o rename tenha falhado
    `if exist "${agentDir}" rd /s /q "${agentDir}"`,
    `del "${batPath}"`,
  ].join('\r\n');

  fs.writeFileSync(batPath, bat, 'utf8');

  const child = cp.spawn('cmd.exe', ['/c', batPath], {
    detached:    true,
    stdio:       'ignore',
    windowsHide: true,
  });
  child.unref();

  console.log(`  🗑️  Remoção agendada — arquivos serão apagados em instantes.`);
  console.log(`  ✅ project-auditor removido com sucesso!\n`);
  console.log(`  Removido : ${auditorDirName}/`);
  console.log(`  Intacto  : ${parentDir}\n`);
}

function removeUnix(agentDir) {
  try { process.chdir(path.resolve(agentDir, '..')); } catch {}
  // chmod recursivo garante que arquivos read-only do .git/ não bloqueiem a remoção
  chmodRecursive(agentDir);
  fs.rmSync(agentDir, { recursive: true, force: true });
}

// Torna todos os arquivos graváveis antes de rmSync (necessário para .git/ no Unix)
function chmodRecursive(target) {
  try {
    const entries = fs.readdirSync(target, { withFileTypes: true });
    for (const e of entries) {
      const p = path.join(target, e.name);
      try { fs.chmodSync(p, 0o755); } catch {}
      if (e.isDirectory()) chmodRecursive(p);
    }
  } catch {}
}

// ── Sistema de input robusto ──────────────────────────────────────────────────

let _pipeLines = null;
let _pipeIdx   = 0;

function detectInputMode() {
  return new Promise(resolve => {
    let buf      = '';
    let resolved = false;

    process.stdin.setEncoding('utf8');
    process.stdin.resume();

    const timer = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      process.stdin.removeAllListeners('data');
      process.stdin.pause();
      _pipeLines = null;
      resolve();
    }, 80);

    process.stdin.on('data', chunk => {
      buf += chunk;
      clearTimeout(timer);
      setTimeout(() => {
        if (resolved) return;
        resolved = true;
        process.stdin.removeAllListeners('data');
        process.stdin.pause();
        _pipeLines = buf.split(/\r?\n/).map(l => l.trim()).filter((_, i, a) => i < a.length - 1 || _ !== '');
        resolve();
      }, 20);
    });
  });
}

function ask(question) {
  return new Promise(resolve => {
    process.stdout.write(question);

    if (_pipeLines !== null) {
      const answer = _pipeLines[_pipeIdx++] ?? '';
      process.stdout.write(answer + '\n');
      resolve(answer);
      return;
    }

    const { createInterface } = require('readline');
    process.stdin.resume();
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    rl.once('line', answer => { rl.close(); process.stdin.pause(); resolve(answer.trim()); });
    rl.once('close', () => resolve(''));
  });
}

// ── Verificações de segurança ─────────────────────────────────────────────────

function assertAgentIdentity() {
  const pkgPath = path.join(__dirname, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    console.error('\n❌ ABORTADO: package.json não encontrado.\n');
    process.exit(1);
  }
  let pkg;
  try { pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')); }
  catch { console.error('\n❌ ABORTADO: Não foi possível ler o package.json.\n'); process.exit(1); }
  if (pkg.name !== AGENT_PACKAGE_NAME) {
    console.error(`\n❌ ABORTADO: Este diretório é "${pkg.name}", não "${AGENT_PACKAGE_NAME}".\n`);
    process.exit(1);
  }
  return pkg;
}

function assertSignatureFiles() {
  const missing = AGENT_SIGNATURE_FILES.filter(f => !fs.existsSync(path.join(__dirname, f)));
  if (missing.length > 2) {
    console.error('\n❌ ABORTADO: Instalação inválida — arquivos ausentes:', missing.join(', '));
    process.exit(1);
  }
}

function resolveDirectories() {
  const agentDir  = path.resolve(__dirname);
  const parentDir = path.resolve(__dirname, '..');
  if (agentDir === parentDir) {
    console.error('\n❌ ABORTADO: agentDir === parentDir. Recusando remover a raiz.\n');
    process.exit(1);
  }
  const looksLikeProject = ['package.json', 'src', '.git', 'composer.json', 'go.mod', 'artisan', 'requirements.txt']
    .some(i => fs.existsSync(path.join(parentDir, i)));
  if (!looksLikeProject) {
    console.warn(`\n⚠️  O diretório pai não parece ser um projeto reconhecido: ${parentDir}\n`);
  }
  return { agentDir, parentDir };
}

// ── Aviso de relatórios pendentes ─────────────────────────────────────────────
// Não copia mais para fora da pasta do auditor.
// Mostra os relatórios disponíveis e lembra o usuário de consultá-los
// antes de confirmar a remoção.

function warnAboutReports(agentDir) {
  const reportsDir = path.join(agentDir, 'reports');
  if (!fs.existsSync(reportsDir)) return;
  const reports = fs.readdirSync(reportsDir).filter(f => f.endsWith('.md'));
  if (!reports.length) return;

  console.log(`\n📄 ${reports.length} relatório(s) em reports/ (serão removidos junto):`);
  reports.forEach(r => console.log(`   • ${r}`));
  console.log(`   ℹ️  Consulte-os antes de continuar, ou abra-os agora em outro terminal.\n`);
}

// ── Limpeza do .gitignore ─────────────────────────────────────────────────────

function cleanGitignore(parentDir, auditorDirName) {
  const giPath = path.join(parentDir, '.gitignore');
  if (!fs.existsSync(giPath)) return;

  const original = fs.readFileSync(giPath, 'utf8');
  const lines    = original.split('\n');

  const auditorEntries = new Set([
    `${auditorDirName}/`,
    `/${auditorDirName}/`,
    auditorDirName,
    'audit-reports/',
    '/audit-reports/',
    '# Project Auditor — remova após usar',
    '# Project Auditor',
  ]);

  const cleaned = lines.filter(l => !auditorEntries.has(l.trim()));

  const dedupedBlanks = cleaned.reduce((acc, l) => {
    if (l.trim() === '' && acc.length > 0 && acc[acc.length - 1].trim() === '') return acc;
    acc.push(l);
    return acc;
  }, []);

  while (dedupedBlanks.length && dedupedBlanks[dedupedBlanks.length - 1].trim() === '') {
    dedupedBlanks.pop();
  }

  const result = dedupedBlanks.join('\n') + (dedupedBlanks.length ? '\n' : '');

  if (result === original) return;

  try {
    fs.writeFileSync(giPath, result, 'utf8');
    console.log(`  🧹 .gitignore restaurado — entradas do auditor removidas.`);
  } catch {
    console.warn(`  ⚠️  Não foi possível limpar o .gitignore. Remova manualmente:`);
    console.warn(`      "${auditorDirName}/" do arquivo .gitignore\n`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const autoYes = process.argv.includes('--yes') || process.argv.includes('-y');
  const isWin   = os.platform() === 'win32';

  if (!autoYes) await detectInputMode();

  console.log(`\n${line('═')}`);
  console.log('  🗑️  PROJECT AUDITOR — Desinstalador');
  console.log(`${line('═')}\n`);

  const pkg                     = assertAgentIdentity();
  assertSignatureFiles();
  const { agentDir, parentDir } = resolveDirectories();
  const auditorDirName          = path.basename(agentDir);

  console.log(`  Agente      : ${pkg.name} v${pkg.version}`);
  console.log(`  Removendo   : ${agentDir}`);
  console.log(`  Projeto pai : ${parentDir}`);
  console.log(`  Tamanho     : ${formatSize(getDirSize(agentDir))}\n`);
  console.log(`${line()}`);
  console.log('  📦 Será removido:');
  console.log(`${line()}`);
  const contents = listContents(agentDir);
  contents.slice(0, 20).forEach(c => console.log(`  ${c}`));
  if (contents.length > 20) console.log(`  ... e mais ${contents.length - 20} item(ns)`);
  console.log(`${line()}\n`);

  // Avisa sobre relatórios mas NÃO copia para fora
  warnAboutReports(agentDir);

  console.log(`${line()}`);
  console.log(`  ⚠️  Esta ação é IRREVERSÍVEL.`);
  console.log(`  Apenas "${auditorDirName}/" será removido.`);
  console.log(`  O projeto em "${path.basename(parentDir)}" NÃO será tocado.`);
  console.log(`${line()}\n`);

  let confirm;
  if (autoYes) {
    confirm = 'remover';
    console.log('  Digite "remover" para confirmar: remover  (automático)\n');
  } else {
    confirm = await ask('  Digite "remover" para confirmar: ');
  }

  if (confirm.toLowerCase() !== 'remover') {
    console.log('\n  ↩️  Cancelado. Nenhum arquivo foi alterado.\n');
    process.exit(0);
  }

  console.log('\n  🗑️  Removendo...\n');

  // Limpa .gitignore ANTES de remover a pasta (ainda temos __dirname válido)
  cleanGitignore(parentDir, auditorDirName);

  console.log(`${line('═')}`);

  if (isWin) {
    // Windows: processo desacoplado via .bat — contorna EBUSY do npm
    removeWindows(agentDir, parentDir, auditorDirName);
    process.exit(0); // encerra o Node; o .bat remove a pasta após 2s
  } else {
    // Unix/macOS: remoção direta após chdir
    removeUnix(agentDir);

    if (fs.existsSync(agentDir)) {
      console.error(`\n❌ Pasta ainda existe. Execute manualmente:\n   rm -rf "${agentDir}"\n`);
      process.exit(1);
    }

    console.log('  ✅ project-auditor removido com sucesso!\n');
    console.log(`  Removido : ${auditorDirName}/`);
    console.log(`  Intacto  : ${parentDir}\n`);
    process.exit(0);
  }
}

main().catch(err => {
  console.error('\n❌ Erro inesperado:', err.message);
  process.exit(1);
});
