#!/usr/bin/env node
'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

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
  if (b < 1024)      return `${b} B`;
  if (b < 1_048_576) return `${(b / 1024).toFixed(1)} KB`;
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

// ── Remoção arquivo por arquivo ───────────────────────────────────────────────
// Estratégia: nunca tenta rmdir no diretório raiz (que o Windows bloqueia
// por ser o CWD do terminal). Em vez disso:
//   1. Percorre toda a árvore de arquivos recursivamente
//   2. Remove cada arquivo individualmente com unlinkSync
//   3. Remove subdiretórios vazios de baixo para cima (exceto a raiz)
// Resultado: pasta raiz fica vazia. O Windows pode manter o handle,
// mas todos os arquivos e conteúdo são apagados.

function deleteAllFiles(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      deleteAllFiles(p);
      // Remove o subdiretório se estiver vazio (funciona pois não é o CWD)
      try { fs.rmdirSync(p); } catch {}
    } else {
      // Garante que o arquivo não é read-only antes de deletar (.git objects)
      try { fs.chmodSync(p, 0o666); } catch {}
      try { fs.unlinkSync(p); } catch (err) {
        // Se falhar, tenta forçar via attrib no Windows
        if (os.platform() === 'win32') {
          try {
            require('child_process').execSync(
              `attrib -r -s -h "${p}"`,
              { stdio: 'ignore', windowsHide: true }
            );
            fs.unlinkSync(p);
          } catch {}
        }
      }
    }
  }
}

function countRemainingFiles(dir) {
  let count = 0;
  try {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) count += countRemainingFiles(p);
      else count++;
    }
  } catch {}
  return count;
}

// ── Remoção diferida da pasta raiz ───────────────────────────────────────────
// Após apagar todos os arquivos, a pasta raiz pode ficar bloqueada porque
// o terminal tem ela como CWD. Quando o usuário fizer cd para outro lugar,
// o handle é liberado automaticamente pelo SO.
//
// Este mecanismo spawna um processo Node filho desacoplado que fica tentando
// rmdir a cada 500ms por até 60 segundos. Assim que o terminal sair da pasta
// (ou qualquer outro processo liberar o handle), o rmdir funciona sozinho.
//
// Funciona igual no Windows e Linux — sem admin, sem registry, sem reboot.

function spawnDeferredRmdir(agentDir) {
  const cp         = require('child_process');
  const os         = require('os');
  const path       = require('path');
  const helperPath = path.join(os.tmpdir(), `auditor-rmdir-${Date.now()}.mjs`);

  const script = `
import { rmdirSync, existsSync, unlinkSync } from 'fs';
import { setTimeout as wait } from 'timers/promises';

const target = process.argv[2];
const self   = process.argv[3];
const start  = Date.now();
const TIMEOUT = 60_000; // 60 segundos
const INTERVAL = 500;   // tenta a cada 500ms

while (Date.now() - start < TIMEOUT) {
  if (!existsSync(target)) break; // já foi removida
  try {
    rmdirSync(target);
    break; // removeu com sucesso
  } catch {
    await wait(INTERVAL);
  }
}

try { unlinkSync(self); } catch {}
`.trimStart();

  require('fs').writeFileSync(helperPath, script, 'utf8');

  cp.spawn(process.execPath, [helperPath, agentDir, helperPath], {
    detached:    true,
    stdio:       'ignore',
    windowsHide: true,
    env: {
      SystemRoot: process.env.SystemRoot || 'C:\\Windows',
      TEMP:       process.env.TEMP       || os.tmpdir(),
      TMP:        process.env.TMP        || os.tmpdir(),
      PATH:       (process.env.SystemRoot || 'C:\\Windows') + '\\system32',
    },
  }).unref();
}

// ── Sistema de input ──────────────────────────────────────────────────────────

let _pipeLines = null;
let _pipeIdx   = 0;

function detectInputMode() {
  return new Promise(resolve => {
    let buf = '', resolved = false;
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
    rl.once('line', a => { rl.close(); process.stdin.pause(); resolve(a.trim()); });
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
  return { agentDir, parentDir };
}

// ── Aviso de relatórios ───────────────────────────────────────────────────────

function warnAboutReports(agentDir) {
  const reportsDir = path.join(agentDir, 'reports');
  if (!fs.existsSync(reportsDir)) return;
  const reports = fs.readdirSync(reportsDir).filter(f => f.endsWith('.md'));
  if (!reports.length) return;
  console.log(`\n📄 ${reports.length} relatório(s) em reports/ (serão removidos junto):`);
  reports.forEach(r => console.log(`   • ${r}`));
  console.log(`   ℹ️  Consulte-os antes de continuar.\n`);
}

// ── Limpeza do .gitignore ─────────────────────────────────────────────────────

function cleanGitignore(parentDir, auditorDirName) {
  const giPath = path.join(parentDir, '.gitignore');
  if (!fs.existsSync(giPath)) return;

  const original = fs.readFileSync(giPath, 'utf8');
  const auditorEntries = new Set([
    `${auditorDirName}/`, `/${auditorDirName}/`, auditorDirName,
    'audit-reports/', '/audit-reports/',
    '# Project Auditor — remova após usar', '# Project Auditor',
  ]);

  let cleaned = original.split('\n').filter(l => !auditorEntries.has(l.trim()));
  cleaned = cleaned.reduce((acc, l) => {
    if (l.trim() === '' && acc.length > 0 && acc[acc.length - 1].trim() === '') return acc;
    acc.push(l);
    return acc;
  }, []);
  while (cleaned.length && cleaned[cleaned.length - 1].trim() === '') cleaned.pop();

  const result = cleaned.join('\n') + (cleaned.length ? '\n' : '');
  if (result === original) return;

  try {
    fs.writeFileSync(giPath, result, 'utf8');
    console.log(`  🧹 .gitignore restaurado — entradas do auditor removidas.`);
  } catch {
    console.warn(`  ⚠️  Não foi possível limpar o .gitignore. Remova manualmente: "${auditorDirName}/"`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const autoYes = process.argv.includes('--yes') || process.argv.includes('-y');

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

  console.log('\n  🗑️  Removendo arquivos...\n');

  // Limpa .gitignore primeiro (enquanto os arquivos ainda existem)
  cleanGitignore(parentDir, auditorDirName);

  // Remove todos os arquivos e subdiretórios (exceto o diretório raiz)
  deleteAllFiles(agentDir);

  // Tenta remover o diretório raiz (funciona se o CWD for o pai)
  try { fs.rmdirSync(agentDir); } catch {}

  const remaining = countRemainingFiles(agentDir);
  const rootGone  = !fs.existsSync(agentDir);

  console.log(`${line('═')}`);

  if (rootGone) {
    console.log('  ✅ project-auditor removido com sucesso!\n');
    console.log(`  Removido : ${auditorDirName}/`);
    console.log(`  Intacto  : ${parentDir}\n`);
  } else if (remaining === 0) {
    // Pasta vazia — spawna processo que remove assim que o terminal sair
    spawnDeferredRmdir(agentDir);
    console.log('  ✅ Todos os arquivos removidos com sucesso!\n');
    console.log(`  📁 A pasta "${auditorDirName}/" está vazia e será removida`);
    console.log(`     automaticamente assim que você sair dela no terminal.\n`);
    console.log(`  💡 Execute: cd "${parentDir}"\n`);
  } else {
    console.log(`  ⚠️  ${remaining} arquivo(s) não puderam ser removidos.`);
    console.log(`  O restante foi apagado. Remova manualmente:\n`);
    if (os.platform() === 'win32') {
      console.log(`    rd /s /q "${agentDir}"\n`);
    } else {
      console.log(`    rm -rf "${agentDir}"\n`);
    }
  }

  process.exit(0);
}

main().catch(err => {
  console.error('\n❌ Erro inesperado:', err.message);
  process.exit(1);
});
