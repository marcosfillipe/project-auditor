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

function line(char='─', len=52) { return char.repeat(len); }
function formatSize(b) {
  if (b < 1024)    return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  return `${(b/1048576).toFixed(1)} MB`;
}
function getDirSize(d) {
  let t = 0;
  try { for (const e of fs.readdirSync(d,{withFileTypes:true})) { const f=path.join(d,e.name); t+=e.isDirectory()?getDirSize(f):fs.statSync(f).size; } } catch {}
  return t;
}
function listContents(dir) {
  const out=[];
  function walk(d,pre=''){let i;try{i=fs.readdirSync(d,{withFileTypes:true});}catch{return;}for(const e of i){out.push(pre+e.name+(e.isDirectory()?'/':''));if(e.isDirectory())walk(path.join(d,e.name),pre+'  ');}}
  walk(dir); return out;
}
function rmrf(target) {
  if (!fs.existsSync(target)) return;
  try { fs.rmSync(target, { recursive: true, force: true }); return; } catch {}
  if (fs.lstatSync(target).isDirectory()) {
    for (const e of fs.readdirSync(target)) rmrf(path.join(target, e));
    fs.rmdirSync(target);
  } else { fs.unlinkSync(target); }
}

// ── Sistema de input robusto ──────────────────────────────────────────────────
// Problema: `npm run` no Windows executa com stdin.isTTY = undefined,
// mesmo estando num terminal real. Não dá para confiar em isTTY.
//
// Solução: detecção por timeout de 80ms.
// - Dados chegam via pipe em < 1ms → modo buffer (CI, scripts, testes)
// - Terminal interativo → nenhum dado em 80ms → modo readline direto
//
// Isso funciona em Windows PowerShell, CMD, Git Bash e Unix.

let _pipeLines = null; // null = interativo | array = pipe/buffer
let _pipeIdx   = 0;

function detectInputMode() {
  return new Promise(resolve => {
    let buf      = '';
    let resolved = false;

    process.stdin.setEncoding('utf8');
    process.stdin.resume();

    // Timer: se nenhum dado em 80ms, é terminal interativo
    const timer = setTimeout(() => {
      if (resolved) return;
      resolved = true;
      process.stdin.removeAllListeners('data');
      process.stdin.pause();
      _pipeLines = null; // modo interativo
      resolve();
    }, 80);

    process.stdin.on('data', chunk => {
      buf += chunk;
      // Dados chegaram — é pipe. Aguarda mais 20ms para coletar tudo e resolve.
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
      // Modo pipe: consome a próxima linha do buffer
      const answer = _pipeLines[_pipeIdx++] ?? '';
      process.stdout.write(answer + '\n');
      resolve(answer);
      return;
    }

    // Modo interativo: readline sem terminal:true (evita ANSI/echo duplo)
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
  if (!fs.existsSync(pkgPath)) { console.error('\n❌ ABORTADO: package.json não encontrado. Execute de dentro da pasta project-auditor/\n'); process.exit(1); }
  let pkg; try { pkg = JSON.parse(fs.readFileSync(pkgPath,'utf8')); }
  catch { console.error('\n❌ ABORTADO: Não foi possível ler o package.json.\n'); process.exit(1); }
  if (pkg.name !== AGENT_PACKAGE_NAME) { console.error(`\n❌ ABORTADO: Este diretório é "${pkg.name}", não "${AGENT_PACKAGE_NAME}".\n`); process.exit(1); }
  return pkg;
}

function assertSignatureFiles() {
  const missing = AGENT_SIGNATURE_FILES.filter(f => !fs.existsSync(path.join(__dirname,f)));
  if (missing.length > 2) { console.error('\n❌ ABORTADO: Instalação inválida — arquivos ausentes:', missing.join(', ')); process.exit(1); }
}

function resolveDirectories() {
  const agentDir  = path.resolve(__dirname);
  const parentDir = path.resolve(__dirname, '..');
  if (agentDir === parentDir) { console.error('\n❌ ABORTADO: agentDir === parentDir. Recusando remover a raiz.\n'); process.exit(1); }
  const looksLike = ['package.json','src','.git','composer.json','go.mod'].some(i => fs.existsSync(path.join(parentDir,i)));
  if (!looksLike) console.warn(`\n⚠️  AVISO: O diretório pai não parece ser um projeto reconhecido: ${parentDir}\n`);
  return { agentDir, parentDir };
}

// ── Exportação de relatórios ──────────────────────────────────────────────────

async function offerReportExport(agentDir, parentDir, autoYes) {
  const reportsDir = path.join(agentDir, 'reports');
  if (!fs.existsSync(reportsDir)) return;
  const reports = fs.readdirSync(reportsDir).filter(f => f.endsWith('.md'));
  if (!reports.length) return;

  console.log(`\n📄 ${reports.length} relatório(s) encontrado(s) em reports/:`);
  reports.forEach(r => console.log(`   • ${r}`));

  let copy = autoYes ? 's' : await ask('\n   Copiar relatórios para a raiz do projeto antes de remover? [S/n] ');
  if (autoYes) console.log('\n   Copiar relatórios? [S/n] s  (automático)');
  if (copy.toLowerCase() === 'n') { console.log('   ⚠️  Relatórios serão perdidos junto com a pasta.'); return; }

  const dest = path.join(parentDir, 'audit-reports');
  fs.mkdirSync(dest, { recursive: true });
  for (const r of reports) fs.copyFileSync(path.join(reportsDir,r), path.join(dest,r));
  console.log(`   ✅ Relatórios copiados para: audit-reports/`);

  const giPath = path.join(parentDir, '.gitignore');
  if (fs.existsSync(giPath) && !fs.readFileSync(giPath,'utf8').includes('audit-reports')) {
    let addGi = autoYes ? 's' : await ask('   Adicionar "audit-reports/" ao .gitignore? [S/n] ');
    if (autoYes) console.log('   Adicionar ao .gitignore? [S/n] s  (automático)');
    if (addGi.toLowerCase() !== 'n') { fs.appendFileSync(giPath, '\n# Project Auditor\naudit-reports/\n'); console.log('   ✅ .gitignore atualizado.'); }
  }
}

// ── Limpeza do .gitignore ─────────────────────────────────────────────────────
// Remove TODAS as linhas que o auditor inseriu no .gitignore do projeto pai:
// - A entrada da pasta do auditor (ex: "project-auditor/")
// - A entrada de audit-reports/ (se foi adicionada pelo auditor)
// - Os comentários "# Project Auditor" associados
// Deixa o .gitignore exatamente como estava antes da instalação.

function cleanGitignore(parentDir, auditorDirName) {
  const giPath = path.join(parentDir, '.gitignore');
  if (!fs.existsSync(giPath)) return;

  const original = fs.readFileSync(giPath, 'utf8');
  const lines    = original.split('\n');

  // Marcadores que o auditor inseriu (deve coincidir com o que index.js escreve)
  const auditorEntries = new Set([
    `${auditorDirName}/`,
    `/${auditorDirName}/`,
    auditorDirName,
    'audit-reports/',
    '/audit-reports/',
    '# Project Auditor — remova após usar',
    '# Project Auditor',
  ]);

  // Filtra linha a linha, removendo entradas do auditor
  const cleaned = lines.filter(l => !auditorEntries.has(l.trim()));

  // Remove linhas em branco duplicadas que possam ter sobrado
  const dedupedBlanks = cleaned.reduce((acc, l, i) => {
    if (l.trim() === '' && acc.length > 0 && acc[acc.length - 1].trim() === '') return acc;
    acc.push(l);
    return acc;
  }, []);

  // Remove linha em branco isolada no final
  while (dedupedBlanks.length && dedupedBlanks[dedupedBlanks.length - 1].trim() === '') {
    dedupedBlanks.pop();
  }

  const result = dedupedBlanks.join('\n') + (dedupedBlanks.length ? '\n' : '');

  // Só sobrescreve se houve mudança real
  if (result === original) return;

  try {
    fs.writeFileSync(giPath, result, 'utf8');
    console.log(`  🧹 .gitignore restaurado — entradas do auditor removidas.`);
  } catch {
    console.warn(`  ⚠️  Não foi possível limpar o .gitignore. Remova manualmente:`);
    console.warn(`      "${auditorDirName}/" e "audit-reports/" (se existir)\n`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const autoYes = process.argv.includes('--yes') || process.argv.includes('-y');

  // Detecta modo de input ANTES de qualquer saída (pipe vs terminal interativo)
  if (!autoYes) await detectInputMode();

  console.log(`\n${line('═')}`);
  console.log('  🗑️  PROJECT AUDITOR — Desinstalador');
  console.log(`${line('═')}\n`);

  const pkg                     = assertAgentIdentity();
  assertSignatureFiles();
  const { agentDir, parentDir } = resolveDirectories();

  console.log(`  Agente      : ${pkg.name} v${pkg.version}`);
  console.log(`  Removendo   : ${agentDir}`);
  console.log(`  Projeto pai : ${parentDir}`);
  console.log(`  Tamanho     : ${formatSize(getDirSize(agentDir))}\n`);
  console.log(`${line()}`);
  console.log('  📦 Será removido:');
  console.log(`${line()}`);
  const contents = listContents(agentDir);
  contents.slice(0,20).forEach(c => console.log(`  ${c}`));
  if (contents.length > 20) console.log(`  ... e mais ${contents.length-20} item(ns)`);
  console.log(`${line()}\n`);

  await offerReportExport(agentDir, parentDir, autoYes);

  console.log(`\n${line()}`);
  console.log(`  ⚠️  Esta ação é IRREVERSÍVEL.`);
  console.log(`  Apenas "${path.basename(agentDir)}/" será removido.`);
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
    console.log('\n  ↩️  Cancelado. Nenhum arquivo foi alterado.\n'); process.exit(0);
  }

  console.log('\n  🗑️  Removendo...\n');

  // Sai da pasta antes de deletá-la.
  // No Windows o processo mantém um handle no CWD — enquanto o Node estiver
  // "dentro" de project-auditor/, o SO bloqueia a remoção do diretório.
  // process.chdir() libera esse handle e permite deletar a pasta por completo.
  try { process.chdir(parentDir); } catch { /* se falhar, tenta assim mesmo */ }

  try { rmrf(agentDir); }
  catch (err) {
    const rmCmd = os.platform() === 'win32' ? `rd /s /q "${agentDir}"` : `rm -rf "${agentDir}"`;
    console.error(`\n❌ Erro: ${err.message}\n   Remova manualmente: ${rmCmd}\n`); process.exit(1);
  }

  if (fs.existsSync(agentDir)) {
    const rmCmd = os.platform() === 'win32' ? `rd /s /q "${agentDir}"` : `rm -rf "${agentDir}"`;
    console.error(`\n❌ Pasta ainda existe. Feche o editor e execute:\n   ${rmCmd}\n`); process.exit(1);
  }

  // Pasta removida com sucesso — limpa os rastros do auditor no .gitignore
  cleanGitignore(parentDir, path.basename(agentDir));

  console.log(`${line('═')}`);
  console.log('  ✅ project-auditor removido com sucesso!');
  console.log(`${line('═')}\n`);
  console.log(`  Removido : ${path.basename(agentDir)}/`);
  console.log(`  Intacto  : ${parentDir}\n`);
  process.exit(0);
}

main().catch(err => { console.error('\n❌ Erro inesperado:', err.message); process.exit(1); });
