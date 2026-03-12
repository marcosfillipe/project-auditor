#!/usr/bin/env node
'use strict';

/**
 * diagnose.js — Project Auditor Diagnostic Tool
 * Roda ANTES do uninstall para capturar o estado exato do ambiente.
 * Gera um arquivo diagnose-report-<timestamp>.txt na pasta temporária do SO
 * e mostra o caminho no final.
 *
 * Uso: node diagnose.js
 *  ou: npm run diagnose
 */

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const cp   = require('child_process');

const agentDir  = path.resolve(__dirname);
const parentDir = path.resolve(__dirname, '..');
const lines     = [];

function log(msg = '') { lines.push(msg); process.stdout.write(msg + '\n'); }
function sec(title)    { log(); log('═'.repeat(60)); log(`  ${title}`); log('═'.repeat(60)); }
function sub(title)    { log(); log(`── ${title}`); log('─'.repeat(40)); }

function run(cmd) {
  try {
    return cp.execSync(cmd, { encoding: 'utf8', timeout: 8000, windowsHide: true }).trim();
  } catch (e) {
    return `[ERRO: ${e.message.split('\n')[0]}]`;
  }
}

function tryRead(p) {
  try { return fs.readFileSync(p, 'utf8').trim(); }
  catch (e) { return `[não legível: ${e.code}]`; }
}

function fileInfo(p) {
  try {
    const s = fs.statSync(p);
    return `size=${s.size}  mode=${s.mode.toString(8)}  mtime=${s.mtime.toISOString()}`;
  } catch (e) { return `[${e.code}]`; }
}

function listDir(dir, depth = 0, maxDepth = 3) {
  if (depth > maxDepth) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch (e) { log(`${'  '.repeat(depth)}[ERRO lendo dir: ${e.code}]`); return; }
  for (const e of entries) {
    const p    = path.join(dir, e.name);
    const info = e.isDirectory() ? '' : `  (${fileInfo(p)})`;
    log(`${'  '.repeat(depth)}${e.isDirectory() ? '📁' : '📄'} ${e.name}${info}`);
    if (e.isDirectory() && depth < maxDepth) listDir(p, depth + 1, maxDepth);
  }
}

// ─────────────────────────────────────────────────────────────────────────────

sec('1. AMBIENTE');

log(`Timestamp   : ${new Date().toISOString()}`);
log(`Plataforma  : ${os.platform()} ${os.release()} (${os.arch()})`);
log(`Node.js     : ${process.version}`);
log(`npm         : ${run('npm --version')}`);
log(`CWD         : ${process.cwd()}`);
log(`__dirname   : ${agentDir}`);
log(`parentDir   : ${parentDir}`);
log(`TEMP/TMP    : ${os.tmpdir()}`);
log(`Usuário     : ${os.userInfo().username}`);
log(`Shell       : ${process.env.SHELL || process.env.ComSpec || 'desconhecido'}`);
log(`npm_execpath: ${process.env.npm_execpath || 'não definido'}`);
log(`npm_lifecycle: ${process.env.npm_lifecycle_event || 'não definido'}`);

// ─────────────────────────────────────────────────────────────────────────────

sec('2. ESTRUTURA DA PASTA DO AUDITOR');
log(`Raiz: ${agentDir}\n`);
listDir(agentDir, 0, 2);

// ─────────────────────────────────────────────────────────────────────────────

sec('3. CONTEÚDO DE .git/ (se existir)');
const gitDir = path.join(agentDir, '.git');
if (fs.existsSync(gitDir)) {
  log(`⚠️  .git/ PRESENTE — criado por git clone`);
  listDir(gitDir, 0, 2);

  sub('Permissões de arquivos críticos do .git/');
  const gitFiles = ['HEAD','config','index','packed-refs'];
  for (const f of gitFiles) {
    const p = path.join(gitDir, f);
    log(`  ${f}: ${fileInfo(p)}`);
  }

  sub('Objetos em .git/objects/ (primeiros 10)');
  const objDir = path.join(gitDir, 'objects');
  if (fs.existsSync(objDir)) {
    let count = 0;
    function walkObjs(d) {
      if (count >= 10) return;
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (count >= 10) break;
        const p = path.join(d, e.name);
        if (e.isFile()) { log(`  ${p}: ${fileInfo(p)}`); count++; }
        else if (e.isDirectory()) walkObjs(p);
      }
    }
    try { walkObjs(objDir); } catch {}
  }
} else {
  log('✅ .git/ NÃO presente');
}

// ─────────────────────────────────────────────────────────────────────────────

sec('4. HANDLES / PROCESSOS COM LOCK NA PASTA (Windows)');
if (os.platform() === 'win32') {
  sub('Processos node.exe ativos');
  log(run('tasklist /FI "IMAGENAME eq node.exe" /FO LIST'));

  sub('Processos npm.cmd / cmd.exe ativos');
  log(run('tasklist /FI "IMAGENAME eq cmd.exe" /FO LIST'));

  sub('Handle aberto na pasta (via handle.exe, se disponível)');
  // handle.exe é da Sysinternals — pode não estar instalado
  const handlePath = run('where handle.exe 2>nul');
  if (!handlePath.startsWith('[')) {
    log(run(`handle.exe "${agentDir}" /accepteula`));
  } else {
    log('[handle.exe não encontrado — instale Sysinternals para ver locks exatos]');
    log('Download: https://learn.microsoft.com/sysinternals/downloads/handle');
  }

  sub('Tentativa de rename da pasta (testa se lock existe)');
  const testRename = path.join(parentDir, `_diag-rename-test-${Date.now()}`);
  try {
    fs.renameSync(agentDir, testRename);
    log(`✅ renameSync FUNCIONOU → pasta renomeada para ${path.basename(testRename)}`);
    log('   (rename revertido para continuar o diagnóstico)');
    fs.renameSync(testRename, agentDir);
    log(`✅ rename revertido com sucesso`);
  } catch (e) {
    log(`❌ renameSync FALHOU: ${e.code} — ${e.message}`);
    log('   → Este é o lock que impede a remoção');
  }

  sub('Tentativa de criar arquivo dentro da pasta (testa acesso de escrita)');
  const testFile = path.join(agentDir, `_diag-write-test-${Date.now()}.tmp`);
  try {
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    log('✅ writeFileSync dentro da pasta: OK');
  } catch (e) {
    log(`❌ writeFileSync FALHOU: ${e.code} — ${e.message}`);
  }

  sub('Tentativa de rmdir na pasta (testa se está vazia e desbloqueada)');
  const emptyTestDir = path.join(agentDir, `_diag-rmdir-test-${Date.now()}`);
  try {
    fs.mkdirSync(emptyTestDir);
    fs.rmdirSync(emptyTestDir);
    log('✅ mkdirSync + rmdirSync de subpasta: OK');
  } catch (e) {
    log(`❌ rmdir de subpasta FALHOU: ${e.code} — ${e.message}`);
  }

  sub('Atributos da pasta do auditor (attrib)');
  log(run(`attrib "${agentDir}"`));

  sub('Atributos de node_modules\\.bin (onde npm mantém handles)');
  const binDir = path.join(agentDir, 'node_modules', '.bin');
  if (fs.existsSync(binDir)) {
    log(run(`attrib "${binDir}\\*"`));
  } else {
    log('[node_modules/.bin não existe]');
  }

} else {
  log('(plataforma não-Windows — locks via lsof)');
  sub('Processos com handle na pasta (lsof)');
  log(run(`lsof +D "${agentDir}" 2>/dev/null | head -30`));
}

// ─────────────────────────────────────────────────────────────────────────────

sec('5. package.json DO AUDITOR');
log(tryRead(path.join(agentDir, 'package.json')));

// ─────────────────────────────────────────────────────────────────────────────

sec('6. .gitignore DO PROJETO PAI');
const giPath = path.join(parentDir, '.gitignore');
if (fs.existsSync(giPath)) {
  log(`Caminho: ${giPath}`);
  log(tryRead(giPath));
} else {
  log('[.gitignore não encontrado no projeto pai]');
}

// ─────────────────────────────────────────────────────────────────────────────

sec('7. SIMULAÇÃO DO PROCESSO DE REMOÇÃO');

sub('process.chdir para o pai');
try {
  process.chdir(parentDir);
  log(`✅ chdir para ${parentDir}: OK`);
  log(`   CWD atual: ${process.cwd()}`);
} catch (e) {
  log(`❌ chdir FALHOU: ${e.message}`);
}

sub('fs.rmSync simulado em arquivo de teste');
const rmTestFile = path.join(agentDir, `_diag-rm-test-${Date.now()}.tmp`);
try {
  // Recria o agentDir se o chdir causou algum problema
  if (!fs.existsSync(agentDir)) {
    log('[agentDir não existe mais após chdir — skip rmSync test]');
  } else {
    fs.writeFileSync(rmTestFile, 'test');
    fs.rmSync(rmTestFile, { force: true });
    log('✅ rmSync de arquivo de teste: OK');
  }
} catch (e) {
  log(`❌ rmSync de arquivo de teste FALHOU: ${e.code} — ${e.message}`);
}

// ─────────────────────────────────────────────────────────────────────────────

sec('8. VARIÁVEIS DE AMBIENTE RELEVANTES');
const relevantEnvKeys = [
  'PATH','PATHEXT','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP',
  'ComSpec','SystemRoot','npm_config_prefix','npm_execpath',
  'npm_lifecycle_event','npm_lifecycle_script','npm_config_cache',
];
for (const k of relevantEnvKeys) {
  if (process.env[k]) log(`${k.padEnd(25)}: ${process.env[k]}`);
}

// ─────────────────────────────────────────────────────────────────────────────

sec('FIM DO DIAGNÓSTICO');

const outPath = path.join(os.tmpdir(), `auditor-diagnose-${Date.now()}.txt`);
try {
  fs.writeFileSync(outPath, lines.join('\n'), 'utf8');
  log('');
  log(`📋 Relatório salvo em:`);
  log(`   ${outPath}`);
  log('');
  log('   Envie este arquivo para análise do problema de remoção.');
} catch (e) {
  log(`\n[Não foi possível salvar o relatório: ${e.message}]`);
  log('Copie a saída do terminal acima manualmente.');
}
