#!/usr/bin/env node
'use strict';

/**
 * uninstall-run.js — Launcher do desinstalador
 *
 * Problema no Windows: quando o usuário roda "npm run uninstall" de dentro
 * de project-auditor/, o terminal tem essa pasta como CWD. O Windows bloqueia
 * rmdir de qualquer pasta que seja CWD de um processo vivo.
 *
 * Solução: este launcher usa child_process.spawnSync para executar o
 * uninstall.js com cwd explicitamente definido como o diretório PAI —
 * independente de onde o npm foi chamado.
 * O spawnSync herda stdio (terminal interativo funciona normalmente).
 */

const cp   = require('child_process');
const path = require('path');
const os   = require('os');

const agentDir  = path.resolve(__dirname);
const parentDir = path.resolve(__dirname, '..');
const args      = process.argv.slice(2); // passa --yes etc adiante

const result = cp.spawnSync(
  process.execPath,
  [path.join(agentDir, 'uninstall.js'), ...args],
  {
    cwd:   parentDir,   // <-- CWD = projeto pai, nunca project-auditor/
    stdio: 'inherit',   // terminal interativo funciona normalmente
    env:   process.env,
  }
);

process.exit(result.status ?? 1);
