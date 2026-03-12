'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

// ─── Caminhos candidatos por plataforma ──────────────────────────────────────

const CANDIDATES = {
  win32: [
    // Chrome estável
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    `${process.env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
    `${process.env.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`,
    // Chrome Canary
    `${process.env.LOCALAPPDATA}\\Google\\Chrome SxS\\Application\\chrome.exe`,
    // Edge (Chromium-based)
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    `${process.env.PROGRAMFILES}\\Microsoft\\Edge\\Application\\msedge.exe`,
    // Playwright cache Windows
    `${process.env.LOCALAPPDATA}\\ms-playwright\\chromium-1194\\chrome-win\\chrome.exe`,
    `${process.env.LOCALAPPDATA}\\ms-playwright\\chromium-1208\\chrome-win\\chrome.exe`,
    `${process.env.USERPROFILE}\\AppData\\Local\\ms-playwright\\chromium-1194\\chrome-win\\chrome.exe`,
  ],
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
    `${os.homedir()}/Applications/Google Chrome.app/Contents/MacOS/Google Chrome`,
    // Playwright cache macOS
    `${os.homedir()}/Library/Caches/ms-playwright/chromium-1194/chrome-mac/Chromium.app/Contents/MacOS/Chromium`,
    `${os.homedir()}/Library/Caches/ms-playwright/chromium-1208/chrome-mac/Chromium.app/Contents/MacOS/Chromium`,
  ],
  linux: [
    // Chrome / Chromium do sistema
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium',
    // Playwright cache Linux (várias versões)
    '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
    '/opt/pw-browsers/chromium-1208/chrome-linux/chrome',
    `${os.homedir()}/.cache/ms-playwright/chromium-1194/chrome-linux/chrome`,
    `${os.homedir()}/.cache/ms-playwright/chromium-1208/chrome-linux/chrome`,
  ],
};

// ─── Tenta encontrar via `which` / `where` ───────────────────────────────────

function findViaPath() {
  const { execSync } = require('child_process');
  const commands = os.platform() === 'win32'
    ? ['where chrome', 'where msedge', 'where chromium']
    : ['which google-chrome', 'which google-chrome-stable', 'which chromium', 'which chromium-browser'];

  for (const cmd of commands) {
    try {
      const result = execSync(cmd, { stdio: 'pipe', timeout: 2000 }).toString().trim().split('\n')[0];
      if (result && fs.existsSync(result)) return result;
    } catch { /* not found */ }
  }
  return null;
}

// ─── Tenta o executablePath padrão do Playwright (sem custom path) ────────────

async function tryPlaywrightDefault(chromium) {
  try {
    const browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
    const version = browser.version();
    await browser.close();
    return { works: true, version, executablePath: null }; // null = usa o default do Playwright
  } catch {
    return { works: false };
  }
}

// ─── Resolução principal ──────────────────────────────────────────────────────

async function resolve(chromium) {
  const platform = os.platform();

  // 1. Tenta primeiro o default do Playwright (já instalado via npx playwright install)
  const defaultTest = await tryPlaywrightDefault(chromium);
  if (defaultTest.works) {
    return { executablePath: null, source: 'Playwright default', version: defaultTest.version };
  }

  // 2. Busca via PATH do sistema
  const fromPath = findViaPath();
  if (fromPath) {
    return { executablePath: fromPath, source: `PATH (${fromPath})` };
  }

  // 3. Busca nos caminhos candidatos da plataforma
  const candidates = CANDIDATES[platform] || CANDIDATES.linux;
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) {
      return { executablePath: candidate, source: `encontrado em ${candidate}` };
    }
  }

  // 4. Não encontrou — retorna null com instruções
  return { executablePath: null, source: null };
}

// ─── Mensagem de instalação por plataforma ────────────────────────────────────

function installInstructions() {
  const platform = os.platform();
  const lines = [
    ``,
    `❌ Nenhum browser Chromium encontrado no sistema.`,
    ``,
    `   O módulo check:ui requer Chromium, Chrome ou Edge instalado.`,
    `   Escolha uma das opções abaixo:`,
    ``,
  ];

  if (platform === 'win32') {
    lines.push(`   Opção 1 — Instalar via Playwright (recomendado):`);
    lines.push(`     npx playwright install chromium`);
    lines.push(``);
    lines.push(`   Opção 2 — Instalar o Chrome:`);
    lines.push(`     https://www.google.com/chrome`);
    lines.push(``);
    lines.push(`   Opção 3 — Usar o Microsoft Edge (já vem no Windows 10/11)`);
    lines.push(`     O auditor detecta o Edge automaticamente.`);
  } else if (platform === 'darwin') {
    lines.push(`   Opção 1 — Instalar via Playwright (recomendado):`);
    lines.push(`     npx playwright install chromium`);
    lines.push(``);
    lines.push(`   Opção 2 — Instalar o Chrome:`);
    lines.push(`     https://www.google.com/chrome`);
  } else {
    lines.push(`   Opção 1 — Instalar via Playwright (recomendado):`);
    lines.push(`     npx playwright install chromium`);
    lines.push(``);
    lines.push(`   Opção 2 — Instalar via apt/snap:`);
    lines.push(`     sudo apt install chromium-browser`);
    lines.push(`     # ou`);
    lines.push(`     sudo snap install chromium`);
  }

  lines.push(``);
  lines.push(`   Após instalar, rode novamente: npm run check:ui`);
  lines.push(``);

  return lines.join('\n');
}

module.exports = { resolve, installInstructions };
