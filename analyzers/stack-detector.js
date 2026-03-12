'use strict';
/**
 * stack-detector.js
 * Detecta quais stacks/frameworks o projeto usa e retorna:
 * - quais analyzers de framework chamar
 * - quais extensões de arquivo scanear
 * - quais diretórios pular
 */

const fs   = require('fs');
const path = require('path');

// Extensões por stack
const EXT_MAP = {
  js:        ['.js', '.jsx', '.mjs', '.cjs'],
  ts:        ['.ts', '.tsx'],
  vue:       ['.vue'],
  svelte:    ['.svelte'],
  html:      ['.html', '.htm', '.css'],
  python:    ['.py'],
  php:       ['.php'],
};

// Detecção por package.json deps
const PKG_SIGNALS = {
  vue:       ['vue', '@vue/core'],
  angular:   ['@angular/core'],
  nextjs:    ['next'],
  svelte:    ['svelte', '@sveltejs/kit'],
  fastify:   ['fastify'],
  nestjs:    ['@nestjs/core'],
  prisma:    ['@prisma/client', 'prisma'],
  typeorm:   ['typeorm', 'sequelize'],
};

// Detecção por arquivos/pastas presentes
const FILE_SIGNALS = {
  nextjs:    ['next.config.js','next.config.mjs','next.config.ts','pages','app/layout.tsx','app/layout.jsx'],
  angular:   ['angular.json','.angular'],
  vue:       ['vue.config.js','nuxt.config.ts','nuxt.config.js'],
  svelte:    ['svelte.config.js','svelte.config.ts'],
  wordpress: ['wp-config.php','wp-includes','wp-content'],
  laravel:   ['artisan','app/Http/Controllers','config/app.php'],
  python:    ['requirements.txt','manage.py','app.py','main.py','pyproject.toml'],
  nestjs:    ['nest-cli.json'],
  prisma:    ['prisma/schema.prisma','schema.prisma'],
  typeorm:   ['ormconfig.js','ormconfig.json','ormconfig.ts'],
};

function detect(projectRoot) {
  const detected = new Set();

  // --- Via package.json ---
  const pkgPath = path.join(projectRoot, 'package.json');
  let deps = {};
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      deps = { ...pkg.dependencies, ...pkg.devDependencies };
    } catch {}
  }
  for (const [stack, pkgs] of Object.entries(PKG_SIGNALS)) {
    if (pkgs.some(p => deps[p])) detected.add(stack);
  }

  // --- Via arquivos/pastas ---
  for (const [stack, files] of Object.entries(FILE_SIGNALS)) {
    if (files.some(f => fs.existsSync(path.join(projectRoot, f)))) detected.add(stack);
  }

  // --- Se tem deps JS mas não foi categorizado → Express/generic Node ---
  if (Object.keys(deps).length > 0 && !detected.has('nextjs') && !detected.has('nestjs') && !detected.has('fastify')) {
    detected.add('node');
  }

  // --- Presença de .py → Python ---
  try {
    const entries = fs.readdirSync(projectRoot);
    if (entries.some(f => f.endsWith('.py'))) detected.add('python');
    if (entries.some(f => f.endsWith('.php'))) {
      detected.add('php');
      // Distingue WordPress de Laravel
      if (!detected.has('wordpress') && !detected.has('laravel')) {
        if (fs.existsSync(path.join(projectRoot, 'wp-config.php'))) detected.add('wordpress');
        else if (fs.existsSync(path.join(projectRoot, 'artisan')))  detected.add('laravel');
        else detected.add('php_generic');
      }
    }
    if (entries.some(f => f.endsWith('.html') || f.endsWith('.htm'))) detected.add('html');
    if (entries.some(f => f.endsWith('.css')))  detected.add('html'); // trata CSS junto com HTML
    if (entries.some(f => f.endsWith('.vue')))  detected.add('vue');
    if (entries.some(f => f.endsWith('.svelte'))) detected.add('svelte');
  } catch {}

  // Resolve extensões a escanear
  const extensions = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs']); // sempre
  if (detected.has('vue'))     EXT_MAP.vue.forEach(e => extensions.add(e));
  if (detected.has('svelte'))  EXT_MAP.svelte.forEach(e => extensions.add(e));
  if (detected.has('html'))    EXT_MAP.html.forEach(e => extensions.add(e));
  if (detected.has('python'))  EXT_MAP.python.forEach(e => extensions.add(e));
  if (detected.has('php') || detected.has('wordpress') || detected.has('laravel')) {
    EXT_MAP.php.forEach(e => extensions.add(e));
  }

  return {
    stacks: [...detected],
    extensions: [...extensions],
  };
}

module.exports = { detect };
