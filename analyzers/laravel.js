'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    // SQL Injection
    { regex: /DB::(?:select|statement|insert|update|delete)\s*\(\s*["'`][^"'`]*\.\s*\$/g, severity: 'CRITICAL', desc: 'DB::query() com concatenação — use bindings: DB::select("... WHERE id = ?", [$id])' },
    { regex: /->whereRaw\s*\(\s*["'`][^"'`]*\.\s*\$/g,                 severity: 'CRITICAL', desc: 'whereRaw() com concatenação — SQL injection no Eloquent' },
    { regex: /->selectRaw\s*\(\s*["'`][^"'`]*\.\s*\$/g,                severity: 'HIGH',     desc: 'selectRaw() com variável direta — use bindings' },
    // Mass Assignment
    { regex: /\$fillable\s*=\s*\[\s*\]/g,                              severity: 'HIGH',     desc: '$fillable vazio — mass assignment bloqueado, mas revise se correto' },
    { regex: /\$guarded\s*=\s*\[\s*\]/g,                               severity: 'CRITICAL', desc: '$guarded = [] — todos os campos são mass assignable, risco de privilege escalation' },
    { regex: /Model::create\s*\(\s*\$request->all\s*\(\s*\)\s*\)/g,   severity: 'HIGH',     desc: 'create($request->all()) sem whitelist — mass assignment com todos os dados do request' },
    { regex: /->fill\s*\(\s*\$request->all\s*\(\s*\)\s*\)/g,          severity: 'HIGH',     desc: '->fill($request->all()) sem filtro — mass assignment' },
    // XSS / Output
    { regex: /\{!!\s*\$/g,                                             severity: 'HIGH',     desc: '{!! $var !!} em Blade — HTML sem escape, verifique sanitização' },
    // Auth / CSRF
    { regex: /Route::\w+\s*\([^)]+\)\s*->withoutMiddleware\s*\(['"](?:auth|csrf)/g, severity: 'HIGH', desc: 'Rota removendo middleware de auth/CSRF — verifique se intencional' },
    { regex: /VerifyCsrfToken[^}]+except\s*=\s*\[['"][^'"]+['"]\]/g,  severity: 'MEDIUM',   desc: 'CSRF desativado para rotas específicas — confirme se necessário' },
    // Secrets
    { regex: /(?:password|secret|api_key)\s*=\s*['"][^'"]{4,}['"]/gi, severity: 'HIGH',     desc: 'Credencial hardcoded — use config() + variável de ambiente' },
  ],
  performance: [
    { regex: /::all\s*\(\s*\)(?!\s*->\s*(?:take|limit|paginate|chunk))/g, severity: 'HIGH', desc: 'Model::all() sem paginação/limite — carrega toda a tabela em memória' },
    { regex: /->get\s*\(\s*\)(?!\s*->\s*(?:take|paginate))/g,         severity: 'MEDIUM',   desc: '->get() sem limit/paginate — verifique se resultado pode ser muito grande' },
    { regex: /foreach\s*\([^)]+\)[^{]*\{[^}]*->\s*(?:find|first|where)\s*\(/g, severity: 'MEDIUM', desc: 'Query Eloquent dentro de loop — padrão N+1, use eager loading (with())' },
    { regex: /->with\s*\(\s*\)\s*->/g,                                severity: 'LOW',      desc: '->with() vazio — eager loading sem relacionamentos definidos' },
  ],
  flow: [
    { regex: /catch\s*\(\s*\\?Exception\s+\$\w+\s*\)\s*\{\s*\}/g,    severity: 'HIGH',     desc: 'Catch vazio de Exception — erros silenciados' },
    { regex: /->orWhere\s*\(\s*['"][^'"]+['"]\s*,\s*\$_/g,           severity: 'HIGH',     desc: 'orWhere com superglobal PHP — SQL injection' },
    { regex: /Storage::disk\s*\(\s*['"]public['"]\s*\)\s*->put\s*\(\s*\$request/g, severity: 'MEDIUM', desc: 'Upload de arquivo com nome do request — valide tipo e gere nome aleatório' },
    { regex: /redirect\s*\(\s*\$request->(?:get|input)\s*\(/g,        severity: 'HIGH',     desc: 'Redirect com input do usuário — open redirect' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                            severity: 'LOW',      desc: 'Débito técnico marcado' },
  ],
};

function analyzeFile(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const lines = src.split('\n');
  const findings = [];

  for (const [label, patterns] of Object.entries(PATTERNS)) {
    for (const { regex, severity, desc } of patterns) {
      lines.forEach((line, i) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ severity, label: `Laravel/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];

  // .env exposto?
  const envExample = path.join(projectRoot, '.env.example');
  const envFile    = path.join(projectRoot, '.env');
  const gitignore  = path.join(projectRoot, '.gitignore');

  if (fs.existsSync(envFile) && fs.existsSync(gitignore)) {
    const gi = fs.readFileSync(gitignore, 'utf8');
    if (!gi.includes('.env'))
      issues.push({ severity: 'CRITICAL', label: 'Laravel/Config', description: '.env não está no .gitignore — credenciais do banco podem ser commitadas.', file: gitignore });
  }

  // config/app.php
  const appConfig = path.join(projectRoot, 'config', 'app.php');
  if (fs.existsSync(appConfig)) {
    const cfg = fs.readFileSync(appConfig, 'utf8');
    if (/'debug'\s*=>\s*true/.test(cfg))
      issues.push({ severity: 'HIGH', label: 'Laravel/Config', description: "'debug' => true no config/app.php — stack traces expostos ao usuário.", file: appConfig });
  }

  // routes/web.php sem middleware auth
  const webRoutes = path.join(projectRoot, 'routes', 'web.php');
  if (fs.existsSync(webRoutes)) {
    const routes = fs.readFileSync(webRoutes, 'utf8');
    if (!/middleware\s*\(\s*['"]auth['"]\s*\)/g.test(routes))
      issues.push({ severity: 'MEDIUM', label: 'Laravel/Config', description: 'routes/web.php sem middleware auth detectado — verifique se rotas protegidas estão agrupadas.', file: webRoutes });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
