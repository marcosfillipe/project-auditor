'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    // SSR data leaks
    { regex: /getServerSideProps[^}]+process\.env\.(?!NEXT_PUBLIC_)\w+/g,  severity: 'CRITICAL', desc: 'Variável de ambiente privada retornada em getServerSideProps — exposta ao cliente' },
    { regex: /getStaticProps[^}]+process\.env\.(?!NEXT_PUBLIC_)\w+/g,      severity: 'HIGH',     desc: 'Variável de ambiente privada em getStaticProps — pode vazar no bundle estático' },
    { regex: /return\s*\{\s*props\s*:\s*\{[^}]*password[^}]*\}/gi,         severity: 'CRITICAL', desc: 'Campo "password" retornado como prop SSR — exposição direta ao cliente' },
    { regex: /return\s*\{\s*props\s*:\s*\{[^}]*secret[^}]*\}/gi,           severity: 'HIGH',     desc: 'Campo "secret" retornado como prop SSR' },
    // API routes
    { regex: /export\s+default\s+function\s+handler[^}]+req\.method(?!.*!==|.*===)/g, severity: 'MEDIUM', desc: 'API route sem validação de método HTTP' },
    { regex: /req\.body\.\w+(?!\s*&&|\s*\?\?|\s*\|\|)/g,                   severity: 'MEDIUM',   desc: 'req.body usado sem validação em API route' },
    { regex: /dangerouslySetInnerHTML/g,                                    severity: 'HIGH',     desc: 'dangerouslySetInnerHTML — verifique sanitização' },
    { regex: /process\.env\.(?!NEXT_PUBLIC_)\w+(?=[^}]*return|[^}]*res\.json)/g, severity: 'HIGH', desc: 'Env privada enviada na resposta da API route' },
  ],
  performance: [
    { regex: /import\s+Image\s+from\s+'next\/image'(?!)/g,                 severity: 'INFO',     desc: 'next/image detectado — verifique se priority está em imagens above-the-fold' },
    { regex: /<img\s+(?!.*next\/image)/g,                                   severity: 'MEDIUM',   desc: '<img> nativo em vez de next/image — perde otimização automática' },
    { regex: /useEffect\s*\(\s*\(\s*\)\s*=>/g,                             severity: 'MEDIUM',   desc: 'useEffect sem array de dependências — executa em todo render' },
    { regex: /getServerSideProps(?![^}]*revalidate)/g,                      severity: 'LOW',      desc: 'getServerSideProps sem revalidate — considere ISR (getStaticProps + revalidate)' },
    { regex: /fetch\s*\(.*\)(?!.*cache|.*revalidate)/g,                    severity: 'LOW',      desc: 'fetch() sem opções de cache — considere { next: { revalidate } }' },
  ],
  flow: [
    { regex: /router\.push\s*\([^)]*req\.(query|params|body)/g,            severity: 'HIGH',     desc: 'Redirect com dados do usuário — risco de open redirect' },
    { regex: /cookies\s*\(\s*\)\s*\.set\s*\([^)]*(?!.*httpOnly)/g,        severity: 'MEDIUM',   desc: 'Cookie definido sem httpOnly — vulnerável a XSS' },
    { regex: /headers\s*\(\s*\)\s*\.get\s*\(\s*['"]authorization['"]\s*\)(?![^}]*verify)/g, severity: 'MEDIUM', desc: 'Header Authorization lido sem verificação visível do token' },
    { regex: /\/\/\s*TODO|\/\/\s*FIXME/gi,                                 severity: 'LOW',      desc: 'Débito técnico marcado' },
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
          findings.push({ severity, label: `Next.js/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];

  // next.config.js
  const nextCfg = ['next.config.js','next.config.mjs','next.config.ts']
    .map(f => path.join(projectRoot, f)).find(fs.existsSync);

  if (nextCfg) {
    const cfg = fs.readFileSync(nextCfg, 'utf8');
    if (/headers\s*:\s*\(\s*\)\s*=>/.test(cfg) === false)
      issues.push({ severity: 'MEDIUM', label: 'Next.js/Config', description: 'next.config.js sem configuração de headers de segurança (X-Frame-Options, CSP, etc).', file: nextCfg });
    if (/reactStrictMode\s*:\s*false/.test(cfg))
      issues.push({ severity: 'MEDIUM', label: 'Next.js/Config', description: 'reactStrictMode: false desativa avisos de boas práticas do React.', file: nextCfg });
    if (/eslint\s*:\s*\{[^}]*ignoreDuringBuilds\s*:\s*true/.test(cfg))
      issues.push({ severity: 'MEDIUM', label: 'Next.js/Config', description: 'ESLint ignorado durante build — erros de qualidade não bloqueiam deploy.', file: nextCfg });
  }

  // Pasta pages/api ou app/api sem middleware de auth
  const apiDir = [
    path.join(projectRoot, 'pages', 'api'),
    path.join(projectRoot, 'src', 'pages', 'api'),
    path.join(projectRoot, 'app', 'api'),
  ].find(fs.existsSync);

  if (apiDir) {
    const middlewarePath = [
      path.join(projectRoot, 'middleware.ts'),
      path.join(projectRoot, 'middleware.js'),
    ].find(fs.existsSync);
    if (!middlewarePath)
      issues.push({ severity: 'MEDIUM', label: 'Next.js/Config', description: 'API routes detectadas mas nenhum middleware.ts encontrado — rotas podem estar sem autenticação centralizada.', file: apiDir });
  }

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
