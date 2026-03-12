'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    { regex: /<script[^>]*src\s*=\s*["']http:\/\//gi,                    severity: 'HIGH',   desc: 'Script carregado via HTTP (não HTTPS) — sujeito a MITM' },
    { regex: /<script(?![^>]*src)[^>]*>[^<]{5,}/gi,                       severity: 'MEDIUM', desc: 'Script inline — dificulta CSP e aumenta superfície de XSS' },
    { regex: /on\w+\s*=\s*["'][^"']+["']/gi,                             severity: 'MEDIUM', desc: 'Handler de evento inline (onclick, onload, etc) — prefira addEventListener' },
    { regex: /<form[^>]*action\s*=\s*["'](?!https?:\/\/)[^"']*["'][^>]*method\s*=\s*["']get["']/gi, severity: 'MEDIUM', desc: 'Form GET com action — dados aparecem na URL' },
    { regex: /autocomplete\s*=\s*["']on["'][^>]*(?:password|secret|card)/gi, severity: 'HIGH', desc: 'autocomplete="on" em campo sensível — senha pode ser salva pelo browser' },
    { regex: /<input[^>]*type\s*=\s*["']password["'][^>]*(?!autocomplete)/gi, severity: 'MEDIUM', desc: 'Campo password sem autocomplete definido explicitamente' },
    { regex: /<!--[^>]*(?:password|token|secret|api.?key|todo|fixme)[^>]*-->/gi, severity: 'HIGH', desc: 'Comentário HTML com dado sensível ou débito técnico — visível no fonte' },
    { regex: /<meta[^>]*http-equiv\s*=\s*["']refresh["']/gi,             severity: 'LOW',    desc: 'Meta refresh — redireciona usuário automaticamente, pode ser explorado' },
  ],
  performance: [
    { regex: /<link[^>]*rel\s*=\s*["']stylesheet["'][^>]*>(?!.*<\/head>)/gi, severity: 'LOW', desc: 'CSS carregado fora do <head> — bloqueia renderização' },
    { regex: /<script[^>]*src[^>]*>(?!.*defer|.*async)/gi,               severity: 'MEDIUM', desc: 'Script sem defer ou async — bloqueia parsing do HTML' },
    { regex: /<img[^>]*(?!loading\s*=\s*["']lazy["'])[^>]*>/gi,          severity: 'LOW',    desc: '<img> sem loading="lazy" — todas as imagens carregadas imediatamente' },
    { regex: /<img[^>]*(?!alt\s*=)[^>]*>/gi,                             severity: 'LOW',    desc: '<img> sem atributo alt — acessibilidade e SEO prejudicados' },
    { regex: /style\s*=\s*["'][^"']{100,}["']/gi,                        severity: 'LOW',    desc: 'Estilo inline longo — mova para classe CSS para melhor manutenção' },
  ],
  flow: [
    { regex: /<form[^>]*>(?![\s\S]*<input[^>]*type\s*=\s*["']submit["'])/gi, severity: 'LOW', desc: 'Form sem botão submit visível' },
    { regex: /<a[^>]*href\s*=\s*["']javascript:/gi,                      severity: 'HIGH',   desc: 'href="javascript:" — use botão ou addEventListener' },
    { regex: /<iframe[^>]*(?!sandbox)[^>]*>/gi,                          severity: 'MEDIUM', desc: '<iframe> sem atributo sandbox — restringe comportamento do conteúdo embutido' },
    { regex: /<input[^>]*type\s*=\s*["']hidden["'][^>]*value\s*=\s*["'][^"']{5,}["']/gi, severity: 'MEDIUM', desc: 'Input hidden com valor visível no fonte — não use para dados sensíveis' },
  ],
};

// CSS-específico
const CSS_PATTERNS = [
  { regex: /url\s*\(\s*['"]?http:\/\//gi,   severity: 'MEDIUM', desc: 'Recurso CSS carregado via HTTP — sujeito a MITM' },
  { regex: /content\s*:\s*["'][^"']*(?:expression|javascript:)[^"']*["']/gi, severity: 'HIGH', desc: 'CSS com expression() ou javascript: — pode executar código em browsers antigos' },
];

function analyzeFile(filePath) {
  let src;
  try { src = fs.readFileSync(filePath, 'utf8'); } catch { return []; }
  const ext = path.extname(filePath).toLowerCase();
  const lines = src.split('\n');
  const findings = [];

  const patterns = ext === '.css'
    ? { css: CSS_PATTERNS }
    : PATTERNS;

  for (const [label, patList] of Object.entries(patterns)) {
    const list = Array.isArray(patList) ? patList : patList;
    for (const { regex, severity, desc } of (Array.isArray(patList) ? patList : Object.values(patList).flat())) {
      lines.forEach((line, i) => {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ severity, label: `HTML-CSS/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];
  // Verifica se existe algum arquivo HTML com <meta charset>
  const indexHtml = path.join(projectRoot, 'index.html');
  if (fs.existsSync(indexHtml)) {
    const src = fs.readFileSync(indexHtml, 'utf8');
    if (!/<meta[^>]*charset/i.test(src))
      issues.push({ severity: 'LOW', label: 'HTML/Config', description: 'index.html sem <meta charset> — pode causar problemas de encoding.', file: indexHtml });
    if (!/<meta[^>]*viewport/i.test(src))
      issues.push({ severity: 'LOW', label: 'HTML/Config', description: 'index.html sem <meta viewport> — layout mobile pode quebrar.', file: indexHtml });
    if (!/<meta[^>]*Content-Security-Policy|Content-Security-Policy/i.test(src))
      issues.push({ severity: 'MEDIUM', label: 'HTML/Config', description: 'Nenhuma Content-Security-Policy via meta tag detectada no HTML.', file: indexHtml });
  }
  return issues;
}

module.exports = { analyzeFile, analyzeProject };
