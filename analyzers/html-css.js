'use strict';

const fs   = require('fs');
const path = require('path');

// ─── Padrões HTML ─────────────────────────────────────────────────────────────

const HTML_SECURITY = [
  { regex: /<script[^>]*>[\s\S]*?(eval|document\.write|innerHTML\s*=)/gi,  severity: 'HIGH',    label: 'Script inline inseguro',             desc: 'Script inline com eval/document.write/innerHTML — mova para arquivo externo e sanitize.' },
  { regex: /<script[^>]+src=["']http:\/\//gi,                              severity: 'HIGH',    label: 'Script externo via HTTP',            desc: 'Script carregado via HTTP não criptografado — use HTTPS sempre.' },
  { regex: /<form[^>]*action=["'](?!https?:\/\/|\/|\#)[^"']+["']/gi,       severity: 'MEDIUM',  label: 'Form action relativo suspeito',       desc: 'action do formulário com path relativo não convencional — verifique o destino.' },
  { regex: /<form[^>]*method=["']get["'][^>]*>[\s\S]{0,500}(?:password|senha|token)/gi, severity: 'HIGH', label: 'Form GET com campo sensível', desc: 'Formulário GET com campo de senha/token — use POST para não expor dados na URL.' },
  { regex: /<input[^>]*type=["']password["'][^>]*(?!autocomplete)/gi,       severity: 'MEDIUM',  label: 'Input password sem autocomplete',    desc: 'Campo password sem autocomplete="off" ou "new-password" — navegadores podem armazenar.' },
  { regex: /<meta\s+http-equiv=["']refresh["']/gi,                          severity: 'MEDIUM',  label: 'Meta refresh',                       desc: 'Meta refresh pode ser usado para redirect attacks — prefira redirect HTTP 301/302.' },
  { regex: /on\w+\s*=\s*["'][^"']*["']/gi,                                  severity: 'MEDIUM',  label: 'Evento inline (on*=)',               desc: 'Handler de evento inline (onclick=, onload=) — mova para addEventListener no JS externo.' },
  { regex: /<iframe[^>]*(?!sandbox)/gi,                                     severity: 'MEDIUM',  label: 'iframe sem sandbox',                 desc: 'iframe sem atributo sandbox — adicione sandbox="allow-scripts allow-same-origin" conforme necessário.' },
  { regex: /<!--[\s\S]*?(?:password|token|secret|api.?key|TODO|FIXME)[\s\S]*?-->/gi, severity: 'HIGH', label: 'Comentário HTML com dado sensível', desc: 'Comentário HTML com informação sensível — comentários são visíveis no source da página.' },
  { regex: /<a[^>]+href=["']javascript:/gi,                                 severity: 'HIGH',    label: 'href com javascript:',               desc: 'javascript: URI em href — use addEventListener em vez disso.' },
  { regex: /document\.cookie(?!\s*===)/g,                                   severity: 'MEDIUM',  label: 'Acesso a document.cookie',           desc: 'Acesso manual a cookies via JS — prefira cookies HttpOnly gerenciados pelo servidor.' },
];

const HTML_PERFORMANCE = [
  { regex: /<script[^>]*>(?![\s\S]*<\/script>)/gi,                          severity: 'LOW',    label: 'Script inline extenso',              desc: 'Script inline grande — mova para arquivo externo para permitir cache do browser.' },
  { regex: /<link[^>]*rel=["']stylesheet["'][^>]*>(?![\s\S]{0,2000}<\/head>)/gi, severity: 'LOW', label: 'CSS carregado no body',            desc: 'Link de CSS fora do <head> — estilos devem ser carregados no <head> para evitar FOUC.' },
  { regex: /<img[^>]*(?!loading=["']lazy["'])[^>]*>/gi,                     severity: 'LOW',    label: 'img sem loading="lazy"',             desc: 'Imagens sem loading="lazy" — adicione para melhorar performance de carregamento.' },
  { regex: /<img[^>]*(?!alt=)[^>]*>/gi,                                     severity: 'LOW',    label: 'img sem alt',                        desc: 'Imagem sem atributo alt — necessário para acessibilidade e SEO.' },
  { regex: /style=["'][^"']{100,}["']/gi,                                   severity: 'LOW',    label: 'Estilo inline extenso',              desc: 'Estilo inline longo — mova para classe CSS para manutenibilidade e cache.' },
];

const HTML_FLOW = [
  { regex: /<meta\s+name=["']viewport["'](?![^>]*content)/gi,               severity: 'MEDIUM', label: 'Meta viewport sem content',          desc: 'Meta viewport sem atributo content — defina width=device-width,initial-scale=1.' },
  { regex: /<!DOCTYPE\s+html>/gi,                                           severity: 'LOW',    label: 'Sem DOCTYPE',                        desc: 'DOCTYPE não encontrado — pode causar modo quirks no browser.' },
  { regex: /<html(?![^>]*lang=)/gi,                                         severity: 'LOW',    label: '<html> sem lang',                    desc: '<html> sem atributo lang — importante para acessibilidade e leitores de tela.' },
  { regex: /<title>\s*<\/title>|<title>\s*(?:Untitled|New Page|Default)\s*<\/title>/gi, severity: 'LOW', label: 'Title vazio ou padrão',     desc: 'Tag <title> vazia ou com valor padrão — defina um título descritivo.' },
  { regex: /<form(?![^>]*action)/gi,                                        severity: 'MEDIUM', label: 'Form sem action',                    desc: 'Formulário sem action — dados serão enviados para a URL atual.' },
  { regex: /<input[^>]*type=["'](?:text|email|search)["'][^>]*(?!name=)[^>]*>/gi, severity: 'LOW', label: 'Input sem name',               desc: 'Input sem atributo name — não será incluído no submit do formulário.' },
];

// ─── Padrões CSS ──────────────────────────────────────────────────────────────

const CSS_PATTERNS = [
  { regex: /content\s*:\s*["'][^"']*(?:password|token|secret|api.?key)[^"']*["']/gi, severity: 'HIGH', label: 'Dado sensível em content CSS', desc: 'String sensível em propriedade content do CSS — visível no source da página.' },
  { regex: /url\s*\(\s*['"]?http:\/\//gi,                                   severity: 'MEDIUM', label: 'Resource HTTP em CSS',             desc: 'Recurso (imagem/fonte) carregado via HTTP — use HTTPS.' },
  { regex: /expression\s*\(/gi,                                             severity: 'HIGH',    label: 'CSS expression()',                 desc: 'CSS expression() é obsoleto e perigoso — não use (IE legacy).' },
  { regex: /-moz-binding\s*:/gi,                                            severity: 'HIGH',    label: '-moz-binding em CSS',             desc: '-moz-binding pode executar XBL scripts — remova.' },
  { regex: /behavior\s*:\s*url/gi,                                          severity: 'HIGH',    label: 'behavior:url em CSS',             desc: 'Propriedade behavior é IE-only e pode executar HTC scripts — remova.' },
  { regex: /!\s*important/g,                                                severity: 'LOW',     label: '!important excessivo',            desc: '!important dificulta manutenção — refatore a especificidade dos seletores.' },
];

function makeResult(filePath, line, severity, label, desc) {
  return { file: filePath, line, severity, label, description: desc };
}

function scanPatterns(text, patterns, filePath) {
  const results = [];
  const lines   = text.split('\n');
  for (const { regex, severity, label, desc } of patterns) {
    regex.lastIndex = 0;
    lines.forEach((lineText, idx) => {
      regex.lastIndex = 0;
      if (regex.test(lineText)) {
        results.push(makeResult(filePath, idx + 1, severity, label, desc));
      }
      regex.lastIndex = 0;
    });
  }
  return results;
}

// Verifica se CSP meta está presente no HTML
function checkCSPMeta(content, filePath) {
  const findings = [];
  const hasCSP = /<meta[^>]+http-equiv=["']Content-Security-Policy["']/i.test(content);
  const isFullPage = /<html|<!DOCTYPE/i.test(content);
  if (isFullPage && !hasCSP) {
    findings.push(makeResult(filePath, 1, 'MEDIUM', 'CSP meta ausente',
      'Nenhuma meta tag Content-Security-Policy encontrada — adicione para reduzir superfície de XSS.'));
  }
  return findings;
}

function analyzeFile(filePath) {
  const findings = [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return findings; }

  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.html' || ext === '.htm') {
    findings.push(...scanPatterns(content, HTML_SECURITY,    filePath));
    findings.push(...scanPatterns(content, HTML_PERFORMANCE, filePath));
    findings.push(...scanPatterns(content, HTML_FLOW,        filePath));
    findings.push(...checkCSPMeta(content, filePath));
  } else if (ext === '.css' || ext === '.scss' || ext === '.sass' || ext === '.less') {
    findings.push(...scanPatterns(content, CSS_PATTERNS, filePath));
  }

  return findings;
}

module.exports = { analyzeFile };
