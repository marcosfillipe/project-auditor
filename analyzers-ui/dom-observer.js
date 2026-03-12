'use strict';

// ─── Padrões sensíveis para busca no DOM ──────────────────────────────────────

const SENSITIVE_DOM_PATTERNS = [
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i, label: 'Email visível no DOM',        severity: 'LOW'      },
  { regex: /\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/,                  label: 'CPF exposto no DOM',          severity: 'HIGH'     },
  { regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/,       label: 'Número de cartão no DOM',     severity: 'CRITICAL' },
  { regex: /password['":\s]+[^\s<"']{4,}/i,                      label: 'Senha exposta no DOM',        severity: 'CRITICAL' },
  { regex: /api[_-]?key['":\s]+[A-Za-z0-9_-]{12,}/i,            label: 'API Key exposta no DOM',      severity: 'CRITICAL' },
  { regex: /token['":\s]+[A-Za-z0-9._-]{20,}/i,                  label: 'Token exposto no DOM',        severity: 'HIGH'     },
  { regex: /secret['":\s]+[A-Za-z0-9_-]{8,}/i,                  label: 'Secret exposto no DOM',       severity: 'HIGH'     },
  { regex: /Bearer\s+[A-Za-z0-9._-]{20,}/,                      label: 'Bearer token visível no DOM', severity: 'HIGH'     },
];

// ─── Padrões no localStorage / sessionStorage ─────────────────────────────────

const SENSITIVE_STORAGE_KEYS = [
  { regex: /password|passwd|senha/i, label: 'Senha no Storage',    severity: 'CRITICAL' },
  { regex: /token|jwt|auth/i,        label: 'Token no Storage',    severity: 'HIGH'     },
  { regex: /secret|private/i,        label: 'Secret no Storage',   severity: 'HIGH'     },
  { regex: /credit|card|cvv|cvc/i,   label: 'Dados de cartão no Storage', severity: 'CRITICAL' },
  { regex: /ssn|cpf|rg\b/i,          label: 'Documento pessoal no Storage', severity: 'HIGH' },
  { regex: /api[_-]?key/i,           label: 'API Key no Storage',  severity: 'CRITICAL' },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeResult(label, severity, status, detail, location = null) {
  return { label, severity, status, detail, location };
}

// ─── Análise do DOM ───────────────────────────────────────────────────────────

async function analyzeDOMContent(page, url) {
  const findings = [];

  // Extrai conteúdo visível e atributos do DOM
  const domData = await page.evaluate(() => {
    // Texto visível
    const text = document.body.innerText || '';

    // Todos os atributos data-* e value em inputs
    const inputs = Array.from(document.querySelectorAll('input')).map(el => ({
      name:  el.name || el.id || '',
      type:  el.type,
      value: el.value,
    })).filter(i => i.value && i.type !== 'password');

    // window.__INITIAL_STATE__ ou globals injetados pelo servidor
    const globals = Object.keys(window).filter(k =>
      /state|data|config|user|auth|token/i.test(k) &&
      typeof window[k] === 'object' &&
      window[k] !== null
    ).map(k => {
      try { return { key: k, json: JSON.stringify(window[k]).substring(0, 500) }; }
      catch { return null; }
    }).filter(Boolean);

    // Comentários HTML
    const walker = document.createTreeWalker(document, NodeFilter.SHOW_COMMENT);
    const comments = [];
    let node;
    while ((node = walker.nextNode())) comments.push(node.nodeValue.trim());

    return { text, inputs, globals, comments };
  });

  // Verifica texto visível do DOM
  for (const pattern of SENSITIVE_DOM_PATTERNS) {
    if (pattern.regex.test(domData.text)) {
      findings.push(makeResult(
        pattern.label,
        pattern.severity,
        'warn',
        `Padrão sensível detectado no texto visível da página ${url}. Verifique se o dado deveria estar exposto.`,
        url
      ));
    }
  }

  // Verifica valores em inputs visíveis
  for (const input of domData.inputs) {
    for (const pattern of SENSITIVE_DOM_PATTERNS) {
      if (pattern.regex.test(input.value)) {
        findings.push(makeResult(
          `${pattern.label} em campo de formulário`,
          pattern.severity,
          'fail',
          `Campo "${input.name}" (${input.type}) contém dado sensível pré-preenchido no DOM.`,
          url
        ));
      }
    }
  }

  // Verifica globals do window
  for (const glob of domData.globals) {
    for (const pattern of SENSITIVE_DOM_PATTERNS) {
      if (pattern.regex.test(glob.json)) {
        findings.push(makeResult(
          `${pattern.label} em window.${glob.key}`,
          pattern.severity,
          'fail',
          `Objeto global window.${glob.key} contém dado sensível exposto ao JS do cliente.`,
          url
        ));
      }
    }
  }

  // Verifica comentários HTML
  for (const comment of domData.comments) {
    for (const pattern of SENSITIVE_DOM_PATTERNS) {
      if (pattern.regex.test(comment)) {
        findings.push(makeResult(
          `${pattern.label} em comentário HTML`,
          'HIGH',
          'fail',
          `Comentário HTML contém dado sensível: "${comment.substring(0, 80)}"`,
          url
        ));
      }
    }
    // Comentários com dicas de debug/infra
    if (/TODO|FIXME|password|secret|api[_-]?key|debug/i.test(comment)) {
      findings.push(makeResult(
        'Comentário HTML com informação sensível',
        'MEDIUM',
        'warn',
        `Comentário HTML potencialmente informativo: "${comment.substring(0, 100)}"`,
        url
      ));
    }
  }

  return findings;
}

// ─── Análise de Storage ───────────────────────────────────────────────────────

async function analyzeStorage(page, url) {
  const findings = [];

  const storageData = await page.evaluate(() => {
    const local   = { ...localStorage };
    const session = { ...sessionStorage };
    return { local, session };
  });

  for (const [key, value] of Object.entries(storageData.local)) {
    for (const pattern of SENSITIVE_STORAGE_KEYS) {
      if (pattern.regex.test(key) || pattern.regex.test(value)) {
        findings.push(makeResult(
          pattern.label,
          pattern.severity,
          'fail',
          `localStorage["${key}"] contém dado sensível — use cookies HttpOnly gerenciados pelo servidor.`,
          url
        ));
        break;
      }
    }
  }

  for (const [key, value] of Object.entries(storageData.session)) {
    for (const pattern of SENSITIVE_STORAGE_KEYS) {
      if (pattern.regex.test(key) || pattern.regex.test(value)) {
        findings.push(makeResult(
          `${pattern.label} (sessionStorage)`,
          pattern.severity,
          'fail',
          `sessionStorage["${key}"] contém dado sensível — acessível via XSS.`,
          url
        ));
        break;
      }
    }
  }

  return findings;
}

// ─── Console leaks ────────────────────────────────────────────────────────────

async function analyzeConsoleLeaks(page, url) {
  const findings = [];
  const consoleLogs = [];

  page.on('console', msg => {
    if (['log', 'debug', 'info', 'warn'].includes(msg.type())) {
      consoleLogs.push({ type: msg.type(), text: msg.text() });
    }
  });

  await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(500);
  page.removeAllListeners('console');

  const sensitiveConsole = consoleLogs.filter(l =>
    SENSITIVE_DOM_PATTERNS.some(p => p.regex.test(l.text)) ||
    /password|token|secret|api[_-]?key/i.test(l.text)
  );

  if (sensitiveConsole.length > 0) {
    findings.push(makeResult(
      'Dados sensíveis no console',
      'HIGH',
      'fail',
      `${sensitiveConsole.length} mensagem(ns) de console contêm dados potencialmente sensíveis. Remova todos os console.log de produção.`,
      url
    ));
  }

  const allConsoleLogs = consoleLogs.filter(l => l.type === 'log');
  if (allConsoleLogs.length > 5) {
    findings.push(makeResult(
      'Excesso de console.log em produção',
      'LOW',
      'warn',
      `${allConsoleLogs.length} mensagens de console.log detectadas — remova logs de debug antes do deploy.`,
      url
    ));
  }

  return findings;
}

// ─── Verificações de meta tags de segurança ───────────────────────────────────

async function analyzeMetaTags(page) {
  const findings = [];

  const metaData = await page.evaluate(() => {
    const viewport = document.querySelector('meta[name="viewport"]');
    const robots   = document.querySelector('meta[name="robots"]');
    const referrer = document.querySelector('meta[name="referrer"]');
    return {
      viewport: viewport?.content || null,
      robots:   robots?.content   || null,
      referrer: referrer?.content || null,
    };
  });

  if (!metaData.viewport) {
    findings.push(makeResult(
      'Meta viewport ausente',
      'LOW', 'warn',
      'Sem meta viewport — pode afetar comportamento em dispositivos móveis e breakpoints de segurança.',
    ));
  }

  if (metaData.referrer && metaData.referrer.includes('unsafe-url')) {
    findings.push(makeResult(
      'Referrer policy insegura',
      'MEDIUM', 'warn',
      `Meta referrer="unsafe-url" envia URL completa (incluindo query params com dados sensíveis) como referrer.`,
    ));
  }

  return findings;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function analyze(page, url) {
  const findings = [];
  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
    findings.push(...await analyzeDOMContent(page, url));
    findings.push(...await analyzeStorage(page, url));
    findings.push(...await analyzeMetaTags(page));

    // Console leaks requer nova navegação para capturar desde o início
    const consolePage = await page.context().newPage();
    findings.push(...await analyzeConsoleLeaks(consolePage, url));
    await consolePage.close();
  } catch (err) {
    findings.push(makeResult('Erro na análise DOM', 'INFO', 'error', err.message));
  }
  return findings;
}

module.exports = { analyze };
