'use strict';

// ─── Headers de segurança esperados ──────────────────────────────────────────

const REQUIRED_HEADERS = [
  { name: 'x-frame-options',           severity: 'HIGH',   desc: 'Protege contra clickjacking (iframe embedding)' },
  { name: 'x-content-type-options',    severity: 'MEDIUM', desc: 'Previne MIME-type sniffing' },
  { name: 'strict-transport-security', severity: 'HIGH',   desc: 'Força HTTPS (HSTS)' },
  { name: 'content-security-policy',   severity: 'HIGH',   desc: 'Controla origens de recursos (CSP)' },
  { name: 'referrer-policy',           severity: 'LOW',    desc: 'Controla informação de referrer' },
  { name: 'permissions-policy',        severity: 'LOW',    desc: 'Controla APIs do browser (câmera, microfone, etc.)' },
];

const DANGEROUS_HEADERS = [
  { name: 'x-powered-by',    severity: 'LOW',    desc: 'Expõe tecnologia do servidor (ex: Express, PHP)' },
  { name: 'server',          severity: 'LOW',    desc: 'Expõe versão do servidor web' },
  { name: 'x-aspnet-version',severity: 'MEDIUM', desc: 'Expõe versão do .NET Framework' },
];

// Padrões de dados sensíveis em URLs e respostas
const SENSITIVE_URL_PATTERNS = [
  { regex: /[?&]password=/i,    label: 'Senha na URL',      severity: 'CRITICAL' },
  { regex: /[?&]token=[^&]{8,}/i, label: 'Token na URL',   severity: 'HIGH' },
  { regex: /[?&]api[_-]?key=/i, label: 'API Key na URL',   severity: 'CRITICAL' },
  { regex: /[?&]secret=/i,      label: 'Secret na URL',    severity: 'CRITICAL' },
  { regex: /[?&]ssn=/i,         label: 'SSN/CPF na URL',   severity: 'CRITICAL' },
  { regex: /[?&]credit[_-]?card=/i, label: 'Cartão na URL',severity: 'CRITICAL' },
  { regex: /[?&]email=[^&]+@/i, label: 'Email na URL (GET)',severity: 'MEDIUM' },
];

const SENSITIVE_BODY_PATTERNS = [
  { regex: /"password"\s*:\s*"[^"]+"/i,  label: 'Senha em plain-text na resposta JSON', severity: 'CRITICAL' },
  { regex: /"secret"\s*:\s*"[^"]{8,}"/i, label: 'Secret exposto na resposta',           severity: 'HIGH' },
  { regex: /"token"\s*:\s*"[^"]{20,}"/i, label: 'Token exposto na resposta JSON',        severity: 'MEDIUM' },
  { regex: /"cvv"\s*:|"cvc"\s*:/i,        label: 'CVV de cartão na resposta',             severity: 'CRITICAL' },
  { regex: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/, label: 'Número de cartão detectado', severity: 'CRITICAL' },
  { regex: /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/, label: 'CPF detectado na resposta',          severity: 'HIGH' },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeResult(label, severity, status, detail, url = null) {
  return { label, severity, status, detail, url };
}

// ─── Análise de headers da resposta principal ─────────────────────────────────

async function analyzeResponseHeaders(page, url) {
  const findings = [];

  const response = await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => null);
  if (!response) {
    return [makeResult('Página inacessível', 'INFO', 'error', `Não foi possível carregar ${url}`)];
  }

  const headers = response.headers();

  // Headers obrigatórios ausentes
  for (const h of REQUIRED_HEADERS) {
    if (!headers[h.name]) {
      findings.push(makeResult(
        `Header ausente: ${h.name}`,
        h.severity,
        'fail',
        `${h.desc}. Adicione via helmet.js ou configuração do servidor.`,
        url
      ));
    }
  }

  // Headers que expõem informação
  for (const h of DANGEROUS_HEADERS) {
    if (headers[h.name]) {
      findings.push(makeResult(
        `Header perigoso presente: ${h.name}`,
        h.severity,
        'fail',
        `${h.desc} — valor: "${headers[h.name]}". Remova ou suprima este header.`,
        url
      ));
    }
  }

  // CSP presente mas com wildcards perigosos
  const csp = headers['content-security-policy'];
  if (csp) {
    if (csp.includes("'unsafe-inline'")) {
      findings.push(makeResult(
        "CSP com 'unsafe-inline'",
        'MEDIUM',
        'warn',
        `Content-Security-Policy permite 'unsafe-inline' — reduz a efetividade contra XSS.`,
        url
      ));
    }
    if (csp.includes("'unsafe-eval'")) {
      findings.push(makeResult(
        "CSP com 'unsafe-eval'",
        'HIGH',
        'warn',
        `Content-Security-Policy permite 'unsafe-eval' — permite execução de código dinâmico via eval().`,
        url
      ));
    }
    if (csp.includes('*')) {
      findings.push(makeResult(
        'CSP com wildcard *',
        'HIGH',
        'fail',
        `Content-Security-Policy contém wildcard (*) — anula a proteção para a diretiva afetada.`,
        url
      ));
    }
  }

  // Cookie flags
  const setCookie = headers['set-cookie'];
  if (setCookie) {
    const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const cookie of cookies) {
      const name = cookie.split('=')[0].trim();
      const isSession = /session|auth|token|jwt/i.test(name);

      if (isSession && !cookie.toLowerCase().includes('httponly')) {
        findings.push(makeResult(
          'Cookie de sessão sem HttpOnly',
          'HIGH',
          'fail',
          `Cookie "${name}" parece ser de sessão/auth mas não tem flag HttpOnly — acessível via JS (XSS pode roubar).`,
          url
        ));
      }
      if (isSession && !cookie.toLowerCase().includes('samesite')) {
        findings.push(makeResult(
          'Cookie de sessão sem SameSite',
          'MEDIUM',
          'fail',
          `Cookie "${name}" sem atributo SameSite — vulnerável a CSRF em navegadores mais antigos.`,
          url
        ));
      }
      if (isSession && !cookie.toLowerCase().includes('secure')) {
        findings.push(makeResult(
          'Cookie de sessão sem Secure flag',
          'MEDIUM',
          'warn',
          `Cookie "${name}" sem flag Secure — pode ser transmitido em conexões HTTP não criptografadas.`,
          url
        ));
      }
    }
  }

  return findings;
}

// ─── Intercepta requisições em tempo real ────────────────────────────────────

async function interceptRequests(page, baseUrl) {
  const findings = [];
  const requestLog = [];

  // Intercepta todas as requisições de rede feitas pela página
  page.on('request', request => {
    const url = request.url();
    const method = request.method();
    const headers = request.headers();
    const postData = request.postData() || '';

    requestLog.push({ url, method, headers, postData });

    // Dados sensíveis na URL
    for (const pattern of SENSITIVE_URL_PATTERNS) {
      if (pattern.regex.test(url)) {
        findings.push(makeResult(
          pattern.label,
          pattern.severity,
          'fail',
          `Requisição ${method} para "${url.substring(0, 100)}" contém dado sensível na URL — use POST com body ou headers.`,
          url
        ));
      }
    }

    // POST sem Content-Type definido
    if (['POST', 'PUT', 'PATCH'].includes(method) && !headers['content-type'] && postData) {
      findings.push(makeResult(
        'POST sem Content-Type',
        'LOW',
        'warn',
        `Requisição ${method} para "${url.substring(0, 80)}" sem Content-Type header.`,
        url
      ));
    }

    // Authorization em GET com dados na query string
    if (method === 'GET' && url.includes('?') && headers['authorization']) {
      findings.push(makeResult(
        'Authorization header + query params em GET',
        'LOW',
        'warn',
        `GET "${url.substring(0, 80)}" combina Authorization header com query params — dados da URL ficam em logs de servidor.`,
        url
      ));
    }
  });

  page.on('response', async response => {
    const url   = response.url();
    const ctype = response.headers()['content-type'] || '';

    // Analisa respostas JSON em busca de dados sensíveis
    if (ctype.includes('application/json')) {
      try {
        const text = await response.text();
        for (const pattern of SENSITIVE_BODY_PATTERNS) {
          if (pattern.regex.test(text)) {
            findings.push(makeResult(
              pattern.label,
              pattern.severity,
              'fail',
              `Resposta de "${url.substring(0, 80)}" contém dado sensível em plain-text.`,
              url
            ));
          }
        }
      } catch { /* resposta pode já ter sido consumida */ }
    }
  });

  // Aguarda a página carregar e disparar requisições
  await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(1000);

  // Remove event listeners para não interferir nos próximos testes
  page.removeAllListeners('request');
  page.removeAllListeners('response');

  // Analisa o log consolidado
  const postWithoutCsrf = requestLog.filter(r =>
    ['POST', 'PUT', 'PATCH', 'DELETE'].includes(r.method) &&
    !r.headers['x-csrf-token'] &&
    !r.headers['x-xsrf-token'] &&
    !r.headers['x-requested-with'] &&
    !r.headers['authorization']
  );

  if (postWithoutCsrf.length > 0) {
    findings.push(makeResult(
      'Mutações sem proteção CSRF nos headers',
      'HIGH',
      'fail',
      `${postWithoutCsrf.length} requisição(ões) de mutação (POST/PUT/PATCH/DELETE) sem token CSRF no header. URLs: ${postWithoutCsrf.slice(0,2).map(r => r.url.substring(0, 60)).join(', ')}`,
    ));
  }

  return findings;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function analyze(page, url) {
  const findings = [];
  try {
    findings.push(...await analyzeResponseHeaders(page, url));
    const pageForRequests = await page.context().newPage();
    findings.push(...await interceptRequests(pageForRequests, url));
    await pageForRequests.close();
  } catch (err) {
    findings.push(makeResult('Erro na inspeção de rede', 'INFO', 'error', err.message));
  }
  return findings;
}

module.exports = { analyze };
