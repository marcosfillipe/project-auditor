'use strict';

const { probe } = require('./detector');

// ─── Config ───────────────────────────────────────────────────────────────────

const PROBE_COUNT   = 15;   // submissões rápidas para testar rate limit
const PROBE_DELAY   = 80;   // ms entre cada submissão
const BLOCK_TIMEOUT = 3000; // aguarda resposta de bloqueio

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function makeResult(label, severity, status, detail, url = null) {
  return { label, severity, status, detail, url };
}

// ─── Detecta endpoints de autenticação na página ──────────────────────────────

async function detectAuthEndpoints(page, baseUrl) {
  const endpoints = [];

  // Intercepta requisições para detectar endpoints reais
  const captured = [];
  page.on('request', req => {
    if (['POST', 'PUT'].includes(req.method())) {
      captured.push({ url: req.url(), method: req.method(), postData: req.postData() });
    }
  });

  // Carrega a página
  await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});

  page.removeAllListeners('request');

  // Analisa URLs capturadas
  for (const req of captured) {
    const url = req.url;
    const isAuth = /login|signin|auth|session|token|register|signup|password|reset/i.test(url);
    if (isAuth) endpoints.push(req);
  }

  // Também busca por formulários com action apontando para endpoints conhecidos
  const formActions = await page.evaluate(() =>
    Array.from(document.querySelectorAll('form[action]')).map(f => ({
      action: f.action,
      method: f.method || 'get',
    }))
  ).catch(() => []);

  for (const form of formActions) {
    if (/login|auth|register|signin/i.test(form.action)) {
      endpoints.push({ url: form.action, method: form.method.toUpperCase() });
    }
  }

  return endpoints;
}

// ─── Teste de rate limiting num endpoint ─────────────────────────────────────

async function probeRateLimit(endpoint) {
  const findings = [];
  const url = endpoint.url;
  const responses = [];

  // Dispara PROBE_COUNT requisições rápidas
  for (let i = 0; i < PROBE_COUNT; i++) {
    const result = await probe(url, BLOCK_TIMEOUT);
    responses.push(result.status || 0);
    await sleep(PROBE_DELAY);
  }

  const blocked    = responses.filter(s => s === 429 || s === 423 || s === 503).length;
  const successful = responses.filter(s => s >= 200 && s < 400).length;
  const errors     = responses.filter(s => s >= 500).length;

  if (blocked > 0) {
    findings.push(makeResult(
      'Rate limiting ativo ✓',
      'INFO',
      'pass',
      `Endpoint "${url.substring(0, 70)}" retornou HTTP ${responses.find(s => s === 429 || s === 423)} após ${responses.indexOf(responses.find(s => s === 429 || s === 423)) + 1} requisições — rate limiting funcionando.`,
      url
    ));
  } else if (successful >= PROBE_COUNT * 0.8) {
    findings.push(makeResult(
      'Sem rate limiting detectado',
      'HIGH',
      'fail',
      `Endpoint "${url.substring(0, 70)}" respondeu ${successful}/${PROBE_COUNT} requisições rápidas com sucesso (nenhuma bloqueada). Vulnerável a brute force e credential stuffing.`,
      url
    ));
  } else if (errors > PROBE_COUNT * 0.5) {
    findings.push(makeResult(
      'Endpoint instável sob carga',
      'MEDIUM',
      'warn',
      `Endpoint "${url.substring(0, 70)}" retornou ${errors} erros 5xx em ${PROBE_COUNT} requisições — pode não suportar carga leve.`,
      url
    ));
  }

  return findings;
}

// ─── Teste de rate limiting via formulário (browser) ─────────────────────────

async function probeFormRateLimit(page, baseUrl) {
  const findings = [];

  // Localiza formulários de login/register
  const loginForm = await page.evaluate(() => {
    const forms = Array.from(document.querySelectorAll('form'));
    for (const form of forms) {
      const text = form.innerText.toLowerCase() + form.innerHTML.toLowerCase();
      if (/login|entrar|sign.?in|senha|password/i.test(text)) {
        const inputs = Array.from(form.querySelectorAll('input[type="text"], input[type="email"], input[type="password"]'));
        const submit = form.querySelector('[type="submit"], button');
        if (inputs.length >= 1 && submit) {
          return {
            hasForm: true,
            inputCount: inputs.length,
            firstInputName: inputs[0].name || inputs[0].id,
            submitText: submit.innerText || 'Submit',
          };
        }
      }
    }
    return { hasForm: false };
  });

  if (!loginForm.hasForm) {
    findings.push(makeResult(
      'Formulário de login não encontrado',
      'INFO',
      'skip',
      `Nenhum formulário de login detectado em ${baseUrl} para teste de rate limiting via browser.`
    ));
    return findings;
  }

  // Submete o formulário repetidamente com credenciais inválidas
  const responses = [];
  for (let i = 0; i < 8; i++) {
    try {
      const beforeUrl = page.url();

      await page.evaluate(() => {
        const emailInput = document.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');
        const passInput  = document.querySelector('input[type="password"]');
        const submit     = document.querySelector('form [type="submit"], form button[type="submit"], form button:not([type])');

        if (emailInput) emailInput.value = `probe${Math.random().toString(36).slice(2)}@test.com`;
        if (passInput)  passInput.value  = 'WrongPass_Probe_' + Math.random().toString(36).slice(2);
        if (submit) submit.click();
      });

      await sleep(600);

      const afterUrl = page.url();
      const pageText = await page.evaluate(() => document.body.innerText.toLowerCase());

      const wasBlocked = /muitas tentativas|too many|rate limit|bloqueado|blocked|aguarde|wait|tente mais tarde/i.test(pageText);
      const wasError   = /senha incorreta|invalid|incorrect|erro|error|inválid/i.test(pageText);

      responses.push({ blocked: wasBlocked, error: wasError, redirected: afterUrl !== beforeUrl });

      if (wasBlocked) break;

      // Volta para o form se redirecionou
      if (afterUrl !== beforeUrl) {
        await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 8000 }).catch(() => {});
      }
    } catch { break; }
  }

  const blocked = responses.filter(r => r.blocked).length;
  const total   = responses.length;

  if (blocked > 0) {
    findings.push(makeResult(
      'Rate limiting de formulário ativo ✓',
      'INFO',
      'pass',
      `Formulário de login bloqueou tentativas após ${responses.indexOf(responses.find(r => r.blocked)) + 1} submissões inválidas.`
    ));
  } else if (total >= 5) {
    findings.push(makeResult(
      'Formulário de login sem rate limiting visível',
      'HIGH',
      'fail',
      `${total} tentativas de login inválidas consecutivas sem bloqueio ou mensagem de rate limit. Vulnerável a brute force.`
    ));
  }

  return findings;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function analyze(page, baseUrl) {
  const findings = [];
  try {
    // Detecta endpoints via interceptação de rede
    const probePage = await page.context().newPage();
    const endpoints = await detectAuthEndpoints(probePage, baseUrl);
    await probePage.close();

    // Testa rate limiting HTTP direto nos endpoints detectados
    for (const ep of endpoints.slice(0, 3)) {
      findings.push(...await probeRateLimit(ep));
      await sleep(500);
    }

    // Testa via formulário no browser
    const formPage = await page.context().newPage();
    await formPage.goto(baseUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
    findings.push(...await probeFormRateLimit(formPage, baseUrl));
    await formPage.close();

    if (endpoints.length === 0 && findings.filter(f => f.status !== 'skip').length === 0) {
      findings.push(makeResult(
        'Nenhum endpoint de autenticação detectado',
        'INFO',
        'skip',
        `Nenhuma requisição de login/auth foi interceptada em ${baseUrl}. Navegue até a tela de login e rode novamente, ou especifique --url diretamente.`
      ));
    }
  } catch (err) {
    findings.push(makeResult('Erro no probe de rate limit', 'INFO', 'error', err.message));
  }
  return findings;
}

module.exports = { analyze };
