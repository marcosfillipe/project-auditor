'use strict';

// ─── Payloads de teste ────────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>window.__xss_probe=1</script>',
  '"><img src=x onerror="window.__xss_probe=2">',
  "';alert('xss');//",
  '<svg onload="window.__xss_probe=3">',
  'javascript:window.__xss_probe=4',
];

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "1; DROP TABLE users--",
  "' UNION SELECT null,null--",
  "admin'--",
];

const PATH_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
  '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
];

const OVERSIZED_PAYLOAD = 'A'.repeat(10001);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeResult(label, severity, status, detail, field = null, formAction = null) {
  return { label, severity, status, detail, field, formAction };
}

// ─── Análise de formulários ───────────────────────────────────────────────────

async function analyzeForms(page, baseUrl) {
  const findings = [];

  // Coleta todos os formulários da página
  const forms = await page.evaluate(() => {
    return Array.from(document.querySelectorAll('form')).map((form, fi) => ({
      index:    fi,
      action:   form.action || '',
      method:   form.method || 'get',
      hasCSRF:  !!form.querySelector('[name*="csrf" i], [name*="token" i], [name*="_token" i]'),
      fields:   Array.from(form.querySelectorAll('input, textarea, select')).map(el => ({
        name:         el.name || el.id || `field-${Math.random().toString(36).slice(2,6)}`,
        type:         el.type || 'text',
        autocomplete: el.autocomplete,
        required:     el.required,
        maxlength:    el.maxLength > 0 ? el.maxLength : null,
        readonly:     el.readOnly,
        hidden:       el.type === 'hidden',
        value:        el.type === 'hidden' ? el.value : null,
      })),
    }));
  });

  if (forms.length === 0) {
    return [makeResult('Nenhum formulário encontrado', 'INFO', 'skip',
      `Nenhum <form> detectado em ${baseUrl} — página pode usar submissão via JS (fetch/axios)`)];
  }

  for (const form of forms) {
    const formLabel = `Form #${form.index + 1} (${form.action || 'sem action'})`;

    // ── 1. CSRF Token ──
    if (form.method.toLowerCase() === 'post' && !form.hasCSRF) {
      findings.push(makeResult(
        'CSRF Token ausente',
        'HIGH',
        'fail',
        `${formLabel} usa POST sem campo de CSRF token visível. Vulnerável a Cross-Site Request Forgery.`,
        null,
        form.action
      ));
    }

    // ── 2. Campos ocultos com valores suspeitos ──
    const hiddenFields = form.fields.filter(f => f.hidden);
    for (const hf of hiddenFields) {
      const suspicious = /role|admin|price|discount|total|permission|level|id|user/i.test(hf.name);
      if (suspicious) {
        findings.push(makeResult(
          'Campo hidden manipulável',
          'HIGH',
          'fail',
          `${formLabel} tem campo hidden "${hf.name}" com valor "${hf.value}" — pode ser alterado via DevTools antes do envio.`,
          hf.name,
          form.action
        ));
      }
    }

    // ── 3. Campos de senha com autocomplete ──
    const passwordFields = form.fields.filter(f => f.type === 'password');
    for (const pf of passwordFields) {
      if (!pf.autocomplete || pf.autocomplete === 'on' || pf.autocomplete === '') {
        findings.push(makeResult(
          'Autocomplete em campo de senha',
          'MEDIUM',
          'fail',
          `Campo de senha "${pf.name}" sem autocomplete="off" ou autocomplete="new-password" — navegadores podem sugerir/armazenar a senha indevidamente.`,
          pf.name,
          form.action
        ));
      }
    }

    // ── 4. Campos sem maxlength ──
    const textFields = form.fields.filter(f =>
      ['text', 'email', 'search', 'url', 'tel', 'textarea'].includes(f.type) && !f.readonly
    );
    for (const tf of textFields) {
      if (!tf.maxlength) {
        findings.push(makeResult(
          'Campo sem limite de tamanho',
          'LOW',
          'warn',
          `Campo "${tf.name}" (${tf.type}) sem maxlength — aceita payloads grandes (buffer overflow no frontend).`,
          tf.name,
          form.action
        ));
      }
    }

    // ── 5. Sondagem de XSS nos campos de texto ──
    const inputFields = form.fields.filter(f =>
      ['text', 'search', 'email', 'url'].includes(f.type) && !f.readonly && !f.hidden
    );

    for (const field of inputFields.slice(0, 3)) { // limita a 3 campos por form
      for (const payload of XSS_PAYLOADS.slice(0, 2)) { // 2 payloads por campo
        try {
          await page.evaluate((name, val) => {
            window.__xss_probe = 0;
            const el = document.querySelector(`[name="${name}"], [id="${name}"]`);
            if (el) { el.value = val; el.dispatchEvent(new Event('input', { bubbles: true })); }
          }, field.name, payload);

          // Aguarda possível re-render
          await page.waitForTimeout(300);

          // Verifica se o payload foi renderizado no DOM sem escape
          const injected = await page.evaluate((name, pay) => {
            const body = document.body.innerHTML;
            // Verifica se o script foi executado
            if (window.__xss_probe && window.__xss_probe > 0) return 'executed';
            // Verifica se aparece não-escapado no DOM (exceto no próprio input)
            const el = document.querySelector(`[name="${name}"]`);
            const stripped = body.replace(el ? el.outerHTML : '', '');
            return stripped.includes(pay.replace(/"/g, '&quot;')) ? 'escaped' :
                   stripped.includes(pay) ? 'raw' : 'safe';
          }, field.name, payload);

          if (injected === 'executed') {
            findings.push(makeResult(
              'XSS Executável Confirmado',
              'CRITICAL',
              'fail',
              `Campo "${field.name}" em ${formLabel}: payload XSS foi EXECUTADO em runtime. "${payload.substring(0, 50)}"`,
              field.name, form.action
            ));
            break;
          } else if (injected === 'raw') {
            findings.push(makeResult(
              'XSS Refletido no DOM',
              'HIGH',
              'fail',
              `Campo "${field.name}" em ${formLabel}: payload aparece não-escapado no DOM após input. Sanitização ausente.`,
              field.name, form.action
            ));
          }
        } catch { /* campo pode não existir após re-render */ }
      }
    }

    // ── 6. Payload oversized ──
    for (const field of inputFields.slice(0, 1)) {
      try {
        await page.evaluate((name, val) => {
          const el = document.querySelector(`[name="${name}"], [id="${name}"]`);
          if (el) el.value = val;
        }, field.name, OVERSIZED_PAYLOAD);

        const accepted = await page.evaluate((name, size) => {
          const el = document.querySelector(`[name="${name}"]`);
          return el ? el.value.length >= size : false;
        }, field.name, 10000);

        if (accepted) {
          findings.push(makeResult(
            'Aceita payload muito grande',
            'MEDIUM',
            'warn',
            `Campo "${field.name}" aceita strings > 10.000 caracteres sem bloqueio — sem maxlength e sem validação JS.`,
            field.name, form.action
          ));
        }
      } catch { /* ok */ }
    }
  }

  return findings;
}

// ─── Verifica submissão via JS (sem form tag) ─────────────────────────────────

async function detectJSSubmission(page) {
  const findings = [];

  const jsSubmit = await page.evaluate(() => {
    const scripts = Array.from(document.querySelectorAll('script:not([src])')).map(s => s.textContent);
    const all = scripts.join('\n');
    return {
      hasFetch:  /fetch\s*\(/.test(all),
      hasAxios:  /axios\.(post|put|patch)/.test(all),
      hasXHR:    /XMLHttpRequest/.test(all),
    };
  });

  if (jsSubmit.hasFetch || jsSubmit.hasAxios || jsSubmit.hasXHR) {
    findings.push(makeResult(
      'Submissão via JS detectada',
      'INFO',
      'info',
      `Página usa ${[jsSubmit.hasFetch && 'fetch', jsSubmit.hasAxios && 'axios', jsSubmit.hasXHR && 'XMLHttpRequest'].filter(Boolean).join(', ')} para envio de dados. Verifique se validação ocorre antes do envio e se payloads são sanitizados.`
    ));
  }

  return findings;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function analyze(page, url) {
  const findings = [];
  try {
    await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
    findings.push(...await analyzeForms(page, url));
    findings.push(...await detectJSSubmission(page));
  } catch (err) {
    findings.push(makeResult('Erro ao analisar formulários', 'INFO', 'error',
      `Não foi possível carregar ${url}: ${err.message}`));
  }
  return findings;
}

module.exports = { analyze };
