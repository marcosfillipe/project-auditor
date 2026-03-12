'use strict';
const fs = require('fs');
const path = require('path');

const PATTERNS = {
  security: [
    // XSS / Output não sanitizado
    { regex: /echo\s+\$_(GET|POST|REQUEST|COOKIE|SERVER)\[/g,           severity: 'CRITICAL', desc: 'echo $_GET/$_POST direto — XSS e injeção direta sem sanitização' },
    { regex: /echo\s+\$(?!wp_|esc_|sanitize_|the_|get_the_)[a-z_]+\[['"]?\w/gi, severity: 'HIGH', desc: 'echo de variável não sanitizada — verifique se passou por esc_html/esc_attr' },
    { regex: /\$_(?:GET|POST|REQUEST|COOKIE)\[/g,                       severity: 'MEDIUM',   desc: 'Acesso direto a superglobal — sanitize com sanitize_text_field() ou intval()' },
    // SQL Injection
    { regex: /\$wpdb->query\s*\(\s*["'`][^"'`]*\.\s*\$/g,              severity: 'CRITICAL', desc: 'wpdb->query() com concatenação — use $wpdb->prepare()' },
    { regex: /\$wpdb->get_results?\s*\(\s*["'`][^"'`]*\.\s*\$/g,       severity: 'CRITICAL', desc: 'wpdb->get_results() com concatenação — SQL injection, use prepare()' },
    { regex: /\$wpdb->prepare\s*\([^)]*(?<!%s|%d|%f)['"]\s*\)/g,      severity: 'HIGH',     desc: 'wpdb->prepare() sem placeholders — prepare() sem %s/%d não protege' },
    // CSRF / Nonce
    { regex: /wp_ajax_(?!nopriv_)\w+/g,                                 severity: 'MEDIUM',   desc: 'Hook wp_ajax sem wp_verify_nonce visível — verifique CSRF protection' },
    { regex: /add_action\s*\(\s*['"]wp_ajax/g,                          severity: 'MEDIUM',   desc: 'AJAX action — confirme wp_verify_nonce() no handler' },
    // File/Path
    { regex: /include\s*\(\s*\$_(GET|POST|REQUEST)/g,                   severity: 'CRITICAL', desc: 'include() com parâmetro do usuário — LFI/RFI direto' },
    { regex: /require\s*\(\s*\$_(GET|POST|REQUEST)/g,                   severity: 'CRITICAL', desc: 'require() com parâmetro do usuário — LFI/RFI direto' },
    // Secrets
    { regex: /define\s*\(\s*['"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY)['"]\s*,\s*['"][^'"]{4,}['"]/g, severity: 'HIGH', desc: 'Chave WordPress hardcoded — verifique se este arquivo está no .gitignore' },
  ],
  performance: [
    { regex: /WP_Query\s*\(\s*\[(?![^\]]*'posts_per_page'|[^\]]*"posts_per_page")/g, severity: 'MEDIUM', desc: 'WP_Query sem posts_per_page — pode retornar todos os posts' },
    { regex: /get_posts\s*\(\s*\[(?![^\]]*'numberposts'|[^\]]*"numberposts")/g, severity: 'MEDIUM', desc: 'get_posts() sem numberposts definido' },
    { regex: /\$wpdb->get_results\s*\([^)]*SELECT\s+\*\s+FROM/gi,      severity: 'MEDIUM',   desc: 'SELECT * via wpdb — selecione apenas os campos necessários' },
  ],
  flow: [
    { regex: /update_option\s*\(\s*['"][^'"]+['"]\s*,\s*\$_(GET|POST|REQUEST)/g, severity: 'HIGH', desc: 'update_option() com dado do usuário não sanitizado' },
    { regex: /add_option\s*\(\s*['"][^'"]+['"]\s*,\s*\$_(GET|POST|REQUEST)/g,    severity: 'HIGH', desc: 'add_option() com dado do usuário não sanitizado' },
    { regex: /wp_redirect\s*\(\s*\$_(GET|POST|REQUEST)/g,              severity: 'HIGH',     desc: 'wp_redirect() com input do usuário — open redirect' },
    { regex: /current_user_can\s*\(\s*\)\s*(?!===\s*true|.*die|.*wp_die)/g, severity: 'MEDIUM', desc: 'current_user_can() sem abort visível se falhar — verifique o fluxo' },
    { regex: /\/\/\s*TODO|#\s*TODO|\/\/\s*FIXME/gi,                   severity: 'LOW',      desc: 'Débito técnico marcado' },
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
          findings.push({ severity, label: `WordPress/${label}`, description: desc, file: filePath, line: i + 1 });
        }
        regex.lastIndex = 0;
      });
    }
  }
  return findings;
}

function analyzeProject(projectRoot) {
  const issues = [];

  // wp-config.php
  const wpConfig = path.join(projectRoot, 'wp-config.php');
  if (fs.existsSync(wpConfig)) {
    const cfg = fs.readFileSync(wpConfig, 'utf8');
    if (/define\s*\(\s*['"]WP_DEBUG['"]\s*,\s*true\s*\)/i.test(cfg))
      issues.push({ severity: 'HIGH', label: 'WordPress/Config', description: 'WP_DEBUG = true em wp-config.php — desative em produção.', file: wpConfig });
    if (/define\s*\(\s*['"]WP_DEBUG_DISPLAY['"]\s*,\s*true\s*\)/i.test(cfg))
      issues.push({ severity: 'HIGH', label: 'WordPress/Config', description: 'WP_DEBUG_DISPLAY = true — erros exibidos na tela, exposição de informações.', file: wpConfig });
    if (!/define\s*\(\s*['"]DISALLOW_FILE_EDIT['"]/i.test(cfg))
      issues.push({ severity: 'MEDIUM', label: 'WordPress/Config', description: 'DISALLOW_FILE_EDIT não definido — editor de arquivos no admin está habilitado.', file: wpConfig });
  }

  // .htaccess
  const htaccess = path.join(projectRoot, 'public', '.htaccess');
  const htaccess2 = path.join(projectRoot, '.htaccess');
  const ht = [htaccess, htaccess2].find(fs.existsSync);
  if (!ht)
    issues.push({ severity: 'LOW', label: 'WordPress/Config', description: '.htaccess não encontrado — regras de segurança (wp-includes, wp-config) podem estar ausentes.', file: projectRoot });

  return issues;
}

module.exports = { analyzeFile, analyzeProject };
