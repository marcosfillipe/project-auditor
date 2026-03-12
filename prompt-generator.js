'use strict';

const path = require('path');

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function sortBySeverity(items) {
  return [...items].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9));
}

function relPath(filePath, projectRoot) {
  return path.relative(projectRoot, filePath) || filePath;
}

function timestamp() {
  return new Date().toLocaleString('pt-BR', { timeZone: 'America/Fortaleza', dateStyle: 'full', timeStyle: 'short' });
}

function groupByLabel(findings) {
  const groups = {};
  for (const f of findings) {
    if (!groups[f.label]) groups[f.label] = [];
    groups[f.label].push(f);
  }
  return groups;
}

function uniqueFiles(findings) {
  return [...new Set(findings.filter(f => f.file).map(f => f.file))];
}

// ─── Prompt Templates por tipo de problema ───────────────────────────────────

const PROMPT_TEMPLATES = {

  // ── SEGURANÇA ──────────────────────────────────────────────────────────────

  'SQL Injection Risk': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    const examples = findings.slice(0, 3).map(f =>
      `- Linha ${f.line} em \`${relPath(f.file, projectRoot)}\`: ${f.description}`
    ).join('\n');
    return `
Você é um engenheiro de segurança sênior revisando código Node.js/PostgreSQL.

**Contexto:** Foram encontradas ${findings.length} ocorrência(s) de SQL Injection nos arquivos abaixo.

**Arquivos afetados:**
${files}

**Exemplos detectados:**
${examples}

**Sua tarefa — execute em ordem:**
1. Abra cada arquivo listado acima
2. Localize todas as queries que usam concatenação de string ou template literals com variáveis de usuário
3. Substitua cada uma por **parameterized queries** no formato correto para o driver em uso (pg, mysql2, knex, prisma, etc.)
4. Exemplo de correção:
   - ❌ ANTES: \`db.query("SELECT * FROM users WHERE id = " + req.params.id)\`
   - ✅ DEPOIS: \`db.query("SELECT * FROM users WHERE id = $1", [req.params.id])\`
5. Após corrigir, execute os testes existentes para garantir que nenhuma query quebrou
6. Confirme que nenhuma query dinâmica restou sem parametrização

**Critério de conclusão:** Zero ocorrências de concatenação de string em contexto de query SQL.
`.trim();
  },

  'Hardcoded Secrets / Credentials': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de segurança responsável por higienizar credenciais expostas no código-fonte.

**Contexto:** Foram encontradas ${findings.length} credencial(is) hardcoded nos arquivos abaixo.

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Abra cada arquivo afetado e identifique todas as strings que representam: passwords, API keys, tokens, secrets, connection strings
2. Para cada credencial encontrada:
   a. Crie (ou verifique a existência de) uma variável correspondente no arquivo \`.env\`
   b. Substitua o valor hardcoded por \`process.env.NOME_DA_VARIAVEL\`
   c. Adicione a variável com valor placeholder em \`.env.example\` (sem o valor real)
3. Verifique se o arquivo \`.env\` está listado no \`.gitignore\` — se não estiver, adicione
4. Rode um \`git status\` ou \`git diff\` para garantir que nenhum arquivo \`.env\` com valores reais será commitado
5. Se o projeto usa Docker, adicione as variáveis em \`docker-compose.yml\` como \`environment\` referenciando o \`.env\`

**Critério de conclusão:** Nenhum valor sensível literal no código-fonte. Todas as credenciais lidas de \`process.env\`.
`.trim();
  },

  'Cross-Site Scripting (XSS)': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    const lines = findings.slice(0, 3).map(f =>
      `- Linha ${f.line} em \`${relPath(f.file, projectRoot)}\`: \`${f.lineContent || f.description}\``
    ).join('\n');
    return `
Você é um engenheiro frontend especializado em segurança de aplicações web.

**Contexto:** Foram detectadas ${findings.length} ocorrência(s) de risco de XSS (Cross-Site Scripting).

**Localizações:**
${lines}

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize cada uso de \`innerHTML\`, \`document.write\`, \`dangerouslySetInnerHTML\` ou \`eval\` com variáveis
2. Para cada caso, avalie a origem do dado:
   - Se o dado vem do usuário ou de uma API externa → **sanitize obrigatoriamente**
   - Se o dado é texto puro → substitua por \`textContent\` ou \`innerText\`
   - Se precisa renderizar HTML confiável → instale e use \`DOMPurify\`: \`npm install dompurify\`
3. Exemplo de correção:
   - ❌ ANTES: \`element.innerHTML = userData.name\`
   - ✅ DEPOIS: \`element.textContent = userData.name\`
   - ✅ COM HTML: \`element.innerHTML = DOMPurify.sanitize(userData.bio)\`
4. Para React: substitua \`dangerouslySetInnerHTML\` por renderização condicional ou DOMPurify
5. Remova todos os usos de \`eval()\` — substitua pela lógica equivalente sem execução dinâmica

**Critério de conclusão:** Nenhum dado externo inserido diretamente no DOM sem sanitização.
`.trim();
  },

  'Missing Rate Limiting': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro backend responsável por proteger APIs contra abuso e força bruta.

**Contexto:** ${findings.length} endpoint(s) sem rate limiting identificado(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Instale o pacote adequado:
   - Express: \`npm install express-rate-limit\`
   - Fastify: \`npm install @fastify/rate-limit\`
2. Configure rate limiting **global** (todas as rotas) com limites conservadores:
   \`\`\`js
   // Express
   const rateLimit = require('express-rate-limit');
   app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100 }));
   \`\`\`
3. Configure rate limiting **estrito** nos endpoints de autenticação (/login, /register, /reset-password):
   \`\`\`js
   const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: 'Muitas tentativas' });
   router.post('/login', authLimiter, loginController);
   \`\`\`
4. Verifique se a API está atrás de um proxy (Nginx, Cloudflare) — se sim, configure \`app.set('trust proxy', 1)\`
5. Documente os limites escolhidos em um comentário ou README

**Critério de conclusão:** Todo endpoint de autenticação com rate limit ≤ 10 req/15min. Demais rotas com limite global definido.
`.trim();
  },

  'CORS Misconfiguration': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de segurança revisando a política de CORS da aplicação.

**Contexto:** ${findings.length} configuração(ões) de CORS insegura(s) detectada(s) (wildcard ou sem restrição).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize todas as configurações de CORS no projeto
2. Substitua \`origin: '*'\` por uma lista explícita de origens permitidas:
   \`\`\`js
   app.use(cors({
     origin: process.env.ALLOWED_ORIGINS?.split(',') || ['https://meudominio.com'],
     methods: ['GET', 'POST', 'PUT', 'DELETE'],
     allowedHeaders: ['Content-Type', 'Authorization'],
     credentials: true
   }));
   \`\`\`
3. Adicione \`ALLOWED_ORIGINS\` ao \`.env\` e \`.env.example\`
4. Para ambientes de desenvolvimento, permita localhost explicitamente via variável de ambiente
5. Teste os endpoints com um cliente HTTP para confirmar que origens não autorizadas recebem erro 403

**Critério de conclusão:** Nenhum \`origin: '*'\` em produção. Origens controladas via variável de ambiente.
`.trim();
  },

  'Authentication / Authorization Weakness': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de segurança especializado em sistemas de autenticação.

**Contexto:** ${findings.length} fraqueza(s) de autenticação detectada(s) no projeto.

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. **Hashing de senhas:** substitua MD5/SHA1 por bcrypt ou argon2
   - Instale: \`npm install bcrypt\`
   - Use: \`await bcrypt.hash(password, 12)\` e \`await bcrypt.compare(input, hash)\`
2. **JWT:** verifique todas as chamadas \`jwt.sign()\` e \`jwt.verify()\`
   - O secret deve vir exclusivamente de \`process.env.JWT_SECRET\` — sem fallback
   - Defina expiração: \`{ expiresIn: '1h' }\`
   - Nunca use \`algorithm: 'none'\`
3. **Geração de tokens:** substitua \`Math.random()\` por \`crypto.randomBytes(32).toString('hex')\`
4. **Verificação:** confirme que \`jwt.verify()\` está sendo chamado em todos os middlewares de autenticação

**Critério de conclusão:** Senhas com bcrypt (cost ≥ 12). JWT com secret exclusivo via env. Tokens gerados com crypto.
`.trim();
  },

  'Path Traversal / File Injection': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de segurança revisando operações de acesso a arquivos.

**Contexto:** ${findings.length} operação(ões) de leitura de arquivo com input do usuário detectada(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize todos os \`readFile\`, \`readFileSync\`, \`path.join\` que recebem dados de \`req.params\`, \`req.query\` ou \`req.body\`
2. Para cada caso, aplique validação e normalização:
   \`\`\`js
   const safeName = path.basename(req.params.filename); // remove traversal sequences
   const fullPath = path.resolve('/var/uploads', safeName);
   // garante que o path final está dentro do diretório permitido
   if (!fullPath.startsWith(path.resolve('/var/uploads'))) {
     return res.status(403).json({ error: 'Acesso negado' });
   }
   const content = await fs.promises.readFile(fullPath);
   \`\`\`
3. Nunca aceite caminhos absolutos vindos do usuário
4. Use whitelist de extensões permitidas quando aplicável

**Critério de conclusão:** Nenhum acesso a arquivo sem validação de path. Todos os paths normalizados e confinados ao diretório permitido.
`.trim();
  },

  // ── PERFORMANCE ────────────────────────────────────────────────────────────

  'N+1 Query Risk': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de banco de dados otimizando queries em Node.js/PostgreSQL.

**Contexto:** ${findings.length} ocorrência(s) de padrão N+1 detectada(s) — queries dentro de loops que multiplicam o número de chamadas ao banco.

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize cada loop (\`for\`, \`forEach\`, \`map\`) que contém uma chamada ao banco de dados dentro dele
2. Para cada caso, escolha a estratégia de correção adequada:
   - **JOIN:** reescreva como uma única query com JOIN que retorna todos os dados necessários
   - **IN clause:** colete os IDs primeiro, depois faça uma query única com \`WHERE id = ANY($1)\`
   - **Promise.all:** se as queries forem independentes, execute em paralelo (não em série)
3. Exemplo de correção com IN:
   - ❌ ANTES: \`for (const user of users) { user.orders = await db.query('SELECT * FROM orders WHERE user_id = $1', [user.id]) }\`
   - ✅ DEPOIS: \`const ids = users.map(u => u.id); const orders = await db.query('SELECT * FROM orders WHERE user_id = ANY($1)', [ids])\`
4. Após corrigir, verifique se os índices necessários existem nas colunas de JOIN/WHERE

**Critério de conclusão:** Nenhuma query executada dentro de loop iterativo. Número de queries por request é O(1) ou O(log n).
`.trim();
  },

  'Missing Pagination': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro backend garantindo que endpoints de listagem sejam seguros e performáticos.

**Contexto:** ${findings.length} query(ies) sem LIMIT/paginação detectada(s) — risco de retornar tabelas inteiras.

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize todos os \`SELECT\` sem \`LIMIT\` e todas as chamadas \`findAll()\`/\`find()\` sem \`limit\`
2. Implemente paginação baseada em offset ou cursor:
   \`\`\`js
   // Offset-based (simples)
   const page = parseInt(req.query.page) || 1;
   const limit = Math.min(parseInt(req.query.limit) || 20, 100); // máximo 100
   const offset = (page - 1) * limit;
   const result = await db.query('SELECT * FROM items LIMIT $1 OFFSET $2', [limit, offset]);
   \`\`\`
3. Retorne metadados de paginação na resposta: \`{ data: [...], total, page, limit, totalPages }\`
4. Defina um limite máximo por request (recomendado: 100 itens) e force esse teto no código

**Critério de conclusão:** Todo endpoint de listagem com LIMIT explícito. Máximo de itens por request definido e documentado.
`.trim();
  },

  'Synchronous / Blocking Operation': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro Node.js otimizando o uso do event loop.

**Contexto:** ${findings.length} operação(ões) síncrona(s) bloqueante(s) detectada(s) (\`readFileSync\`, \`writeFileSync\`, \`execSync\`).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Substitua cada operação síncrona pela versão assíncrona equivalente:
   - \`fs.readFileSync(path)\` → \`await fs.promises.readFile(path)\`
   - \`fs.writeFileSync(path, data)\` → \`await fs.promises.writeFile(path, data)\`
   - \`execSync(cmd)\` → \`await exec(cmd)\` (usando \`util.promisify(require('child_process').exec)\`)
2. Garanta que a função que faz a chamada seja \`async\` e que o \`await\` esteja presente
3. Envolva em try/catch para tratar erros de I/O adequadamente
4. Exceção válida: arquivos de configuração lidos UMA vez na inicialização da aplicação (antes do servidor subir) podem manter versão síncrona

**Critério de conclusão:** Zero chamadas \`*Sync\` em handlers de request. Event loop desbloqueado durante I/O.
`.trim();
  },

  'Response Time / Timeout': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro de confiabilidade (SRE) garantindo resiliência em chamadas externas.

**Contexto:** ${findings.length} chamada(s) HTTP externa(s) sem timeout definido detectada(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Para cada \`fetch()\` sem AbortController, adicione timeout:
   \`\`\`js
   const controller = new AbortController();
   const timeout = setTimeout(() => controller.abort(), 5000); // 5s
   try {
     const res = await fetch(url, { signal: controller.signal });
   } finally {
     clearTimeout(timeout);
   }
   \`\`\`
2. Para \`axios\`, adicione o campo \`timeout\` em todas as chamadas ou na instância global:
   \`\`\`js
   const api = axios.create({ timeout: 5000 });
   \`\`\`
3. Defina timeouts diferentes por criticidade: APIs de pagamento (10s), APIs internas (3s), APIs de enriquecimento (2s)
4. Trate o erro de timeout explicitamente e retorne resposta degradada (graceful degradation) quando possível

**Critério de conclusão:** 100% das chamadas HTTP externas com timeout configurado. Timeout máximo de 10s para qualquer chamada.
`.trim();
  },

  // ── FLUXO & QUALIDADE ──────────────────────────────────────────────────────

  'Unhandled Promise / Async Error': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro Node.js garantindo que erros assíncronos sejam sempre tratados.

**Contexto:** ${findings.length} ocorrência(s) de Promise/async sem tratamento de erro detectada(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Localize todas as funções \`async\` sem bloco \`try/catch\` e todos os \`.then()\` sem \`.catch()\`
2. Envolva o corpo de cada função async de controller/handler com try/catch:
   \`\`\`js
   async function getUser(req, res) {
     try {
       const user = await db.findUser(req.params.id);
       res.json(user);
     } catch (err) {
       res.status(500).json({ error: 'Erro interno', message: err.message });
     }
   }
   \`\`\`
3. Adicione \`.catch(next)\` em chains de Promise dentro de middlewares Express
4. Confirme que existe um handler global de erros no arquivo principal da aplicação:
   \`\`\`js
   app.use((err, req, res, next) => {
     console.error(err.stack);
     res.status(err.status || 500).json({ error: err.message });
   });
   \`\`\`
5. Configure \`process.on('unhandledRejection', ...)\` como fallback de último recurso (logar e encerrar graciosamente)

**Critério de conclusão:** Toda função async em handler/controller com try/catch. Handler global de erros presente.
`.trim();
  },

  'Missing Input Validation': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro backend implementando validação de entrada em uma API Node.js.

**Contexto:** ${findings.length} ponto(s) de uso de input do usuário sem validação visível detectado(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Instale uma biblioteca de validação de schema: \`npm install zod\` (recomendado) ou \`npm install joi\`
2. Para cada endpoint que usa \`req.body\`, \`req.params\` ou \`req.query\`, defina um schema:
   \`\`\`js
   const { z } = require('zod');
   const createUserSchema = z.object({
     name: z.string().min(1).max(100),
     email: z.string().email(),
     age: z.number().int().min(0).max(150).optional()
   });
   
   // No handler:
   const parsed = createUserSchema.safeParse(req.body);
   if (!parsed.success) return res.status(400).json({ errors: parsed.error.flatten() });
   const { name, email, age } = parsed.data; // dados seguros e tipados
   \`\`\`
3. Nunca use diretamente \`req.body.campo\` em queries ou lógica crítica sem passar pelo schema
4. Para \`req.params.id\` numérico, valide com \`z.coerce.number().int().positive()\`

**Critério de conclusão:** Todo endpoint com schema de validação definido. Nenhum input de usuário usado diretamente sem parse.
`.trim();
  },

  'Dead / Debug Code': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    const todos = findings.filter(f => f.description?.includes('TODO'));
    const fixmes = findings.filter(f => f.description?.includes('FIXME'));
    return `
Você é um engenheiro revisando código para remover débito técnico e artefatos de desenvolvimento.

**Contexto:** ${findings.length} ocorrência(s) de código morto ou debug detectada(s) (${todos.length} TODOs, ${fixmes.length} FIXMEs, console.logs, debugger statements).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Remova todos os \`console.log\`, \`console.debug\`, \`console.info\` de código de produção
   - Se logging é necessário, substitua por um logger estruturado: \`npm install pino\`
   - \`const logger = require('pino')(); logger.info({ userId }, 'User logged in');\`
2. Remova todos os \`debugger;\` statements
3. Para cada TODO e FIXME:
   - Se é urgente: crie uma issue/card e resolva agora
   - Se é futuro: mova para o issue tracker e remova o comentário do código
4. Verifique se há funções, variáveis ou imports declarados mas nunca usados e remova-os

**Critério de conclusão:** Zero console.log em produção. Zero debugger statements. Todos os TODOs/FIXMEs triados e removidos do código.
`.trim();
  },

  'Exposed Internal Routes': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    const debugRoutes = findings.filter(f => f.lineContent?.includes('/debug'));
    return `
Você é um engenheiro de segurança auditando rotas expostas desnecessariamente.

**Contexto:** ${findings.length} rota(s) potencialmente sensível(is) detectada(s) (/admin, /internal, /debug).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. Para rotas \`/debug\` ou similares (${debugRoutes.length} detectada(s)):
   - Remova completamente em produção, ou proteja com variável de ambiente:
   \`\`\`js
   if (process.env.NODE_ENV !== 'production') {
     router.get('/debug/env', debugController);
   }
   \`\`\`
2. Para rotas \`/admin\`:
   - Certifique-se que existe middleware de autenticação E autorização por role antes do handler
   - Adicione logging de auditoria para todas as ações administrativas
3. Para rotas \`/internal\`:
   - Restrinja por IP (allowlist de IPs internos) ou por network policy
   - Nunca exponha ao público na internet
4. Revise todos os middlewares aplicados nessas rotas e confirme a cadeia de autenticação

**Critério de conclusão:** Rotas /debug removidas em produção. Rotas /admin com auth+role verificados. Rotas /internal inacessíveis externamente.
`.trim();
  },

  'React / Frontend Anti-patterns': (findings, projectRoot) => {
    const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n');
    return `
Você é um engenheiro frontend garantindo boas práticas de segurança no lado do cliente.

**Contexto:** ${findings.length} anti-pattern(s) de segurança frontend detectado(s).

**Arquivos afetados:**
${files}

**Sua tarefa — execute em ordem:**
1. **localStorage com dados sensíveis:** substitua por cookies httpOnly gerenciados pelo servidor
   - Tokens JWT não devem nunca ser armazenados em localStorage (vulnerável a XSS)
   - Configure o cookie no backend: \`res.cookie('token', jwt, { httpOnly: true, secure: true, sameSite: 'strict' })\`
2. **Variáveis de ambiente privadas no frontend:**
   - Apenas variáveis prefixadas com \`VITE_\` ou \`REACT_APP_\` devem ser usadas no frontend
   - API keys privadas, secrets de backend nunca devem aparecer no bundle do frontend
3. **window.__INITIAL_STATE__ com dados sensíveis:**
   - Nunca inclua passwords, tokens ou dados pessoais sensíveis no estado inicial injetado no HTML

**Critério de conclusão:** Nenhum token/credencial em localStorage. Frontend usa apenas variáveis públicas de ambiente.
`.trim();
  },

  // ── CONFIG / INFRAESTRUTURA ────────────────────────────────────────────────

  'Missing .gitignore': () => `
Você é um engenheiro DevOps garantindo que arquivos sensíveis não sejam versionados.

**Contexto:** Não foi encontrado arquivo \`.gitignore\` no projeto, ou ele está incompleto.

**Sua tarefa — execute em ordem:**
1. Crie ou abra o arquivo \`.gitignore\` na raiz do projeto
2. Adicione no mínimo as seguintes entradas:
   \`\`\`
   node_modules/
   .env
   .env.local
   .env.*.local
   .env.production
   *.log
   dist/
   build/
   coverage/
   .DS_Store
   \`\`\`
3. Verifique se algum arquivo sensível já foi commitado: \`git log --all --full-history -- "**/.env"\`
4. Se sim, use \`git filter-branch\` ou BFG Repo Cleaner para remover do histórico
5. Rotacione IMEDIATAMENTE qualquer credencial que possa ter sido exposta

**Critério de conclusão:** .gitignore presente e cobrindo todos os arquivos sensíveis. Histórico do git limpo de secrets.
`.trim(),

  'Missing Helmet.js / Security Headers': () => `
Você é um engenheiro de segurança configurando headers HTTP de proteção.

**Contexto:** Nenhuma biblioteca de security headers (helmet, @fastify/helmet) foi detectada.

**Sua tarefa — execute em ordem:**
1. Instale o pacote adequado:
   - Express: \`npm install helmet\`
   - Fastify: \`npm install @fastify/helmet\`
2. Configure no arquivo principal da aplicação, ANTES de qualquer rota:
   \`\`\`js
   // Express
   const helmet = require('helmet');
   app.use(helmet());
   
   // Configuração customizada recomendada:
   app.use(helmet({
     contentSecurityPolicy: {
       directives: {
         defaultSrc: ["'self'"],
         scriptSrc: ["'self'"],
         styleSrc: ["'self'", "'unsafe-inline'"],
       }
     },
     hsts: { maxAge: 31536000, includeSubDomains: true }
   }));
   \`\`\`
3. Valide os headers em produção usando: https://securityheaders.com

**Critério de conclusão:** helmet instalado e ativo. Headers X-Frame-Options, CSP, HSTS, X-Content-Type-Options todos presentes nas respostas.
`.trim(),

  'No Rate Limiting Package': () => `
Você é um engenheiro backend protegendo a API contra abuso automatizado.

**Contexto:** Nenhuma biblioteca de rate limiting foi detectada no package.json.

**Sua tarefa:**
1. Instale: \`npm install express-rate-limit\` (Express) ou \`npm install @fastify/rate-limit\` (Fastify)
2. Aplique globalmente e com limites mais rígidos nos endpoints de autenticação
3. Consulte o prompt de correção "Missing Rate Limiting" para instruções detalhadas

**Critério de conclusão:** Rate limiting ativo globalmente e nos endpoints críticos.
`.trim(),

};

// ─── Fallback genérico ────────────────────────────────────────────────────────

function genericPrompt(label, findings, projectRoot) {
  const files = uniqueFiles(findings).map(f => `- \`${relPath(f, projectRoot)}\``).join('\n') || '_(sem arquivo específico)_';
  return `
Você é um engenheiro de software revisando problemas de qualidade/segurança.

**Problema detectado:** ${label}
**Total de ocorrências:** ${findings.length}

**Arquivos afetados:**
${files}

**Ocorrências:**
${findings.slice(0, 5).map(f => `- ${f.description}${f.file ? ` — \`${relPath(f.file, projectRoot)}:${f.line || ''}\`` : ''}`).join('\n')}

**Sua tarefa:**
1. Abra cada arquivo listado e localize as ocorrências descritas acima
2. Avalie o impacto de cada ocorrência no contexto do projeto
3. Aplique a correção adequada seguindo as boas práticas da tecnologia em uso
4. Teste as correções para garantir que o comportamento do sistema não foi alterado

**Critério de conclusão:** Todas as ocorrências de "${label}" resolvidas ou documentadas com justificativa técnica.
`.trim();
}

// ─── Builder do documento de prompts ─────────────────────────────────────────

function buildPromptDoc({ projectName, projectRoot, allFindings, counts, rating, reportFilename }) {
  const sorted = sortBySeverity(allFindings);
  const grouped = groupByLabel(sorted);

  const lines = [
    `# 🤖 Playbook de Correções — ${projectName}`,
    ``,
    `> **Gerado em:** ${timestamp()}`,
    `> **Relatório de referência:** \`${reportFilename}\``,
    `> **Score atual:** ${rating.score}/100 (${rating.grade}) — ${rating.verdict}`,
    ``,
    `---`,
    ``,
    `## 📋 Como usar este playbook`,
    ``,
    `Este arquivo contém **${Object.keys(grouped).length} prompt(s) de correção**, um por categoria de problema encontrado.`,
    `Cada prompt foi gerado a partir dos achados reais da auditoria e pode ser executado:`,
    ``,
    `- **Manualmente:** Leia o prompt, abra os arquivos indicados e aplique as correções descritas`,
    `- **Via agente de IA:** Cole o prompt em um agente (Claude, Cursor, Copilot) apontando para o repositório`,
    `- **Via CLI:** Use com ferramentas como \`aider\` ou \`claude-code\` passando o prompt como instrução`,
    ``,
    `**Ordem de execução recomendada:** Siga a sequência numérica abaixo — os itens críticos vêm primeiro.`,
    ``,
    `---`,
    ``,
    `## 📊 Resumo dos problemas a corrigir`,
    ``,
    `| # | Categoria | Severidade | Ocorrências | Status |`,
    `|---|-----------|-----------|------------|--------|`,
  ];

  const sortedLabels = Object.entries(grouped).sort(([, a], [, b]) =>
    (SEVERITY_ORDER[a[0].severity] ?? 9) - (SEVERITY_ORDER[b[0].severity] ?? 9)
  );

  sortedLabels.forEach(([label, items], idx) => {
    const sev = items[0].severity;
    const emoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: '⚪' }[sev];
    const label_pt = { CRITICAL: 'CRÍTICO', HIGH: 'ALTO', MEDIUM: 'MÉDIO', LOW: 'BAIXO', INFO: 'INFO' }[sev];
    lines.push(`| ${idx + 1} | ${label} | ${emoji} ${label_pt} | ${items.length} | ☐ Pendente |`);
  });

  lines.push(``, `---`, ``);

  // ── Gera um prompt por categoria ──
  sortedLabels.forEach(([label, items], idx) => {
    const sev = items[0].severity;
    const emoji = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: '⚪' }[sev];
    const label_pt = { CRITICAL: 'CRÍTICO', HIGH: 'ALTO', MEDIUM: 'MÉDIO', LOW: 'BAIXO', INFO: 'INFO' }[sev];

    lines.push(`## Prompt ${idx + 1} — ${label}`);
    lines.push(``);
    lines.push(`> ${emoji} **Severidade:** ${label_pt} | **Ocorrências:** ${items.length}`);
    lines.push(``);
    lines.push(`\`\`\`prompt`);

    const templateFn = PROMPT_TEMPLATES[label];
    const promptText = templateFn
      ? templateFn(items, projectRoot)
      : genericPrompt(label, items, projectRoot);

    lines.push(promptText);
    lines.push(`\`\`\``);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  });

  // ── Prompt de verificação final ──
  lines.push(`## Prompt Final — Verificação Geral`);
  lines.push(``);
  lines.push(`> ✅ Execute este prompt após concluir todas as correções acima`);
  lines.push(``);
  lines.push(`\`\`\`prompt`);
  lines.push(`Você é um engenheiro de segurança e qualidade fazendo a revisão final do projeto ${projectName}.`);
  lines.push(``);
  lines.push(`Todas as correções do playbook de auditoria foram aplicadas. Sua tarefa de verificação:`);
  lines.push(``);
  lines.push(`1. **Segurança:** Confirme que não existe nenhuma query SQL com concatenação de string. Confirme que não há secrets hardcoded. Confirme que CORS está restrito a origens explícitas.`);
  lines.push(`2. **Performance:** Confirme que nenhum endpoint retorna resultados sem LIMIT. Confirme que não há queries dentro de loops.`);
  lines.push(`3. **Qualidade:** Confirme que todas as funções async têm try/catch. Confirme que não há console.log em código de produção. Confirme que todos os inputs de usuário passam por validação de schema.`);
  lines.push(`4. **Infraestrutura:** Confirme que .gitignore cobre .env e node_modules. Confirme que helmet está ativo. Confirme que rate limiting está configurado.`);
  lines.push(`5. **Testes:** Execute a suite de testes (se existir) e confirme que não há regressões.`);
  lines.push(`6. Gere um resumo final listando o que foi corrigido, o que ficou pendente e qualquer risco residual identificado.`);
  lines.push(`\`\`\``);
  lines.push(``);
  lines.push(`---`);
  lines.push(``);
  lines.push(`_Playbook gerado automaticamente pelo Project Auditor Agent. Os prompts são ponto de partida — adapte ao contexto específico do projeto quando necessário._`);

  return lines.join('\n');
}

module.exports = { buildPromptDoc };
