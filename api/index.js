'use strict';
/**
 * Nexo CRM — API privada (Vercel Serverless + Neon Postgres).
 * Mismo protocolo que el Code.gs original: POST /api { action, token, ... }
 */
const crypto = require('crypto');
const { neon } = require('@neondatabase/serverless');

const SESSION_SECONDS = 21600; // 6 horas
const MAX_FAILS = 8;
const FAIL_WINDOW_MIN = 10;
const STAGES = ['Nuevo', 'Contactado', 'Propuesta', 'Negociación', 'Ganado', 'Perdido'];

const COLS = {
  contacts: ['id', 'createdAt', 'updatedAt', 'name', 'company', 'email', 'phone', 'status', 'source', 'owner', 'notes', 'archived'],
  opportunities: ['id', 'createdAt', 'updatedAt', 'title', 'contactId', 'value', 'stage', 'probability', 'owner', 'expectedClose', 'lastActivity', 'notes', 'lostReason', 'archived'],
  follow_ups: ['id', 'createdAt', 'updatedAt', 'opportunityId', 'contactId', 'title', 'dueAt', 'type', 'owner', 'status', 'notes', 'completedAt'],
  conversations: ['id', 'createdAt', 'contactId', 'opportunityId', 'channel', 'direction', 'summary', 'owner'],
  quotes: ['id', 'createdAt', 'updatedAt', 'quoteNumber', 'contactId', 'opportunityId', 'subtotal', 'taxRate', 'taxAmount', 'total', 'currency', 'status', 'validUntil', 'itemsJson', 'notes', 'owner'],
  sellers: ['id', 'createdAt', 'updatedAt', 'name', 'email', 'passwordHash', 'role', 'active']
};

let _sql;
function db() {
  if (!process.env.DATABASE_URL) throw apiError('Falta la variable DATABASE_URL en Vercel.', 'NOT_CONFIGURED');
  if (!_sql) _sql = neon(process.env.DATABASE_URL);
  return _sql;
}
async function q(text, params) { return db().query(text, params || []); }

function apiError(message, code) {
  const e = new Error(message);
  e.code = code;
  e.isApi = true;
  return e;
}

// ---------- utilidades ----------
const now = () => new Date().toISOString();
const sha256 = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const newId = prefix => prefix + '-' + Date.now().toString(36).toUpperCase() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
const cleanText = (v, max) => String(v == null ? '' : v).replace(/\u0000/g, '').trim().slice(0, max || 500);
const normEmail = v => cleanText(v, 180).toLowerCase();
const cleanChoice = (v, choices, fallback) => (choices.includes(String(v || '')) ? String(v) : fallback);
const clamp = (v, min, max, fallback) => { const n = Number(v); return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback; };
const roundMoney = v => Math.round((Number(v) + Number.EPSILON) * 100) / 100;
const requireText = (v, msg) => { if (!String(v || '').trim()) throw apiError(msg, 'VALIDATION'); };
const defaultProbability = s => ({ Nuevo: 10, Contactado: 25, Propuesta: 50, 'Negociación': 75, Ganado: 100, Perdido: 0 }[s] ?? 10);

function cleanDate(v) {
  if (!v) return '';
  const s = String(v);
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s;
  const d = new Date(s);
  return isNaN(d.getTime()) ? '' : d.toISOString().slice(0, 10);
}
function cleanDateTime(v) {
  if (!v) return '';
  const d = new Date(v);
  return isNaN(d.getTime()) ? '' : d.toISOString();
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return 's1$' + salt + '$' + hash;
}
function verifyPassword(password, stored) {
  const parts = String(stored || '').split('$');
  if (parts.length !== 3 || parts[0] !== 's1') return false;
  const expected = Buffer.from(parts[2], 'hex');
  const actual = crypto.scryptSync(String(password), parts[1], 64);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

// ---------- acceso a datos ----------
async function upsert(table, item) {
  const cols = COLS[table];
  const names = cols.map(c => '"' + c + '"').join(', ');
  const marks = cols.map((_, i) => '$' + (i + 1)).join(', ');
  const updates = cols.slice(1).map(c => '"' + c + '" = EXCLUDED."' + c + '"').join(', ');
  await q(
    'INSERT INTO ' + table + ' (' + names + ') VALUES (' + marks + ') ON CONFLICT ("id") DO UPDATE SET ' + updates,
    cols.map(c => item[c])
  );
  return item;
}
async function findById(table, id) {
  if (!id) return null;
  const rows = await q('SELECT * FROM ' + table + ' WHERE "id" = $1 LIMIT 1', [String(id)]);
  return rows[0] || null;
}
async function requireRecord(table, id, message) {
  const row = await findById(table, id);
  if (!row) throw apiError(message, 'NOT_FOUND');
  return row;
}
const publicSeller = s => ({ id: s.id, name: s.name, email: normEmail(s.email), role: s.role || 'seller', active: !!s.active });

// ---------- sesión / login ----------
async function ensureAdmin(email, password) {
  const adminEmail = normEmail(process.env.ADMIN_EMAIL);
  if (!adminEmail || !process.env.ADMIN_PASSWORD) return;
  if (email !== adminEmail || password !== process.env.ADMIN_PASSWORD) return;
  const exists = await q('SELECT 1 FROM sellers WHERE lower("email") = $1 LIMIT 1', [adminEmail]);
  if (exists.length) return;
  const t = now();
  await upsert('sellers', {
    id: newId('USR'), createdAt: t, updatedAt: t,
    name: cleanText(process.env.ADMIN_NAME || 'Administrador', 120),
    email: adminEmail, passwordHash: hashPassword(password), role: 'admin', active: true
  });
  if (process.env.COMPANY_NAME) {
    await q('INSERT INTO settings ("key","value") VALUES ($1,$2) ON CONFLICT ("key") DO UPDATE SET "value" = EXCLUDED."value"',
      ['companyName', cleanText(process.env.COMPANY_NAME, 120)]);
  }
}

async function login(req) {
  const email = normEmail(req.email);
  const password = String(req.password || '');
  if (!email || !password) throw apiError('Ingresá tu email y contraseña.', 'VALIDATION');

  const fails = await q(
    'SELECT count(*)::int AS n FROM login_attempts WHERE "email" = $1 AND "at" > now() - ($2 || \' minutes\')::interval',
    [email, String(FAIL_WINDOW_MIN)]
  );
  if (fails[0].n >= MAX_FAILS) {
    throw apiError('Demasiados intentos. Esperá 10 minutos antes de volver a ingresar.', 'RATE_LIMIT');
  }

  await ensureAdmin(email, password);
  const rows = await q('SELECT * FROM sellers WHERE lower("email") = $1 AND "active" = TRUE LIMIT 1', [email]);
  const seller = rows[0];
  if (!seller || !verifyPassword(password, seller.passwordHash)) {
    await q('INSERT INTO login_attempts ("email") VALUES ($1)', [email]);
    throw apiError('Email o contraseña incorrectos.', 'UNAUTHORIZED');
  }
  await q('DELETE FROM login_attempts WHERE "email" = $1', [email]);
  await q('DELETE FROM login_attempts WHERE "at" < now() - interval \'1 day\'');
  await q('DELETE FROM sessions WHERE "expiresAt" < now()');

  const token = crypto.randomBytes(32).toString('hex');
  await q(
    'INSERT INTO sessions ("tokenHash","sellerId","expiresAt") VALUES ($1,$2, now() + ($3 || \' seconds\')::interval)',
    [sha256(token), seller.id, String(SESSION_SECONDS)]
  );
  return { ok: true, token, user: publicSeller(seller), expiresIn: SESSION_SECONDS };
}

async function requireSession(token) {
  const t = String(token || '');
  if (!t) throw apiError('Tu sesión venció. Volvé a ingresar.', 'UNAUTHORIZED');
  const rows = await q(
    'SELECT s."id", s."name", s."email", s."role" FROM sessions x JOIN sellers s ON s."id" = x."sellerId" ' +
    'WHERE x."tokenHash" = $1 AND x."expiresAt" > now() AND s."active" = TRUE LIMIT 1',
    [sha256(t)]
  );
  if (!rows[0]) throw apiError('Tu sesión venció. Volvé a ingresar.', 'UNAUTHORIZED');
  return rows[0];
}

// ---------- acciones ----------
async function bootstrap(session) {
  const [settingsRows, contacts, opportunities, followUps, conversations, quotes, sellers] = await Promise.all([
    q('SELECT "key","value" FROM settings'),
    q('SELECT * FROM contacts WHERE "archived" = FALSE ORDER BY "createdAt"'),
    q('SELECT * FROM opportunities WHERE "archived" = FALSE ORDER BY "createdAt"'),
    q('SELECT * FROM follow_ups ORDER BY "dueAt"'),
    q('SELECT * FROM conversations ORDER BY "createdAt" DESC LIMIT 500'),
    q('SELECT * FROM quotes ORDER BY "createdAt"'),
    q('SELECT * FROM sellers WHERE "active" = TRUE ORDER BY "createdAt"')
  ]);
  const settings = {};
  settingsRows.forEach(r => { settings[r.key] = r.value; });
  return {
    ok: true, user: session, settings, contacts, opportunities, followUps, conversations, quotes,
    sellers: sellers.map(publicSeller), serverTime: now()
  };
}

async function saveContact(data, session) {
  data = data || {};
  requireText(data.name, 'El nombre del contacto es obligatorio.');
  const cur = data.id ? await findById('contacts', data.id) : null;
  const t = now();
  const item = {
    id: cur ? cur.id : newId('CON'), createdAt: cur ? cur.createdAt : t, updatedAt: t,
    name: cleanText(data.name, 120), company: cleanText(data.company, 120),
    email: normEmail(data.email), phone: cleanText(data.phone, 60),
    status: cleanChoice(data.status, ['Prospecto', 'Cliente', 'Inactivo'], 'Prospecto'),
    source: cleanText(data.source, 80), owner: cleanText(data.owner || session.name, 120),
    notes: cleanText(data.notes, 2000), archived: false
  };
  await upsert('contacts', item);
  return { ok: true, item };
}

async function archiveRow(table, id, msg) {
  const row = await requireRecord(table, id, msg);
  row.archived = true;
  row.updatedAt = now();
  await upsert(table, row);
  return { ok: true, id };
}

async function saveOpportunity(data, session) {
  data = data || {};
  requireText(data.title, 'El nombre de la oportunidad es obligatorio.');
  const cur = data.id ? await findById('opportunities', data.id) : null;
  const t = now();
  const stage = cleanChoice(data.stage, STAGES, 'Nuevo');
  const item = {
    id: cur ? cur.id : newId('OPP'), createdAt: cur ? cur.createdAt : t, updatedAt: t,
    title: cleanText(data.title, 160), contactId: cleanText(data.contactId, 80),
    value: clamp(data.value, 0, 999999999999, 0), stage,
    probability: clamp(data.probability, 0, 100, defaultProbability(stage)),
    owner: cleanText(data.owner || session.name, 120), expectedClose: cleanDate(data.expectedClose),
    lastActivity: cur ? (cur.lastActivity || t) : t, notes: cleanText(data.notes, 3000),
    lostReason: stage === 'Perdido' ? cleanText(data.lostReason, 500) : '', archived: false
  };
  await upsert('opportunities', item);
  return { ok: true, item };
}

async function changeStage(id, stage, session) {
  const next = cleanChoice(stage, STAGES, '');
  if (!next) throw apiError('Etapa inválida.', 'VALIDATION');
  const opp = await requireRecord('opportunities', id, 'Oportunidad no encontrada.');
  const previous = opp.stage;
  const t = now();
  opp.stage = next;
  opp.probability = defaultProbability(next);
  opp.lastActivity = t;
  opp.updatedAt = t;
  await upsert('opportunities', opp);
  await upsert('conversations', {
    id: newId('ACT'), createdAt: t, contactId: opp.contactId, opportunityId: opp.id,
    channel: 'Sistema', direction: 'Nota', summary: 'Etapa actualizada: ' + previous + ' → ' + next, owner: session.name
  });
  return { ok: true, item: opp };
}

async function saveFollowUp(data, session) {
  data = data || {};
  requireText(data.title, 'El asunto del seguimiento es obligatorio.');
  if (!cleanDateTime(data.dueAt)) throw apiError('Elegí la fecha y hora del seguimiento.', 'VALIDATION');
  const cur = data.id ? await findById('follow_ups', data.id) : null;
  const t = now();
  const item = {
    id: cur ? cur.id : newId('SEG'), createdAt: cur ? cur.createdAt : t, updatedAt: t,
    opportunityId: cleanText(data.opportunityId, 80), contactId: cleanText(data.contactId, 80),
    title: cleanText(data.title, 180), dueAt: cleanDateTime(data.dueAt),
    type: cleanChoice(data.type, ['Llamada', 'Email', 'Reunión', 'WhatsApp', 'Tarea'], 'Tarea'),
    owner: cleanText(data.owner || session.name, 120), status: cur ? cur.status : 'Pendiente',
    notes: cleanText(data.notes, 2000), completedAt: cur ? cur.completedAt : ''
  };
  await upsert('follow_ups', item);
  return { ok: true, item };
}

async function completeFollowUp(id, completed) {
  const row = await requireRecord('follow_ups', id, 'Seguimiento no encontrado.');
  const done = completed !== false;
  const t = now();
  row.status = done ? 'Completado' : 'Pendiente';
  row.completedAt = done ? t : '';
  row.updatedAt = t;
  await upsert('follow_ups', row);
  return { ok: true, item: row };
}

async function saveConversation(data, session) {
  data = data || {};
  requireText(data.summary, 'Escribí un resumen de la conversación.');
  const item = {
    id: newId('MSG'), createdAt: now(),
    contactId: cleanText(data.contactId, 80), opportunityId: cleanText(data.opportunityId, 80),
    channel: cleanChoice(data.channel, ['Llamada', 'Email', 'WhatsApp', 'Reunión', 'Nota', 'Sistema'], 'Nota'),
    direction: cleanChoice(data.direction, ['Entrante', 'Saliente', 'Nota'], 'Nota'),
    summary: cleanText(data.summary, 3000), owner: cleanText(data.owner || session.name, 120)
  };
  await upsert('conversations', item);
  if (item.opportunityId) {
    const opp = await findById('opportunities', item.opportunityId);
    if (opp) {
      opp.lastActivity = item.createdAt;
      opp.updatedAt = item.createdAt;
      await upsert('opportunities', opp);
    }
  }
  return { ok: true, item };
}

async function nextQuoteNumber() {
  const year = String(new Date().getFullYear());
  const rows = await q(
    'INSERT INTO counters ("key","value") VALUES ($1, 1) ON CONFLICT ("key") DO UPDATE SET "value" = counters."value" + 1 RETURNING "value"',
    ['QUOTE_' + year]
  );
  return 'COT-' + year + '-' + String(rows[0].value).padStart(4, '0');
}

async function saveQuote(data, session) {
  data = data || {};
  const items = (Array.isArray(data.items) ? data.items : []).map(it => {
    const quantity = clamp(it.quantity, 0, 999999, 1);
    const price = clamp(it.price, 0, 999999999999, 0);
    return { description: cleanText(it.description, 200), quantity, price, total: roundMoney(quantity * price) };
  }).filter(it => it.description);
  if (!items.length) throw apiError('Agregá al menos un ítem a la cotización.', 'VALIDATION');

  const cur = data.id ? await findById('quotes', data.id) : null;
  const subtotal = roundMoney(items.reduce((s, it) => s + it.total, 0));
  const taxRate = clamp(data.taxRate, 0, 100, 0);
  const taxAmount = roundMoney(subtotal * taxRate / 100);
  const t = now();
  const item = {
    id: cur ? cur.id : newId('COT'), createdAt: cur ? cur.createdAt : t, updatedAt: t,
    quoteNumber: cur ? cur.quoteNumber : await nextQuoteNumber(),
    contactId: cleanText(data.contactId, 80), opportunityId: cleanText(data.opportunityId, 80),
    subtotal, taxRate, taxAmount, total: roundMoney(subtotal + taxAmount),
    currency: cleanChoice(data.currency, ['ARS', 'USD', 'EUR', 'UYU', 'CLP', 'MXN'], 'ARS'),
    status: cleanChoice(data.status, ['Borrador', 'Enviada', 'Aceptada', 'Rechazada', 'Vencida'], 'Borrador'),
    validUntil: cleanDate(data.validUntil), itemsJson: JSON.stringify(items),
    notes: cleanText(data.notes, 2000), owner: cleanText(data.owner || session.name, 120)
  };
  await upsert('quotes', item);
  return { ok: true, item };
}

async function saveSeller(data) {
  data = data || {};
  requireText(data.name, 'El nombre del vendedor es obligatorio.');
  const email = normEmail(data.email);
  if (!email || email.indexOf('@') < 1) throw apiError('Ingresá un email válido.', 'VALIDATION');
  const cur = data.id ? await findById('sellers', data.id) : null;
  const dup = await q('SELECT "id" FROM sellers WHERE lower("email") = $1 LIMIT 1', [email]);
  if (dup[0] && (!cur || dup[0].id !== cur.id)) throw apiError('Ya existe un usuario con ese email.', 'VALIDATION');
  const password = String(data.password || '');
  if (!cur && password.length < 8) throw apiError('La contraseña debe tener al menos 8 caracteres.', 'VALIDATION');
  if (cur && password && password.length < 8) throw apiError('La contraseña debe tener al menos 8 caracteres.', 'VALIDATION');
  const t = now();
  const item = {
    id: cur ? cur.id : newId('USR'), createdAt: cur ? cur.createdAt : t, updatedAt: t,
    name: cleanText(data.name, 120), email,
    passwordHash: password ? hashPassword(password) : cur.passwordHash,
    role: cleanChoice(data.role, ['admin', 'seller'], 'seller'), active: data.active !== false
  };
  await upsert('sellers', item);
  return { ok: true, item: publicSeller(item) };
}

// ---------- handler ----------
function parseBody(req) {
  let b = req.body;
  if (Buffer.isBuffer(b)) b = b.toString('utf8');
  if (typeof b === 'string') { try { b = JSON.parse(b); } catch (_) { b = {}; } }
  return b && typeof b === 'object' ? b : {};
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  const send = (payload, status) => res.status(status || 200).send(JSON.stringify(payload));

  if (req.method === 'GET') {
    try { await q('SELECT 1'); return send({ ok: true, app: 'Nexo CRM', status: 'online', db: true, timestamp: now() }); }
    catch (e) { return send({ ok: false, app: 'Nexo CRM', status: 'online', db: false, error: e.message }); }
  }
  if (req.method !== 'POST') return send({ ok: false, error: 'Método no permitido.', code: 'BAD_REQUEST' }, 405);

  try {
    const r = parseBody(req);
    const action = String(r.action || '').trim();
    if (!action) throw apiError('Falta indicar la acción.', 'BAD_REQUEST');
    if (action === 'ping') return send({ ok: true, timestamp: now() });
    if (action === 'login') return send(await login(r));

    const session = await requireSession(r.token);
    switch (action) {
      case 'bootstrap': return send(await bootstrap(session));
      case 'saveContact': return send(await saveContact(r.data, session));
      case 'archiveContact': return send(await archiveRow('contacts', r.id, 'Contacto no encontrado.'));
      case 'saveOpportunity': return send(await saveOpportunity(r.data, session));
      case 'archiveOpportunity': return send(await archiveRow('opportunities', r.id, 'Oportunidad no encontrada.'));
      case 'changeStage': return send(await changeStage(r.id, r.stage, session));
      case 'saveFollowUp': return send(await saveFollowUp(r.data, session));
      case 'completeFollowUp': return send(await completeFollowUp(r.id, r.completed));
      case 'saveConversation': return send(await saveConversation(r.data, session));
      case 'saveQuote': return send(await saveQuote(r.data, session));
      case 'saveSeller':
        if (session.role !== 'admin') throw apiError('Esta acción requiere permisos de administrador.', 'FORBIDDEN');
        return send(await saveSeller(r.data));
      case 'logout':
        await q('DELETE FROM sessions WHERE "tokenHash" = $1', [sha256(String(r.token || ''))]);
        return send({ ok: true });
      default: throw apiError('Acción no reconocida.', 'NOT_FOUND');
    }
  } catch (error) {
    console.error(error && error.stack ? error.stack : error);
    const known = !!(error && error.isApi);
    return send({
      ok: false,
      error: known ? error.message : 'Ocurrió un error en el servidor. Revisá los logs en Vercel.',
      code: known ? error.code : 'SERVER_ERROR'
    });
  }
};
