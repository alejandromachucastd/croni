// Servidor de Horario · Enlaces
// API sencilla con sesiones (cookie) + almacenamiento en archivos JSON.
// No requiere internet: todo corre en localhost.

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SCHEDULES_FILE = path.join(DATA_DIR, 'schedules.json');
const SECRET_FILE = path.join(DATA_DIR, 'session-secret.txt');

// Si hay MONGODB_URI, los datos se guardan en MongoDB Atlas (persistente en
// hosts con disco efímero, como Render). Si no, se guardan en archivos JSON
// locales (modo original, sin necesidad de internet).
const MONGODB_URI = process.env.MONGODB_URI || '';
let usersCol = null, schedulesCol = null;

async function initStorage() {
  if (!MONGODB_URI) return;
  const { MongoClient } = require('mongodb');
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  const db = client.db(process.env.MONGODB_DB || 'croni');
  usersCol = db.collection('users');
  schedulesCol = db.collection('schedules');
  console.log('Almacenamiento: MongoDB Atlas.');
}

if (!MONGODB_URI) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '{}', 'utf8');
  if (!fs.existsSync(SCHEDULES_FILE)) fs.writeFileSync(SCHEDULES_FILE, '{}', 'utf8');
}

function readJSON(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (e) { return fallback; }
}
// Escritura atómica: primero a un temporal y luego rename, para que un corte
// a medio guardar nunca deje el archivo a la mitad.
function writeJSON(file, obj) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), 'utf8');
  fs.renameSync(tmp, file);
}

// En modo archivos JSON, las operaciones de leer-modificar-escribir se hacen en
// fila (una a la vez) para que dos peticiones simultáneas no se pisen.
let fileQueue = Promise.resolve();
function withFileLock(fn) {
  const run = fileQueue.then(fn, fn);
  fileQueue = run.catch(() => {});
  return run;
}

// Cada usuario se lee y se guarda POR SEPARADO. Antes se leían y reescribían
// todos los usuarios en cada guardado, y dos personas guardando casi al mismo
// tiempo podían borrarse los cambios entre sí.
const strip = d => { if (!d) return null; const { _id, ...rest } = d; return rest; };
async function getUser(key) {
  if (usersCol) return strip(await usersCol.findOne({ _id: key }));
  return readJSON(USERS_FILE, {})[key] || null;
}
async function listUsers() {
  if (usersCol) { const obj = {}; (await usersCol.find().toArray()).forEach(d => { obj[d._id] = strip(d); }); return obj; }
  return readJSON(USERS_FILE, {});
}
async function countUsers() { return usersCol ? usersCol.countDocuments() : Object.keys(readJSON(USERS_FILE, {})).length; }
async function updateUser(key, mutate) {
  if (usersCol) {
    const next = mutate(strip(await usersCol.findOne({ _id: key })));
    if (next === null) await usersCol.deleteOne({ _id: key });
    else await usersCol.replaceOne({ _id: key }, { _id: key, ...next }, { upsert: true });
    return next;
  }
  return withFileLock(() => {
    const all = readJSON(USERS_FILE, {});
    const next = mutate(all[key] || null);
    if (next === null) delete all[key]; else all[key] = next;
    writeJSON(USERS_FILE, all);
    return next;
  });
}
async function getSchedule(key) {
  if (schedulesCol) return strip(await schedulesCol.findOne({ _id: key }));
  return readJSON(SCHEDULES_FILE, {})[key] || null;
}
async function updateSchedule(key, mutate) {
  if (schedulesCol) {
    const next = mutate(strip(await schedulesCol.findOne({ _id: key })));
    if (next === null) await schedulesCol.deleteOne({ _id: key });
    else await schedulesCol.replaceOne({ _id: key }, { _id: key, ...next }, { upsert: true });
    return next;
  }
  return withFileLock(() => {
    const all = readJSON(SCHEDULES_FILE, {});
    const next = mutate(all[key] || null);
    if (next === null) delete all[key]; else all[key] = next;
    writeJSON(SCHEDULES_FILE, all);
    return next;
  });
}

// Con MongoDB, el disco puede ser efímero (p. ej. Render), así que si no hay
// un SESSION_SECRET fijo por variable de entorno, se genera uno nuevo en
// memoria en cada arranque (las sesiones activas se cierran al reiniciar,
// pero eso no afecta a los datos guardados).
let SESSION_SECRET = process.env.SESSION_SECRET;
if (!SESSION_SECRET) {
  if (!MONGODB_URI && fs.existsSync(SECRET_FILE)) {
    SESSION_SECRET = fs.readFileSync(SECRET_FILE, 'utf8').trim();
  } else {
    SESSION_SECRET = crypto.randomBytes(32).toString('hex');
    if (!MONGODB_URI) { try { fs.writeFileSync(SECRET_FILE, SESSION_SECRET, 'utf8'); } catch (e) {} }
  }
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: SESSION_SECRET,
  name: 'horario.sid',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 30 }
}));

function requireAuth(req, res, next) {
  if (!req.session.username) return res.status(401).json({ error: 'No has iniciado sesión.' });
  next();
}
async function requireAdmin(req, res, next) {
  const user = await getUser(req.session.username);
  if (!user || !user.isAdmin) return res.status(403).json({ error: 'Solo un administrador puede ver esto.' });
  next();
}

/* ============ LOGIN CON GOOGLE (único método de acceso) ============ */
const GOOGLE_ENABLED = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback';

app.use(passport.initialize());

if (GOOGLE_ENABLED) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  }, (accessToken, refreshToken, profile, done) => done(null, profile)));

  app.get('/auth/google', passport.authenticate('google', { session: false, scope: ['profile', 'email'] }));

  app.get('/auth/google/callback',
    passport.authenticate('google', { session: false, failureRedirect: '/?googleError=1' }),
    async (req, res) => {
      const email = req.user.emails && req.user.emails[0] && req.user.emails[0].value;
      if (!email) return res.redirect('/?googleError=1');
      const key = 'google:' + email.toLowerCase();
      const displayName = req.user.displayName || email;

      let user = await getUser(key);
      if (!user) {
        const isFirst = (await countUsers()) === 0;
        user = await updateUser(key, prev => prev || {
          username: displayName, nombre: displayName, provider: 'google', email,
          isAdmin: isFirst,
          createdAt: new Date().toISOString()
        });
        await updateSchedule(key, prev => prev || { acts: {}, link: {}, categories: [], weeks: {} });
      }

      req.session.username = key;
      req.session.displayName = user.username;
      res.redirect('/');
    }
  );
}

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/config', (req, res) => {
  res.json({ googleEnabled: GOOGLE_ENABLED });
});

app.get('/api/session', async (req, res) => {
  if (!req.session.username) return res.json({ loggedIn: false });
  const user = await getUser(req.session.username);
  res.json({
    loggedIn: true, username: req.session.displayName, isAdmin: !!(user && user.isAdmin),
    provider: user ? user.provider : 'local', email: user ? (user.email || '') : '',
    createdAt: user ? user.createdAt : null
  });
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await listUsers();
  const list = Object.keys(users).map(key => {
    const u = users[key];
    return {
      key, username: u.username, nombre: u.nombre || u.username, email: u.email || '',
      provider: u.provider || 'local', isAdmin: !!u.isAdmin, createdAt: u.createdAt
    };
  }).sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
  res.json({ users: list });
});

function streakFromVisits(visits) {
  const set = new Set(visits || []);
  const d = new Date(); d.setUTCHours(0, 0, 0, 0);
  if (!set.has(d.toISOString().slice(0, 10))) d.setUTCDate(d.getUTCDate() - 1);
  let streak = 0;
  while (set.has(d.toISOString().slice(0, 10))) { streak++; d.setUTCDate(d.getUTCDate() - 1); }
  return streak;
}

function isoWeekId(d) {
  const date = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  const day = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - day + 3);
  const firstThursday = new Date(Date.UTC(date.getUTCFullYear(), 0, 4));
  const fDay = (firstThursday.getUTCDay() + 6) % 7;
  firstThursday.setUTCDate(firstThursday.getUTCDate() - fDay + 3);
  const weekNo = 1 + Math.round((date - firstThursday) / (7 * 24 * 3600 * 1000));
  return date.getUTCFullYear() + '-W' + String(weekNo).padStart(2, '0');
}
const WEEK_RE = /^\d{4}-W\d{2}$/;

// Rango permitido para navegar/guardar semanas: 1 año hacia atrás, 2 años hacia adelante.
const PAST_LIMIT_DAYS = 365;
const FUTURE_LIMIT_DAYS = 730;

function mondayFromWeekId(weekId) {
  const [y, w] = weekId.split('-W').map(Number);
  const jan4 = new Date(Date.UTC(y, 0, 4));
  const jan4Day = (jan4.getUTCDay() + 6) % 7;
  const week1Monday = new Date(jan4); week1Monday.setUTCDate(jan4.getUTCDate() - jan4Day);
  const monday = new Date(week1Monday); monday.setUTCDate(week1Monday.getUTCDate() + (w - 1) * 7);
  return monday;
}
function daysFromToday(weekId) {
  const todayMonday = mondayFromWeekId(isoWeekId(new Date()));
  return Math.round((mondayFromWeekId(weekId) - todayMonday) / 86400000);
}
function weekWithinLimits(weekId) {
  const diff = daysFromToday(weekId);
  return diff >= -PAST_LIMIT_DAYS && diff <= FUTURE_LIMIT_DAYS;
}
function addDays(d, n) { const nd = new Date(d); nd.setUTCDate(nd.getUTCDate() + n); return nd; }
const MIN_WEEK = isoWeekId(addDays(new Date(), -PAST_LIMIT_DAYS));
const MAX_WEEK = isoWeekId(addDays(new Date(), FUTURE_LIMIT_DAYS));

/* ============ FRANJAS PERSONALIZABLES ============ */
// Formato 2 de celdas: llave "día|minutoDeInicio" y cada celda guarda su "end" (minuto de fin).
// Formato 1 (anterior): llave "día|fila" con 17 filas fijas de 1 h desde las 5:00.
const LEGACY_ROWS = 17, LEGACY_START = 300;
function migrateCellV1(cell) {
  const out = {}, unmapped = {};
  Object.entries(cell || {}).forEach(([k, v]) => {
    const m = /^(\d)\|(\d+)$/.exec(k);
    const di = m ? +m[1] : -1, r = m ? +m[2] : -1;
    if (m && di <= 6 && r < LEGACY_ROWS && v && typeof v === 'object') {
      out[di + '|' + (LEGACY_START + 60 * r)] = { ...v, end: LEGACY_START + 60 * (r + 1) };
    } else unmapped[k] = v;
  });
  return { out, unmapped };
}
// Convierte TODAS las semanas guardadas y el horario heredado. Idempotente: si ya
// está en formato 2 no hace nada. Guarda una copia del formato anterior por si acaso.
function migrateRec(rec) {
  if (!rec || rec.cellFormat === 2) return rec;
  const next = { ...rec };
  if (!next.legacyBackup) next.legacyBackup = { cell: rec.cell || null, weeks: rec.weeks || null, savedAt: new Date().toISOString() };
  const unmapped = {};
  if (rec.cell) { const r = migrateCellV1(rec.cell); next.cell = r.out; if (Object.keys(r.unmapped).length) unmapped.cell = r.unmapped; }
  if (rec.weeks) {
    next.weeks = {};
    Object.entries(rec.weeks).forEach(([wk, w]) => {
      const r = migrateCellV1((w && w.cell) || {});
      next.weeks[wk] = { ...(w || {}), cell: r.out };
      if (Object.keys(r.unmapped).length) unmapped[wk] = r.unmapped;
    });
  }
  if (Object.keys(unmapped).length) next.migrationUnmapped = unmapped;
  next.cellFormat = 2;
  return next;
}
function validSlots(slots) {
  if (!Array.isArray(slots) || slots.length < 1 || slots.length > 96) return false;
  let prevEnd = -1;
  for (const sl of slots) {
    if (!sl || !Number.isInteger(sl.start) || !Number.isInteger(sl.end)) return false;
    if (sl.start < 0 || sl.end > 1440 || sl.end - sl.start < 15) return false;
    if (sl.start < prevEnd) return false; // ordenadas y sin traslapes
    prevEnd = sl.end;
  }
  return true;
}
async function ensureMigrated(key) {
  const rec = await getSchedule(key);
  if (!rec || rec.cellFormat === 2) return rec;
  return updateSchedule(key, prev => migrateRec(prev));
}

function cellForWeek(rec, weekId) {
  const weeks = rec.weeks || {};
  if (weeks[weekId]) return weeks[weekId].cell || {};
  const priorKeys = Object.keys(weeks).filter(k => k <= weekId).sort();
  if (priorKeys.length) return weeks[priorKeys[priorKeys.length - 1]].cell || {};
  return rec.cell || {}; // horario heredado de antes de que existieran semanas por fecha
}

app.get('/api/schedule', requireAuth, async (req, res) => {
  const key = req.session.username;
  let weekId = WEEK_RE.test(req.query.week || '') ? req.query.week : isoWeekId(new Date());
  if (!weekWithinLimits(weekId)) weekId = isoWeekId(new Date());
  let rec = (await ensureMigrated(key)) || { acts: {}, link: {}, categories: [], cellFormat: 2 };
  const today = new Date().toISOString().slice(0, 10);
  if (!(rec.visits || []).includes(today)) {
    rec = await updateSchedule(key, prev => {
      const base = prev || rec;
      const v = (base.visits || []).slice();
      if (!v.includes(today)) v.push(today);
      if (v.length > 400) v.splice(0, v.length - 400);
      return { ...base, visits: v };
    });
  }
  const visits = rec.visits || [];
  res.json({
    acts: rec.acts || {}, link: rec.link || {}, categories: rec.categories || [],
    habits: rec.habits || [], goals: rec.goals || [], habitCategories: rec.habitCategories || [],
    habitsBestStreak: rec.habitsBestStreak || 0, onboarded: !!rec.onboarded,
    routines: rec.routines || null, reminders: rec.reminders || [],
    slots: validSlots(rec.slots) ? rec.slots : null, cellFormat: 2,
    dailyPlanning: {
      enabled: !(rec.dailyPlanning && rec.dailyPlanning.enabled === false),
      tasksEnabled: !(rec.dailyPlanning && rec.dailyPlanning.tasksEnabled === false)
    },
    cell: cellForWeek(rec, weekId), weekId, streak: streakFromVisits(visits),
    minWeek: MIN_WEEK, maxWeek: MAX_WEEK
  });
});

app.put('/api/schedule', requireAuth, async (req, res) => {
  const { week, acts, link, categories, cell, habits, goals, habitCategories, habitsBestStreak, routines, reminders, slots, cellFormat } = req.body || {};
  if (typeof acts !== 'object' || typeof link !== 'object' || typeof cell !== 'object' || !Array.isArray(categories)
    || !Array.isArray(habits || []) || !Array.isArray(goals || []) || !Array.isArray(habitCategories || [])
    || !Array.isArray(reminders || [])) {
    return res.status(400).json({ error: 'Formato de horario inválido.' });
  }
  if (!WEEK_RE.test(week || '')) return res.status(400).json({ error: 'Semana inválida.' });
  if (!weekWithinLimits(week)) {
    return res.status(400).json({ error: 'Esa semana está fuera del rango permitido (hasta 1 año atrás o 2 años adelante).' });
  }
  if (slots !== undefined && slots !== null && !validSlots(slots)) return res.status(400).json({ error: 'Las franjas no son válidas (revisa horas, traslapes o duración mínima de 15 min).' });
  const key = req.session.username;
  const current = await ensureMigrated(key);
  // Una pestaña vieja (antes de las franjas) mandaría celdas en el formato anterior y las revolvería.
  if (current && current.cellFormat === 2 && cellFormat !== 2) {
    return res.status(409).json({ error: 'Croni se actualizó. Recarga la página para seguir guardando.' });
  }
  await updateSchedule(key, prevRec => {
    const prev = prevRec || {};
    const weeks = { ...(prev.weeks || {}) };
    weeks[week] = { cell };
    return {
      ...prev, acts, link, categories, weeks,
      habits: habits || prev.habits || [], goals: goals || prev.goals || [],
      habitCategories: habitCategories || prev.habitCategories || [],
      habitsBestStreak: Number.isFinite(habitsBestStreak) ? habitsBestStreak : (prev.habitsBestStreak || 0),
      routines: (routines && typeof routines === 'object' && !Array.isArray(routines)) ? routines : (prev.routines || null),
      reminders: reminders || prev.reminders || [],
      // null = volver a las franjas por defecto; si no viene el campo (pestaña vieja), se conservan.
      slots: slots !== undefined ? slots : (prev.slots || null),
      cellFormat: 2
    };
  });
  res.json({ ok: true });
});

app.post('/api/onboarding-done', requireAuth, async (req, res) => {
  await updateSchedule(req.session.username, prev => ({ ...(prev || {}), onboarded: true }));
  res.json({ ok: true });
});

app.put('/api/profile', requireAuth, async (req, res) => {
  const { nombre } = req.body || {};
  const nombreLimpio = (typeof nombre === 'string' ? nombre.trim() : '').slice(0, 60);
  if (!nombreLimpio) return res.status(400).json({ error: 'El nombre no puede estar vacío.' });

  const saved = await updateUser(req.session.username, prev => prev ? { ...prev, nombre: nombreLimpio } : prev);
  if (!saved) return res.status(404).json({ error: 'No se encontró tu cuenta.' });
  req.session.displayName = nombreLimpio;
  res.json({ ok: true, username: nombreLimpio });
});

app.delete('/api/admin/users/:key', requireAuth, requireAdmin, async (req, res) => {
  const key = req.params.key;
  const users = await listUsers();
  if (!users[key]) return res.status(404).json({ error: 'Ese usuario no existe.' });
  if (key === req.session.username) return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta desde aquí.' });
  const admins = Object.keys(users).filter(k => users[k].isAdmin);
  if (users[key].isAdmin && admins.length <= 1) {
    return res.status(400).json({ error: 'No puedes eliminar al único administrador.' });
  }
  await updateUser(key, () => null);
  await updateSchedule(key, () => null);
  res.json({ ok: true });
});

app.post('/api/schedule/delete-activity', requireAuth, async (req, res) => {
  const { name, week } = req.body || {};
  if (typeof name !== 'string' || !name) return res.status(400).json({ error: 'Falta el nombre de la actividad.' });

  const key = req.session.username;
  const scrub = (cell) => {
    if (!cell) return;
    Object.keys(cell).forEach(k => {
      if (cell[k] && cell[k].act === name) {
        delete cell[k].act; delete cell[k].nombre; delete cell[k].nota;
        if (Object.keys(cell[k]).length === 0) delete cell[k];
      }
    });
  };
  const rec = await updateSchedule(key, prev => {
    const r = prev || { acts: {}, link: {}, categories: [], weeks: {} };
    delete r.acts?.[name];
    delete r.link?.[name];
    scrub(r.cell);
    Object.values(r.weeks || {}).forEach(w => scrub(w.cell));
    return r;
  });

  let weekId = WEEK_RE.test(week || '') ? week : isoWeekId(new Date());
  if (!weekWithinLimits(weekId)) weekId = isoWeekId(new Date());
  res.json({ ok: true, cell: cellForWeek(rec, weekId) });
});

/* ============ PLANEA TU DÍA ============ */
// "Reclama" el día: solo la primera vez que se pide en esa fecha responde show:true,
// así la ventana no vuelve a salir al recargar ni en otro dispositivo.
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
// kind: "plan" (Planea tu día) o "tasks" (Tareas de hoy); cada una lleva su propio registro.
const DAILY_KINDS = { plan: { last: 'last', flag: 'enabled' }, tasks: { last: 'lastTasks', flag: 'tasksEnabled' } };
app.post('/api/daily-plan/claim', requireAuth, async (req, res) => {
  const { date, kind = 'plan' } = req.body || {};
  const k = DAILY_KINDS[kind];
  if (!DATE_RE.test(date || '') || !k) return res.status(400).json({ error: 'Fecha inválida.' });
  let show = false;
  await updateSchedule(req.session.username, prev => {
    const r = prev || {};
    const dp = { ...(r.dailyPlanning || {}) };
    if (dp[k.flag] === false || dp[k.last] === date) return r;
    show = true;
    dp[k.last] = date;
    return { ...r, dailyPlanning: dp };
  });
  res.json({ show });
});
app.post('/api/daily-plan/pref', requireAuth, async (req, res) => {
  const { enabled, kind = 'plan' } = req.body || {};
  const k = DAILY_KINDS[kind];
  if (typeof enabled !== 'boolean' || !k) return res.status(400).json({ error: 'Valor inválido.' });
  await updateSchedule(req.session.username, prev => ({ ...(prev || {}), dailyPlanning: { ...((prev || {}).dailyPlanning || {}), [k.flag]: enabled } }));
  res.json({ ok: true, enabled });
});

/* ============ RESPALDO COMPLETO (todas las semanas, hábitos, rutinas...) ============ */
const BACKUP_FIELDS = ['acts', 'link', 'categories', 'cell', 'weeks', 'habits', 'goals', 'habitCategories',
  'habitsBestStreak', 'routines', 'reminders', 'slots', 'cellFormat'];
const isPlainObject = v => !!v && typeof v === 'object' && !Array.isArray(v);

app.get('/api/backup', requireAuth, async (req, res) => {
  const rec = (await ensureMigrated(req.session.username)) || {};
  const data = {};
  BACKUP_FIELDS.forEach(f => { if (rec[f] !== undefined) data[f] = rec[f]; });
  res.json({ format: 'croni-backup', version: 2, exportedAt: new Date().toISOString(), data });
});

app.post('/api/backup/restore', requireAuth, async (req, res) => {
  const body = req.body || {};
  const d = body.data;
  if (body.format !== 'croni-backup' || !isPlainObject(d)) return res.status(400).json({ error: 'Ese archivo no es un respaldo completo de Croni.' });
  const objFields = ['acts', 'link', 'cell', 'weeks'], arrFields = ['categories', 'habits', 'goals', 'habitCategories', 'reminders'];
  for (const f of objFields) if (d[f] !== undefined && !isPlainObject(d[f])) return res.status(400).json({ error: 'Respaldo dañado: "' + f + '" no es válido.' });
  for (const f of arrFields) if (d[f] !== undefined && !Array.isArray(d[f])) return res.status(400).json({ error: 'Respaldo dañado: "' + f + '" no es válido.' });
  if (d.routines !== undefined && d.routines !== null && !isPlainObject(d.routines)) return res.status(400).json({ error: 'Respaldo dañado: "routines" no es válido.' });
  if (d.slots !== undefined && d.slots !== null && !validSlots(d.slots)) return res.status(400).json({ error: 'Respaldo dañado: "slots" no es válido.' });
  for (const [wk, w] of Object.entries(d.weeks || {})) {
    if (!WEEK_RE.test(wk) || !isPlainObject(w) || (w.cell !== undefined && !isPlainObject(w.cell))) return res.status(400).json({ error: 'Respaldo dañado: la semana "' + wk + '" no es válida.' });
  }
  await updateSchedule(req.session.username, prev => {
    const next = { ...(prev || {}) };
    BACKUP_FIELDS.forEach(f => {
      if (f === 'slots' || f === 'cellFormat') { if (d[f] === undefined) delete next[f]; else next[f] = d[f]; return; }
      next[f] = d[f] !== undefined ? d[f] : (Array.isArray(next[f]) ? [] : (f === 'habitsBestStreak' ? 0 : (f === 'routines' ? null : {})));
    });
    // Un respaldo de antes de las franjas viene en formato 1: se convierte al momento.
    return migrateRec(next);
  });
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));

const PORT = process.env.PORT || 3000;
initStorage()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Horario · Enlaces corriendo en http://localhost:${PORT}`);
    });
  })
  .catch(err => {
    console.error('No se pudo conectar al almacenamiento:', err.message);
    process.exit(1);
  });
