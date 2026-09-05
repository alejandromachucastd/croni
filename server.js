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
function writeJSON(file, obj) {
  fs.writeFileSync(file, JSON.stringify(obj, null, 2), 'utf8');
}

async function collectionToObject(col) {
  const docs = await col.find().toArray();
  const obj = {};
  docs.forEach(d => { const { _id, ...rest } = d; obj[_id] = rest; });
  return obj;
}
async function syncObjectToCollection(col, obj) {
  const existingIds = (await col.find({}, { projection: { _id: 1 } }).toArray()).map(d => d._id);
  const keys = Object.keys(obj);
  const ops = keys.map(key => ({
    replaceOne: { filter: { _id: key }, replacement: { _id: key, ...obj[key] }, upsert: true }
  }));
  if (ops.length) await col.bulkWrite(ops);
  const toDelete = existingIds.filter(id => !keys.includes(id));
  if (toDelete.length) await col.deleteMany({ _id: { $in: toDelete } });
}

async function getUsers() { return usersCol ? collectionToObject(usersCol) : readJSON(USERS_FILE, {}); }
async function saveUsers(u) { return usersCol ? syncObjectToCollection(usersCol, u) : writeJSON(USERS_FILE, u); }
async function getSchedules() { return schedulesCol ? collectionToObject(schedulesCol) : readJSON(SCHEDULES_FILE, {}); }
async function saveSchedules(s) { return schedulesCol ? syncObjectToCollection(schedulesCol, s) : writeJSON(SCHEDULES_FILE, s); }

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
  const users = await getUsers();
  const user = users[req.session.username];
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

      const users = await getUsers();
      if (!users[key]) {
        users[key] = {
          username: displayName, nombre: displayName, provider: 'google', email,
          isAdmin: Object.keys(users).length === 0,
          createdAt: new Date().toISOString()
        };
        await saveUsers(users);
        const schedules = await getSchedules();
        schedules[key] = { acts: {}, link: {}, categories: [], weeks: {} };
        await saveSchedules(schedules);
      }

      req.session.username = key;
      req.session.displayName = users[key].username;
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
  const users = await getUsers();
  const user = users[req.session.username];
  res.json({
    loggedIn: true, username: req.session.displayName, isAdmin: !!(user && user.isAdmin),
    provider: user ? user.provider : 'local', email: user ? (user.email || '') : '',
    createdAt: user ? user.createdAt : null
  });
});

app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const users = await getUsers();
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
  const schedules = await getSchedules();
  const rec = schedules[key] || { acts: {}, link: {}, categories: [] };
  const visits = rec.visits || [];
  const today = new Date().toISOString().slice(0, 10);
  if (!visits.includes(today)) {
    visits.push(today);
    if (visits.length > 400) visits.splice(0, visits.length - 400);
    schedules[key] = { ...rec, visits };
    await saveSchedules(schedules);
  }
  res.json({
    acts: rec.acts || {}, link: rec.link || {}, categories: rec.categories || [],
    habits: rec.habits || [], goals: rec.goals || [], habitCategories: rec.habitCategories || [],
    habitsBestStreak: rec.habitsBestStreak || 0, onboarded: !!rec.onboarded,
    cell: cellForWeek(rec, weekId), weekId, streak: streakFromVisits(visits),
    minWeek: MIN_WEEK, maxWeek: MAX_WEEK
  });
});

app.put('/api/schedule', requireAuth, async (req, res) => {
  const { week, acts, link, categories, cell, habits, goals, habitCategories, habitsBestStreak } = req.body || {};
  if (typeof acts !== 'object' || typeof link !== 'object' || typeof cell !== 'object' || !Array.isArray(categories)
    || !Array.isArray(habits || []) || !Array.isArray(goals || []) || !Array.isArray(habitCategories || [])) {
    return res.status(400).json({ error: 'Formato de horario inválido.' });
  }
  if (!WEEK_RE.test(week || '')) return res.status(400).json({ error: 'Semana inválida.' });
  if (!weekWithinLimits(week)) {
    return res.status(400).json({ error: 'Esa semana está fuera del rango permitido (hasta 1 año atrás o 2 años adelante).' });
  }
  const key = req.session.username;
  const schedules = await getSchedules();
  const prev = schedules[key] || {};
  const weeks = { ...(prev.weeks || {}) };
  weeks[week] = { cell };
  schedules[key] = {
    ...prev, acts, link, categories, weeks,
    habits: habits || prev.habits || [], goals: goals || prev.goals || [],
    habitCategories: habitCategories || prev.habitCategories || [],
    habitsBestStreak: Number.isFinite(habitsBestStreak) ? habitsBestStreak : (prev.habitsBestStreak || 0)
  };
  await saveSchedules(schedules);
  res.json({ ok: true });
});

app.post('/api/onboarding-done', requireAuth, async (req, res) => {
  const key = req.session.username;
  const schedules = await getSchedules();
  schedules[key] = { ...(schedules[key] || {}), onboarded: true };
  await saveSchedules(schedules);
  res.json({ ok: true });
});

app.put('/api/profile', requireAuth, async (req, res) => {
  const { nombre } = req.body || {};
  const nombreLimpio = (typeof nombre === 'string' ? nombre.trim() : '').slice(0, 60);
  if (!nombreLimpio) return res.status(400).json({ error: 'El nombre no puede estar vacío.' });

  const users = await getUsers();
  const user = users[req.session.username];
  user.nombre = nombreLimpio;
  await saveUsers(users);
  req.session.displayName = nombreLimpio;
  res.json({ ok: true, username: nombreLimpio });
});

app.delete('/api/admin/users/:key', requireAuth, requireAdmin, async (req, res) => {
  const key = req.params.key;
  const users = await getUsers();
  if (!users[key]) return res.status(404).json({ error: 'Ese usuario no existe.' });
  if (key === req.session.username) return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta desde aquí.' });
  const admins = Object.keys(users).filter(k => users[k].isAdmin);
  if (users[key].isAdmin && admins.length <= 1) {
    return res.status(400).json({ error: 'No puedes eliminar al único administrador.' });
  }
  delete users[key];
  await saveUsers(users);
  const schedules = await getSchedules();
  delete schedules[key];
  await saveSchedules(schedules);
  res.json({ ok: true });
});

app.post('/api/schedule/delete-activity', requireAuth, async (req, res) => {
  const { name, week } = req.body || {};
  if (typeof name !== 'string' || !name) return res.status(400).json({ error: 'Falta el nombre de la actividad.' });

  const key = req.session.username;
  const schedules = await getSchedules();
  const rec = schedules[key] || { acts: {}, link: {}, categories: [], weeks: {} };

  delete rec.acts?.[name];
  delete rec.link?.[name];

  const scrub = (cell) => {
    if (!cell) return;
    Object.keys(cell).forEach(k => {
      if (cell[k] && cell[k].act === name) {
        delete cell[k].act; delete cell[k].nombre; delete cell[k].nota;
        if (Object.keys(cell[k]).length === 0) delete cell[k];
      }
    });
  };
  scrub(rec.cell);
  Object.values(rec.weeks || {}).forEach(w => scrub(w.cell));

  schedules[key] = rec;
  await saveSchedules(schedules);

  let weekId = WEEK_RE.test(week || '') ? week : isoWeekId(new Date());
  if (!weekWithinLimits(weekId)) weekId = isoWeekId(new Date());
  res.json({ ok: true, cell: cellForWeek(rec, weekId) });
});

app.use(express.static(path.join(__dirname, 'public')));

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
