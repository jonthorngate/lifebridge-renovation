const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pgSession = require('connect-pg-simple')(session);
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query('CREATE TABLE IF NOT EXISTS tracker_data (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMPTZ DEFAULT NOW())');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR NOT NULL COLLATE "default",
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL,
      CONSTRAINT session_pkey PRIMARY KEY (sid)
    )
  `).catch(() => {});
  console.log('DB ready');
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.redirect('/login');
}

function requireAuthAPI(req, res, next) {
  if (req.session && req.session.authenticated) return next();
  res.status(401).json({ ok: false, error: 'Unauthorized' });
}

const DEFPASS = 'lifebridge';

async function checkPassword(input) {
  try {
    const r = await pool.query("SELECT value FROM tracker_data WHERE key='lb_admin_password'");
    if (r.rows.length > 0) {
      const stored = JSON.parse(r.rows[0].value);
      if (stored.startsWith('$2')) return bcrypt.compare(input, stored);
      return input === stored;
    }
  } catch(e) {}
  const s = process.env.APP_PASSWORD || DEFPASS;
  if (s.startsWith('$2')) return bcrypt.compare(input, s);
  return input === s;
}

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
  store: new pgSession({ pool, tableName: 'session', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'lifebridge-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, secure: false, sameSite: 'lax' }
}));

// ── Public routes ──────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session.authenticated) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/login', async (req, res) => {
  const { password } = req.body;
  const ok = await checkPassword(password);
  if (ok) {
    req.session.authenticated = true;
    req.session.save((err) => {
      if (err) console.error('Session save error:', err);
      res.redirect('/');
    });
  } else {
    res.redirect('/login?error=1');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Public view — serves index.html without requiring auth
app.get('/public', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Public data endpoint — returns all tracker data for public view
app.get('/api/public-data', async (req, res) => {
  try {
    const r = await pool.query('SELECT key,value FROM tracker_data');
    const d = {};
    r.rows.forEach(row => {
      try { d[row.key] = JSON.parse(row.value); } catch(e) { d[row.key] = row.value; }
    });
    res.json({ ok: true, data: d });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// ── Admin-only routes ──────────────────────────────────────
app.get('/', (req, res, next) => {
  // If accessing from a custom domain (not railway.app), redirect to /public
  const host = req.hostname || '';
  const isRailwayUrl = host.includes('railway.app');
  if (!isRailwayUrl) {
    return res.redirect('/public');
  }
  requireAuth(req, res, next);
}, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api/data', requireAuthAPI, async (req, res) => {
  try {
    const r = await pool.query('SELECT key,value FROM tracker_data');
    const d = {};
    r.rows.forEach(row => {
      try { d[row.key] = JSON.parse(row.value); } catch(e) { d[row.key] = row.value; }
    });
    res.json({ ok: true, data: d });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.post('/api/data/bulk', requireAuthAPI, async (req, res) => {
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ ok: false });
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const [key, value] of Object.entries(data)) {
        const val = typeof value === 'string' ? value : JSON.stringify(value);
        await client.query(
          'INSERT INTO tracker_data (key,value,updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (key) DO UPDATE SET value=$2,updated_at=NOW()',
          [key, val]
        );
      }
      await client.query('COMMIT');
    } catch(e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/api/settings', requireAuthAPI, async (req, res) => {
  try {
    const r = await pool.query("SELECT value FROM tracker_data WHERE key='lb_webhook_url'");
    const webhookUrl = r.rows.length > 0 ? JSON.parse(r.rows[0].value) : '';
    res.json({ ok: true, webhookUrl });
  } catch(e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.use(express.static(path.join(__dirname, 'public')));

initDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`LifeBridge Tracker running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
