const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// ─── Cloudinary config (from environment variables) ────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// ─── PostgreSQL config (from environment variable) ─────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ─── Multer (memory storage — send directly to Cloudinary) ─
const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ─── Create tables on startup ──────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS photos (
      id TEXT PRIMARY KEY,
      cloudinary_id TEXT NOT NULL,
      src TEXT NOT NULL,
      original_name TEXT NOT NULL,
      timestamp BIGINT NOT NULL,
      owner TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY,
      title TEXT,
      content TEXT NOT NULL,
      owner TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
  `);
  console.log('✅ Database tables ready');
}
initDb().catch(err => console.error('DB init error:', err));

// ─── Clean expired sessions (30 days) ─────────────────────
async function cleanSessions() {
  const cutoff = Date.now() - (30 * 24 * 60 * 60 * 1000);
  await pool.query('DELETE FROM sessions WHERE created_at < $1', [cutoff]);
}
cleanSessions();
setInterval(cleanSessions, 6 * 60 * 60 * 1000);

// ─── Auth helpers ──────────────────────────────────────────
function hashPassword(p) {
  return crypto.createHash('sha256').update(p + 'automation_note_2024').digest('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}
async function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const result = await pool.query('SELECT username FROM sessions WHERE token = $1', [token]);
  if (!result.rows.length) return res.status(401).json({ error: 'Session expired. Please log in again.' });
  req.username = result.rows[0].username;
  next();
}

// ─── Keep-alive ping ───────────────────────────────────────
app.get('/api/ping', (req, res) => res.json({ ok: true, t: Date.now() }));

// ─── AUTH ROUTES ───────────────────────────────────────────

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });

    const existing = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (existing.rows.length) return res.status(409).json({ error: 'Username already taken' });

    await pool.query(
      'INSERT INTO users (username, password, created_at) VALUES ($1, $2, $3)',
      [username, hashPassword(password), Date.now()]
    );
    res.status(201).json({ message: 'Account created!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Please fill in all fields' });

    const result = await pool.query(
      'SELECT username FROM users WHERE LOWER(username) = LOWER($1) AND password = $2',
      [username, hashPassword(password)]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Incorrect username or password' });

    const token = generateToken();
    const user = result.rows[0];
    await pool.query(
      'INSERT INTO sessions (token, username, created_at) VALUES ($1, $2, $3)',
      [token, user.username, Date.now()]
    );
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM sessions WHERE token = $1', [req.headers['x-auth-token']]);
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.username }));

// ─── PHOTO ROUTES ──────────────────────────────────────────

app.get('/api/photos', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM photos WHERE owner = $1 ORDER BY timestamp DESC',
      [req.username]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/upload', requireAuth, upload.array('photos', 20), async (req, res) => {
  try {
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });

    const now = Date.now();
    const uploaded = [];

    for (const file of req.files) {
      // Upload buffer to Cloudinary
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'automation-note', resource_type: 'image' },
          (error, result) => error ? reject(error) : resolve(result)
        );
        stream.end(file.buffer);
      });

      const id = crypto.randomBytes(8).toString('hex');
      await pool.query(
        'INSERT INTO photos (id, cloudinary_id, src, original_name, timestamp, owner) VALUES ($1,$2,$3,$4,$5,$6)',
        [id, result.public_id, result.secure_url, file.originalname, now, req.username]
      );
      uploaded.push({
        id, cloudinary_id: result.public_id, src: result.secure_url,
        original_name: file.originalname, timestamp: now, owner: req.username
      });
    }

    res.status(201).json({ uploaded: uploaded.length, photos: uploaded });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/photos/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM photos WHERE id = $1 AND owner = $2',
      [req.params.id, req.username]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });

    // Delete from Cloudinary
    await cloudinary.uploader.destroy(result.rows[0].cloudinary_id);
    // Delete from database
    await pool.query('DELETE FROM photos WHERE id = $1', [req.params.id]);

    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── NOTES ROUTES ──────────────────────────────────────────

app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notes WHERE owner = $1 ORDER BY updated_at DESC',
      [req.username]
    );
    // Map snake_case to camelCase for frontend
    res.json(result.rows.map(n => ({
      id: n.id, title: n.title, content: n.content, owner: n.owner,
      createdAt: n.created_at, updatedAt: n.updated_at
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });
    const id = crypto.randomBytes(8).toString('hex');
    const now = Date.now();
    await pool.query(
      'INSERT INTO notes (id, title, content, owner, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, title || 'Untitled Note', content, req.username, now, now]
    );
    res.status(201).json({ id, title: title || 'Untitled Note', content, owner: req.username, createdAt: now, updatedAt: now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    const now = Date.now();
    const result = await pool.query(
      'UPDATE notes SET title=$1, content=$2, updated_at=$3 WHERE id=$4 AND owner=$5 RETURNING *',
      [title, content, now, req.params.id, req.username]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const n = result.rows[0];
    res.json({ id: n.id, title: n.title, content: n.content, owner: n.owner, createdAt: n.created_at, updatedAt: n.updated_at });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM notes WHERE id = $1 AND owner = $2', [req.params.id, req.username]);
    res.json({ message: 'Deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Fallback ──────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Max 10MB per file' });
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => console.log(`✅ Automation Note running on http://localhost:${PORT}`));
