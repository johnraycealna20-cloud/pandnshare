const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '5mb' }));
app.use(express.static('public'));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ── ADMIN CREDENTIALS (hardcoded — never stored in DB) ─────
const ADMIN_USERNAME = 'ecstar';
const ADMIN_PASSWORD = 'ecstar51566';
function isAdminCreds(u, p) {
  return u.toLowerCase() === ADMIN_USERNAME && p === ADMIN_PASSWORD;
}

// ── DB INIT ────────────────────────────────────────────────
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      display_name TEXT,
      avatar_url TEXT,
      avatar_cloudinary_id TEXT,
      status TEXT DEFAULT 'active',
      created_at BIGINT NOT NULL,
      last_seen BIGINT
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
    CREATE TABLE IF NOT EXISTS blogs (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_url TEXT,
      cloudinary_id TEXT,
      image_position TEXT DEFAULT 'left',
      is_public BOOLEAN DEFAULT false,
      owner TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS blog_comments (
      id TEXT PRIMARY KEY,
      blog_id TEXT NOT NULL REFERENCES blogs(id) ON DELETE CASCADE,
      author TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      to_user TEXT NOT NULL,
      content TEXT NOT NULL,
      read BOOLEAN DEFAULT false,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS admin_log (
      id SERIAL PRIMARY KEY,
      action TEXT NOT NULL,
      target TEXT,
      reason TEXT,
      created_at BIGINT NOT NULL
    );
  `);

  // Add new columns if upgrading from old DB (safe — IF NOT EXISTS)
  const cols = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_cloudinary_id TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen BIGINT`,
  ];
  for (const sql of cols) {
    await pool.query(sql).catch(() => {});
  }

  console.log('✅ Database tables ready');
}

initDb().then(() => {
  cleanSessions();
  setInterval(cleanSessions, 6 * 60 * 60 * 1000);
}).catch(err => console.error('DB init error:', err));

async function cleanSessions() {
  try {
    const cutoff = Date.now() - (30 * 24 * 60 * 60 * 1000);
    await pool.query('DELETE FROM sessions WHERE created_at < $1', [cutoff]);
  } catch (err) {}
}

// ── AUTH HELPERS ───────────────────────────────────────────
function hashPassword(p) {
  return crypto.createHash('sha256').update(p + 'automation_note_2024').digest('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    // Admin session check
    if (token.startsWith('admin_')) {
      req.username = ADMIN_USERNAME;
      req.isAdmin = true;
      return next();
    }
    const result = await pool.query('SELECT username FROM sessions WHERE token = $1', [token]);
    if (!result.rows.length) return res.status(401).json({ error: 'Session expired. Please log in again.' });
    const u = result.rows[0].username;
    // Check if banned
    const userRow = await pool.query('SELECT status FROM users WHERE username = $1', [u]);
    if (userRow.rows[0]?.status === 'banned') return res.status(403).json({ error: 'Your account has been banned.' });
    req.username = u;
    req.isAdmin = false;
    // Update last seen
    pool.query('UPDATE users SET last_seen = $1 WHERE username = $2', [Date.now(), u]).catch(() => {});
    next();
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
}

async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => {
    if (!req.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

async function optionalAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (token) {
    try {
      if (token.startsWith('admin_')) { req.username = ADMIN_USERNAME; req.isAdmin = true; return next(); }
      const result = await pool.query('SELECT username FROM sessions WHERE token = $1', [token]);
      if (result.rows.length) req.username = result.rows[0].username;
    } catch (err) {}
  }
  next();
}

// ── PING ───────────────────────────────────────────────────
app.get('/api/ping', (req, res) => res.json({ ok: true, t: Date.now() }));

// ── AUTH ───────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (username.toLowerCase() === ADMIN_USERNAME) return res.status(400).json({ error: 'Username not available' });
    if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });
    const existing = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (existing.rows.length) return res.status(409).json({ error: 'Username already taken' });
    await pool.query(
      'INSERT INTO users (username, password, display_name, status, created_at) VALUES ($1, $2, $3, $4, $5)',
      [username, hashPassword(password), username, 'active', Date.now()]
    );
    res.status(201).json({ message: 'Account created!' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Please fill in all fields' });

    // Admin login
    if (isAdminCreds(username, password)) {
      const token = 'admin_' + generateToken();
      return res.json({ token, username: ADMIN_USERNAME, isAdmin: true, display_name: 'Admin' });
    }

    const result = await pool.query(
      'SELECT username, status, display_name, avatar_url FROM users WHERE LOWER(username) = LOWER($1) AND password = $2',
      [username, hashPassword(password)]
    );
    if (!result.rows.length) return res.status(401).json({ error: 'Incorrect username or password' });
    const user = result.rows[0];
    if (user.status === 'banned') return res.status(403).json({ error: 'Your account has been banned. Contact admin.' });
    if (user.status === 'suspended') return res.status(403).json({ error: 'Your account is suspended. Contact admin.' });

    const token = generateToken();
    await pool.query('INSERT INTO sessions (token, username, created_at) VALUES ($1, $2, $3)', [token, user.username, Date.now()]);
    pool.query('UPDATE users SET last_seen = $1 WHERE username = $2', [Date.now(), user.username]).catch(() => {});
    res.json({ token, username: user.username, isAdmin: false, display_name: user.display_name || user.username, avatar_url: user.avatar_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  const token = req.headers['x-auth-token'];
  if (!token.startsWith('admin_')) {
    await pool.query('DELETE FROM sessions WHERE token = $1', [token]).catch(() => {});
  }
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, async (req, res) => {
  if (req.isAdmin) return res.json({ username: ADMIN_USERNAME, isAdmin: true, display_name: 'Admin', avatar_url: null });
  const r = await pool.query('SELECT username, display_name, avatar_url, status FROM users WHERE username = $1', [req.username]);
  const u = r.rows[0] || {};
  res.json({ username: req.username, isAdmin: false, display_name: u.display_name || req.username, avatar_url: u.avatar_url });
});

// ── PROFILE ────────────────────────────────────────────────
app.get('/api/profile/:username', optionalAuth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT username, display_name, avatar_url, created_at, last_seen FROM users WHERE username = $1 AND status != $2',
      [req.params.username, 'banned']
    );
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = r.rows[0];
    // Get public blogs
    const blogs = await pool.query(
      'SELECT id, title, content, image_url, image_position, created_at FROM blogs WHERE owner = $1 AND is_public = true ORDER BY created_at DESC',
      [req.params.username]
    );
    res.json({ ...u, blogs: blogs.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { display_name } = req.body;
    if (!display_name?.trim()) return res.status(400).json({ error: 'Display name required' });
    await pool.query('UPDATE users SET display_name = $1 WHERE username = $2', [display_name.trim(), req.username]);
    res.json({ display_name: display_name.trim() });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/profile/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image' });
    // Delete old avatar
    const old = await pool.query('SELECT avatar_cloudinary_id FROM users WHERE username = $1', [req.username]);
    if (old.rows[0]?.avatar_cloudinary_id) {
      await cloudinary.uploader.destroy(old.rows[0].avatar_cloudinary_id).catch(() => {});
    }
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream(
        { folder: 'automation-note-avatars', resource_type: 'image', transformation: [{ width: 200, height: 200, crop: 'fill' }] },
        (error, result) => error ? reject(error) : resolve(result)
      );
      stream.end(req.file.buffer);
    });
    await pool.query('UPDATE users SET avatar_url = $1, avatar_cloudinary_id = $2 WHERE username = $3', [result.secure_url, result.public_id, req.username]);
    res.json({ avatar_url: result.secure_url });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── PHOTOS ─────────────────────────────────────────────────
app.get('/api/photos', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM photos WHERE owner = $1 ORDER BY timestamp DESC', [req.username]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/upload', requireAuth, upload.array('photos', 20), async (req, res) => {
  try {
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
    const now = Date.now(); const uploaded = [];
    for (const file of req.files) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'automation-note', resource_type: 'image' }, (err, r) => err ? reject(err) : resolve(r));
        stream.end(file.buffer);
      });
      const id = crypto.randomBytes(8).toString('hex');
      await pool.query('INSERT INTO photos (id, cloudinary_id, src, original_name, timestamp, owner) VALUES ($1,$2,$3,$4,$5,$6)',
        [id, result.public_id, result.secure_url, file.originalname, now, req.username]);
      uploaded.push({ id, cloudinary_id: result.public_id, src: result.secure_url, original_name: file.originalname, timestamp: now, owner: req.username });
    }
    res.status(201).json({ uploaded: uploaded.length, photos: uploaded });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/photos/:id', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM photos WHERE id = $1 AND owner = $2', [req.params.id, req.username]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    await cloudinary.uploader.destroy(result.rows[0].cloudinary_id).catch(() => {});
    await pool.query('DELETE FROM photos WHERE id = $1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── NOTES ──────────────────────────────────────────────────
app.get('/api/notes', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM notes WHERE owner = $1 ORDER BY updated_at DESC', [req.username]);
    res.json(result.rows.map(n => ({ id: n.id, title: n.title, content: n.content, owner: n.owner, createdAt: n.created_at, updatedAt: n.updated_at })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/notes', requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });
    const id = crypto.randomBytes(8).toString('hex'); const now = Date.now();
    await pool.query('INSERT INTO notes (id, title, content, owner, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6)', [id, title || 'Untitled Note', content, req.username, now, now]);
    res.status(201).json({ id, title: title || 'Untitled Note', content, owner: req.username, createdAt: now, updatedAt: now });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    const { title, content } = req.body; const now = Date.now();
    const result = await pool.query('UPDATE notes SET title=$1, content=$2, updated_at=$3 WHERE id=$4 AND owner=$5 RETURNING *', [title, content, now, req.params.id, req.username]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    const n = result.rows[0];
    res.json({ id: n.id, title: n.title, content: n.content, owner: n.owner, createdAt: n.created_at, updatedAt: n.updated_at });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/notes/:id', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM notes WHERE id = $1 AND owner = $2', [req.params.id, req.username]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── BLOG ───────────────────────────────────────────────────
app.post('/api/blog-image', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image' });
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ folder: 'automation-note-blogs', resource_type: 'image' }, (err, r) => err ? reject(err) : resolve(r));
      stream.end(req.file.buffer);
    });
    res.json({ url: result.secure_url, cloudinary_id: result.public_id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/blogs/public', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.id, b.title, b.content, b.image_url, b.image_position, b.owner, b.created_at, b.updated_at,
       u.display_name, u.avatar_url
       FROM blogs b LEFT JOIN users u ON b.owner = u.username
       WHERE b.is_public = true ORDER BY b.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/blogs/mine', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM blogs WHERE owner = $1 ORDER BY created_at DESC', [req.username]);
    res.json(result.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/blogs/:id', optionalAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT b.*, u.display_name, u.avatar_url FROM blogs b LEFT JOIN users u ON b.owner = u.username WHERE b.id = $1`,
      [req.params.id]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Post not found' });
    const blog = result.rows[0];
    if (!blog.is_public && blog.owner !== req.username && !req.isAdmin) return res.status(403).json({ error: 'This post is private' });
    const comments = await pool.query(
      `SELECT c.*, u.display_name, u.avatar_url FROM blog_comments c LEFT JOIN users u ON c.author = u.username WHERE c.blog_id = $1 ORDER BY c.created_at ASC`,
      [req.params.id]
    );
    res.json({ ...blog, comments: comments.rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/blogs', requireAuth, async (req, res) => {
  try {
    const { title, content, image_url, cloudinary_id, image_position, is_public } = req.body;
    if (!title || !content) return res.status(400).json({ error: 'Title and content required' });
    const id = crypto.randomBytes(10).toString('hex'); const now = Date.now();
    await pool.query('INSERT INTO blogs (id, title, content, image_url, cloudinary_id, image_position, is_public, owner, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)',
      [id, title, content, image_url || null, cloudinary_id || null, image_position || 'left', is_public || false, req.username, now, now]);
    res.status(201).json({ id, title, content, image_url, image_position, is_public, owner: req.username, created_at: now });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/api/blogs/:id', requireAuth, async (req, res) => {
  try {
    const { title, content, image_url, cloudinary_id, image_position, is_public } = req.body; const now = Date.now();
    const result = await pool.query(
      'UPDATE blogs SET title=$1, content=$2, image_url=$3, cloudinary_id=$4, image_position=$5, is_public=$6, updated_at=$7 WHERE id=$8 AND owner=$9 RETURNING *',
      [title, content, image_url || null, cloudinary_id || null, image_position || 'left', is_public || false, now, req.params.id, req.username]
    );
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/blogs/:id', requireAuth, async (req, res) => {
  try {
    const clause = req.isAdmin ? 'WHERE id = $1' : 'WHERE id = $1 AND owner = $2';
    const params = req.isAdmin ? [req.params.id] : [req.params.id, req.username];
    const result = await pool.query(`SELECT * FROM blogs ${clause}`, params);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    if (result.rows[0].cloudinary_id) await cloudinary.uploader.destroy(result.rows[0].cloudinary_id).catch(() => {});
    await pool.query('DELETE FROM blogs WHERE id = $1', [req.params.id]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.patch('/api/blogs/:id/visibility', requireAuth, async (req, res) => {
  try {
    const { is_public } = req.body;
    const result = await pool.query('UPDATE blogs SET is_public=$1 WHERE id=$2 AND owner=$3 RETURNING id, is_public', [is_public, req.params.id, req.username]);
    if (!result.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(result.rows[0]);
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/blogs/:id/comments', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });
    const blog = await pool.query('SELECT * FROM blogs WHERE id = $1', [req.params.id]);
    if (!blog.rows.length) return res.status(404).json({ error: 'Post not found' });
    if (!blog.rows[0].is_public && blog.rows[0].owner !== req.username && !req.isAdmin) return res.status(403).json({ error: 'Cannot comment on private post' });
    const id = crypto.randomBytes(8).toString('hex'); const now = Date.now();
    await pool.query('INSERT INTO blog_comments (id, blog_id, author, content, created_at) VALUES ($1,$2,$3,$4,$5)', [id, req.params.id, req.username, content.trim(), now]);
    const uRow = await pool.query('SELECT display_name, avatar_url FROM users WHERE username = $1', [req.username]);
    const u = uRow.rows[0] || {};
    res.status(201).json({ id, blog_id: req.params.id, author: req.username, display_name: u.display_name || req.username, avatar_url: u.avatar_url, content: content.trim(), created_at: now });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/blogs/:blogId/comments/:commentId', requireAuth, async (req, res) => {
  try {
    const comment = await pool.query('SELECT * FROM blog_comments WHERE id = $1 AND blog_id = $2', [req.params.commentId, req.params.blogId]);
    if (!comment.rows.length) return res.status(404).json({ error: 'Not found' });
    const blog = await pool.query('SELECT owner FROM blogs WHERE id = $1', [req.params.blogId]);
    if (comment.rows[0].author !== req.username && blog.rows[0]?.owner !== req.username && !req.isAdmin) return res.status(403).json({ error: 'Not allowed' });
    await pool.query('DELETE FROM blog_comments WHERE id = $1', [req.params.commentId]);
    res.json({ message: 'Deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── MESSAGES (DMs) ─────────────────────────────────────────
app.get('/api/messages/conversations', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT DISTINCT ON (other_user)
        CASE WHEN from_user = $1 THEN to_user ELSE from_user END as other_user,
        content, created_at, read,
        CASE WHEN from_user = $1 THEN false ELSE NOT read END as has_unread
      FROM messages
      WHERE from_user = $1 OR to_user = $1
      ORDER BY other_user, created_at DESC
    `, [req.username]);
    // Get display names
    const users = [...new Set(r.rows.map(x => x.other_user))];
    let profileMap = {};
    if (users.length) {
      const profiles = await pool.query('SELECT username, display_name, avatar_url FROM users WHERE username = ANY($1)', [users]);
      profiles.rows.forEach(u => profileMap[u.username] = u);
    }
    res.json(r.rows.map(x => ({ ...x, display_name: profileMap[x.other_user]?.display_name || x.other_user, avatar_url: profileMap[x.other_user]?.avatar_url })));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/messages/:otherUser', requireAuth, async (req, res) => {
  try {
    const { otherUser } = req.params;
    const r = await pool.query(
      `SELECT * FROM messages WHERE (from_user=$1 AND to_user=$2) OR (from_user=$2 AND to_user=$1) ORDER BY created_at ASC`,
      [req.username, otherUser]
    );
    // Mark as read
    await pool.query('UPDATE messages SET read=true WHERE to_user=$1 AND from_user=$2', [req.username, otherUser]);
    res.json(r.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/messages/:toUser', requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Message cannot be empty' });
    const { toUser } = req.params;
    if (toUser === req.username) return res.status(400).json({ error: 'Cannot message yourself' });
    // Check user exists
    const exists = await pool.query('SELECT username FROM users WHERE username = $1', [toUser]);
    if (!exists.rows.length) return res.status(404).json({ error: 'User not found' });
    const id = crypto.randomBytes(8).toString('hex'); const now = Date.now();
    await pool.query('INSERT INTO messages (id, from_user, to_user, content, read, created_at) VALUES ($1,$2,$3,$4,$5,$6)', [id, req.username, toUser, content.trim(), false, now]);
    res.status(201).json({ id, from_user: req.username, to_user: toUser, content: content.trim(), read: false, created_at: now });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/messages/unread/count', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT COUNT(*) FROM messages WHERE to_user=$1 AND read=false', [req.username]);
    res.json({ count: parseInt(r.rows[0].count) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── ADMIN ROUTES ───────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT id, username, display_name, avatar_url, status, created_at, last_seen FROM users ORDER BY created_at DESC');
    // Add session/online info
    const now = Date.now();
    const users = r.rows.map(u => ({
      ...u,
      is_online: u.last_seen && (now - u.last_seen) < 5 * 60 * 1000 // online if seen in last 5 min
    }));
    res.json(users);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const [users, blogs, photos, messages] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM blogs'),
      pool.query('SELECT COUNT(*) FROM photos'),
      pool.query('SELECT COUNT(*) FROM messages'),
    ]);
    const now = Date.now();
    const online = await pool.query('SELECT COUNT(*) FROM users WHERE last_seen > $1', [now - 5 * 60 * 1000]);
    res.json({
      total_users: parseInt(users.rows[0].count),
      total_blogs: parseInt(blogs.rows[0].count),
      total_photos: parseInt(photos.rows[0].count),
      total_messages: parseInt(messages.rows[0].count),
      online_users: parseInt(online.rows[0].count),
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/admin/users/:username/status', requireAdmin, async (req, res) => {
  try {
    const { status, reason } = req.body;
    if (!['active', 'suspended', 'banned'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    if (req.params.username.toLowerCase() === ADMIN_USERNAME) return res.status(400).json({ error: 'Cannot modify admin' });
    await pool.query('UPDATE users SET status = $1 WHERE username = $2', [status, req.params.username]);
    // Kill sessions if banned/suspended
    if (status !== 'active') await pool.query('DELETE FROM sessions WHERE username = $1', [req.params.username]);
    await pool.query('INSERT INTO admin_log (action, target, reason, created_at) VALUES ($1,$2,$3,$4)', [status, req.params.username, reason || null, Date.now()]);
    res.json({ message: `User ${req.params.username} is now ${status}` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/admin/users/:username', requireAdmin, async (req, res) => {
  try {
    if (req.params.username.toLowerCase() === ADMIN_USERNAME) return res.status(400).json({ error: 'Cannot delete admin' });
    await pool.query('DELETE FROM sessions WHERE username = $1', [req.params.username]);
    await pool.query('DELETE FROM messages WHERE from_user=$1 OR to_user=$1', [req.params.username]);
    await pool.query('DELETE FROM notes WHERE owner=$1', [req.params.username]);
    await pool.query('DELETE FROM photos WHERE owner=$1', [req.params.username]);
    await pool.query('DELETE FROM blogs WHERE owner=$1', [req.params.username]);
    await pool.query('DELETE FROM users WHERE username=$1', [req.params.username]);
    await pool.query('INSERT INTO admin_log (action, target, reason, created_at) VALUES ($1,$2,$3,$4)', ['deleted', req.params.username, 'Admin deleted account', Date.now()]);
    res.json({ message: 'User deleted' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/log', requireAdmin, async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 100');
    res.json(r.rows);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── FALLBACK ───────────────────────────────────────────────
app.get('/blog/:id', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.get('/user/:username', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.get('*', (req, res) => res.sendFile(__dirname + '/public/index.html'));
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Max 10MB per file' });
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => console.log(`✅ Automation Note v5 running on http://localhost:${PORT}`));
