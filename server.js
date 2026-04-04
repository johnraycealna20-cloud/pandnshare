const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Uploads dir ───────────────────────────────────────────
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ─── Multer ────────────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1e9) + ext);
  }
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Images only'));
  },
  limits: { fileSize: 10 * 1024 * 1024 }
});

// ─── DB helpers ────────────────────────────────────────────
const dbPath = path.join(__dirname, 'db.json');
const sessionsPath = path.join(__dirname, 'sessions.json');

function readDb() {
  if (!fs.existsSync(dbPath)) {
    fs.writeFileSync(dbPath, JSON.stringify({ users: [], photos: [], notes: [] }));
  }
  const db = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
  if (!db.notes) db.notes = [];
  return db;
}
function writeDb(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

// Sessions in separate file — survive server restarts, 30-day expiry
function readSessions() {
  if (!fs.existsSync(sessionsPath)) {
    fs.writeFileSync(sessionsPath, JSON.stringify({}));
  }
  return JSON.parse(fs.readFileSync(sessionsPath, 'utf-8'));
}
function writeSessions(s) {
  fs.writeFileSync(sessionsPath, JSON.stringify(s, null, 2));
}
function cleanExpiredSessions() {
  const sessions = readSessions();
  const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
  const now = Date.now();
  let changed = false;
  for (const t in sessions) {
    if (now - sessions[t].createdAt > THIRTY_DAYS) { delete sessions[t]; changed = true; }
  }
  if (changed) writeSessions(sessions);
}
cleanExpiredSessions();
setInterval(cleanExpiredSessions, 6 * 60 * 60 * 1000);

// ─── Auth helpers ──────────────────────────────────────────
function hashPassword(p) {
  return crypto.createHash('sha256').update(p + 'automation_note_2024').digest('hex');
}
function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}
function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  const sessions = readSessions();
  const session = sessions[token];
  if (!session) return res.status(401).json({ error: 'Session expired. Please log in again.' });
  req.username = session.username;
  next();
}

// ─── Keep-alive (prevents Render from sleeping) ────────────
app.get('/api/ping', (req, res) => res.json({ ok: true, t: Date.now() }));

// ─── AUTH ──────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
  if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });
  const db = readDb();
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'Username already taken' });
  }
  db.users.push({ username, password: hashPassword(password), createdAt: Date.now() });
  writeDb(db);
  res.status(201).json({ message: 'Account created!' });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Please fill in all fields' });
  const db = readDb();
  const user = db.users.find(u =>
    u.username.toLowerCase() === username.toLowerCase() && u.password === hashPassword(password)
  );
  if (!user) return res.status(401).json({ error: 'Incorrect username or password' });
  const token = generateToken();
  const sessions = readSessions();
  sessions[token] = { username: user.username, createdAt: Date.now() };
  writeSessions(sessions);
  res.json({ token, username: user.username });
});

app.post('/api/logout', requireAuth, (req, res) => {
  const token = req.headers['x-auth-token'];
  const sessions = readSessions();
  delete sessions[token];
  writeSessions(sessions);
  res.json({ message: 'Logged out' });
});

app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.username }));

// ─── PHOTOS ────────────────────────────────────────────────
app.get('/api/photos', requireAuth, (req, res) => {
  const db = readDb();
  res.json(db.photos.filter(p => p.owner === req.username).sort((a, b) => b.timestamp - a.timestamp));
});

app.post('/api/upload', requireAuth, upload.array('photos', 20), (req, res) => {
  if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
  const db = readDb();
  const now = Date.now();
  const newPhotos = req.files.map(f => ({
    id: f.filename, src: `/uploads/${f.filename}`,
    originalName: f.originalname, timestamp: now, size: f.size, owner: req.username
  }));
  db.photos.push(...newPhotos);
  writeDb(db);
  res.status(201).json({ uploaded: newPhotos.length, photos: newPhotos });
});

app.delete('/api/photos/:id', requireAuth, (req, res) => {
  const db = readDb();
  const idx = db.photos.findIndex(p => p.id === req.params.id && p.owner === req.username);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  const fp = path.join(uploadsDir, req.params.id);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  db.photos.splice(idx, 1);
  writeDb(db);
  res.json({ message: 'Deleted' });
});

app.use('/uploads', express.static(uploadsDir));

// ─── NOTES ─────────────────────────────────────────────────
app.get('/api/notes', requireAuth, (req, res) => {
  const db = readDb();
  res.json(db.notes.filter(n => n.owner === req.username).sort((a, b) => b.updatedAt - a.updatedAt));
});

app.post('/api/notes', requireAuth, (req, res) => {
  const { title, content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content required' });
  const db = readDb();
  const note = {
    id: crypto.randomBytes(8).toString('hex'), title: title || 'Untitled Note',
    content, owner: req.username, createdAt: Date.now(), updatedAt: Date.now()
  };
  db.notes.push(note);
  writeDb(db);
  res.status(201).json(note);
});

app.put('/api/notes/:id', requireAuth, (req, res) => {
  const db = readDb();
  const note = db.notes.find(n => n.id === req.params.id && n.owner === req.username);
  if (!note) return res.status(404).json({ error: 'Not found' });
  const { title, content } = req.body;
  if (title !== undefined) note.title = title;
  if (content !== undefined) note.content = content;
  note.updatedAt = Date.now();
  writeDb(db);
  res.json(note);
});

app.delete('/api/notes/:id', requireAuth, (req, res) => {
  const db = readDb();
  const idx = db.notes.findIndex(n => n.id === req.params.id && n.owner === req.username);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });
  db.notes.splice(idx, 1);
  writeDb(db);
  res.json({ message: 'Deleted' });
});

// ─── Fallback ──────────────────────────────────────────────
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Max 10MB per file' });
  res.status(500).json({ error: err.message });
});

app.listen(PORT, () => console.log(`✅ Automation Note running on http://localhost:${PORT}`));
