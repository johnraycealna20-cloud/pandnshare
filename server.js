const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const cloudinary = require('cloudinary').v2;
const cors = require('cors');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB for video
});

const ADMIN_USERNAME = 'ecstar';
const ADMIN_PASSWORD = 'ecstar51566';
function isAdminCreds(u, p) { return u.toLowerCase() === ADMIN_USERNAME && p === ADMIN_PASSWORD; }

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
      user_tag TEXT,
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
    CREATE TABLE IF NOT EXISTS collections (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      cover_photo_id TEXT,
      cover_url TEXT,
      cover_cloudinary_id TEXT,
      type TEXT DEFAULT 'mixed',
      is_public BOOLEAN DEFAULT false,
      owner TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      updated_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS collection_photos (
      id TEXT PRIMARY KEY,
      collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
      photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
      added_at BIGINT NOT NULL,
      UNIQUE(collection_id, photo_id)
    );
    CREATE TABLE IF NOT EXISTS collection_notes (
      id TEXT PRIMARY KEY,
      collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
      note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
      added_at BIGINT NOT NULL,
      UNIQUE(collection_id, note_id)
    );
    CREATE TABLE IF NOT EXISTS blogs (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      content TEXT NOT NULL,
      image_url TEXT,
      cloudinary_id TEXT,
      video_url TEXT,
      video_cloudinary_id TEXT,
      image_position TEXT DEFAULT 'left',
      is_public BOOLEAN DEFAULT false,
      ai_tools TEXT[],
      generation_type TEXT,
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
    CREATE TABLE IF NOT EXISTS blog_ratings (
      id TEXT PRIMARY KEY,
      blog_id TEXT NOT NULL REFERENCES blogs(id) ON DELETE CASCADE,
      rater TEXT NOT NULL,
      rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 10),
      created_at BIGINT NOT NULL,
      UNIQUE(blog_id, rater)
    );
    CREATE TABLE IF NOT EXISTS friendships (
      id TEXT PRIMARY KEY,
      requester TEXT NOT NULL,
      recipient TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at BIGINT NOT NULL,
      UNIQUE(requester, recipient)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      to_user TEXT NOT NULL,
      content TEXT NOT NULL,
      read BOOLEAN DEFAULT false,
      created_at BIGINT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      from_user TEXT NOT NULL,
      type TEXT NOT NULL,
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

  // Safe column additions for existing DBs
  const migrations = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_cloudinary_id TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS user_tag TEXT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen BIGINT`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS top_contributor BOOLEAN DEFAULT false`,
    `ALTER TABLE blogs ADD COLUMN IF NOT EXISTS video_url TEXT`,
    `ALTER TABLE blogs ADD COLUMN IF NOT EXISTS video_cloudinary_id TEXT`,
    `ALTER TABLE blogs ADD COLUMN IF NOT EXISTS ai_tools TEXT[]`,
    `ALTER TABLE blogs ADD COLUMN IF NOT EXISTS generation_type TEXT`,
  ];
  for (const sql of migrations) await pool.query(sql).catch(() => {});
  // Ensure admin has admin tag on every startup
  await pool.query("UPDATE users SET user_tag='Admin' WHERE username='ecstar'").catch(()=>{});
  console.log('✅ Database ready');
}

initDb().then(() => { cleanSessions(); setInterval(cleanSessions, 6*60*60*1000); }).catch(err => console.error(err));

async function cleanSessions() {
  try { await pool.query('DELETE FROM sessions WHERE created_at < $1', [Date.now() - 30*24*60*60*1000]); } catch(e) {}
}

// ── AUTH HELPERS ───────────────────────────────────────────
function hash(p) { return crypto.createHash('sha256').update(p+'automation_note_2024').digest('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }

async function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    if (token.startsWith('admin_')) { req.username = ADMIN_USERNAME; req.isAdmin = true; return next(); }
    const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [token]);
    if (!r.rows.length) return res.status(401).json({ error: 'Session expired' });
    const u = r.rows[0].username;
    const ur = await pool.query('SELECT status FROM users WHERE username=$1', [u]);
    if (ur.rows[0]?.status === 'banned') return res.status(403).json({ error: 'Account banned' });
    if (ur.rows[0]?.status === 'suspended') return res.status(403).json({ error: 'Account suspended' });
    req.username = u; req.isAdmin = false;
    pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [Date.now(), u]).catch(()=>{});
    next();
  } catch(err) { res.status(500).json({ error: err.message }); }
}
async function requireAdmin(req, res, next) {
  await requireAuth(req, res, () => { if (!req.isAdmin) return res.status(403).json({ error: 'Admin only' }); next(); });
}
async function optionalAuth(req, res, next) {
  const token = req.headers['x-auth-token'];
  if (token) {
    try {
      if (token.startsWith('admin_')) { req.username = ADMIN_USERNAME; req.isAdmin = true; return next(); }
      const r = await pool.query('SELECT username FROM sessions WHERE token=$1', [token]);
      if (r.rows.length) req.username = r.rows[0].username;
    } catch(e) {}
  }
  next();
}

// ── PING ───────────────────────────────────────────────────
app.get('/api/ping', (req, res) => res.json({ ok: true }));

// ── AUTH ───────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username||!password) return res.status(400).json({ error: 'Required' });
    if (username.toLowerCase()===ADMIN_USERNAME) return res.status(400).json({ error: 'Username not available' });
    if (username.length<3) return res.status(400).json({ error: 'Username min 3 chars' });
    if (password.length<4) return res.status(400).json({ error: 'Password min 4 chars' });
    if (!/^[a-zA-Z0-9_]+$/.test(username)) return res.status(400).json({ error: 'Letters, numbers, underscores only' });
    const ex = await pool.query('SELECT id FROM users WHERE LOWER(username)=LOWER($1)', [username]);
    if (ex.rows.length) return res.status(409).json({ error: 'Username taken' });
    await pool.query('INSERT INTO users (username,password,display_name,status,created_at) VALUES($1,$2,$3,$4,$5)',
      [username, hash(password), username, 'active', Date.now()]);
    res.status(201).json({ message: 'Account created!' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username||!password) return res.status(400).json({ error: 'Fill all fields' });
    if (isAdminCreds(username, password)) {
      return res.json({ token:'admin_'+genToken(), username:ADMIN_USERNAME, isAdmin:true, display_name:'Admin' });
    }
    const r = await pool.query('SELECT * FROM users WHERE LOWER(username)=LOWER($1) AND password=$2', [username, hash(password)]);
    if (!r.rows.length) return res.status(401).json({ error: 'Incorrect username or password' });
    const u = r.rows[0];
    if (u.status==='banned') return res.status(403).json({ error: 'Account banned. Contact admin.' });
    if (u.status==='suspended') return res.status(403).json({ error: 'Account suspended. Contact admin.' });
    const token = genToken();
    await pool.query('INSERT INTO sessions (token,username,created_at) VALUES($1,$2,$3)', [token, u.username, Date.now()]);
    pool.query('UPDATE users SET last_seen=$1 WHERE username=$2', [Date.now(), u.username]).catch(()=>{});
    res.json({ token, username:u.username, isAdmin:false, display_name:u.display_name||u.username, avatar_url:u.avatar_url, user_tag:u.user_tag });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/logout', requireAuth, async (req, res) => {
  const t = req.headers['x-auth-token'];
  if (!t.startsWith('admin_')) await pool.query('DELETE FROM sessions WHERE token=$1', [t]).catch(()=>{});
  res.json({ message: 'ok' });
});

app.get('/api/me', requireAuth, async (req, res) => {
  if (req.isAdmin) return res.json({ username:ADMIN_USERNAME, isAdmin:true, display_name:'Admin', avatar_url:null, user_tag:'Admin' });
  const r = await pool.query('SELECT username,display_name,avatar_url,status,user_tag FROM users WHERE username=$1', [req.username]);
  const u = r.rows[0]||{};
  res.json({ username:req.username, isAdmin:false, display_name:u.display_name||req.username, avatar_url:u.avatar_url, user_tag:u.user_tag });
});

// ── PROFILE ────────────────────────────────────────────────
app.get('/api/profile/:username', optionalAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT username,display_name,avatar_url,user_tag,created_at,last_seen FROM users WHERE username=$1 AND status!=$2', [req.params.username,'banned']);
    if (!r.rows.length) return res.status(404).json({ error: 'User not found' });
    const u = r.rows[0];
    const blogs = await pool.query(
      'SELECT id,title,content,image_url,video_url,image_position,ai_tools,generation_type,created_at FROM blogs WHERE owner=$1 AND is_public=true ORDER BY created_at DESC',
      [req.params.username]
    );
    // Friend status
    let friendStatus = null;
    if (req.username && req.username !== req.params.username) {
      const fr = await pool.query(
        'SELECT * FROM friendships WHERE (requester=$1 AND recipient=$2) OR (requester=$2 AND recipient=$1)',
        [req.username, req.params.username]
      );
      if (fr.rows.length) friendStatus = fr.rows[0].status === 'accepted' ? 'friends' : fr.rows[0].requester === req.username ? 'sent' : 'received';
    }
    res.json({ ...u, blogs: blogs.rows, friend_status: friendStatus });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/profile', requireAuth, async (req, res) => {
  try {
    const { display_name } = req.body;
    if (!display_name?.trim()) return res.status(400).json({ error: 'Name required' });
    await pool.query('UPDATE users SET display_name=$1 WHERE username=$2', [display_name.trim(), req.username]);
    res.json({ display_name: display_name.trim() });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/profile/avatar', requireAuth, upload.single('avatar'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No image' });
    const old = await pool.query('SELECT avatar_cloudinary_id FROM users WHERE username=$1', [req.username]);
    if (old.rows[0]?.avatar_cloudinary_id) await cloudinary.uploader.destroy(old.rows[0].avatar_cloudinary_id).catch(()=>{});
    const result = await new Promise((resolve,reject)=>{
      const s = cloudinary.uploader.upload_stream({ folder:'avatars', transformation:[{width:200,height:200,crop:'fill'}] }, (e,r)=>e?reject(e):resolve(r));
      s.end(req.file.buffer);
    });
    await pool.query('UPDATE users SET avatar_url=$1,avatar_cloudinary_id=$2 WHERE username=$3', [result.secure_url, result.public_id, req.username]);
    res.json({ avatar_url: result.secure_url });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── FRIENDS ────────────────────────────────────────────────
app.post('/api/friends/request/:username', requireAuth, async (req, res) => {
  try {
    const recipient = req.params.username;
    if (recipient === req.username) return res.status(400).json({ error: 'Cannot friend yourself' });
    const exists = await pool.query('SELECT id FROM users WHERE username=$1 AND status=$2', [recipient,'active']);
    if (!exists.rows.length) return res.status(404).json({ error: 'User not found' });
    const existing = await pool.query('SELECT * FROM friendships WHERE (requester=$1 AND recipient=$2) OR (requester=$2 AND recipient=$1)', [req.username, recipient]);
    if (existing.rows.length) return res.status(409).json({ error: 'Friend request already exists' });
    const id = crypto.randomBytes(8).toString('hex');
    await pool.query('INSERT INTO friendships (id,requester,recipient,status,created_at) VALUES($1,$2,$3,$4,$5)', [id, req.username, recipient, 'pending', Date.now()]);
    res.status(201).json({ message: 'Friend request sent!' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/friends/:username/accept', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('UPDATE friendships SET status=$1 WHERE requester=$2 AND recipient=$3 AND status=$4 RETURNING *', ['accepted', req.params.username, req.username, 'pending']);
    if (!r.rows.length) return res.status(404).json({ error: 'Request not found' });
    res.json({ message: 'Friend request accepted!' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/friends/:username', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM friendships WHERE (requester=$1 AND recipient=$2) OR (requester=$2 AND recipient=$1)', [req.username, req.params.username]);
    res.json({ message: 'Removed' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/friends', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT f.*, 
        CASE WHEN f.requester=$1 THEN f.recipient ELSE f.requester END as other_user,
        u.display_name, u.avatar_url, u.last_seen, u.user_tag
      FROM friendships f
      JOIN users u ON u.username = CASE WHEN f.requester=$1 THEN f.recipient ELSE f.requester END
      WHERE (f.requester=$1 OR f.recipient=$1) AND f.status='accepted'
    `, [req.username]);
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/friends/requests', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(`
      SELECT f.*, u.display_name, u.avatar_url, u.user_tag
      FROM friendships f JOIN users u ON u.username=f.requester
      WHERE f.recipient=$1 AND f.status='pending'
    `, [req.username]);
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── PHOTOS ─────────────────────────────────────────────────
app.get('/api/photos', requireAuth, async (req, res) => {
  try { res.json((await pool.query('SELECT * FROM photos WHERE owner=$1 ORDER BY timestamp DESC', [req.username])).rows); }
  catch(err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/upload', requireAuth, upload.array('photos', 20), async (req, res) => {
  try {
    if (!req.files?.length) return res.status(400).json({ error: 'No files' });
    const now = Date.now(); const uploaded = [];
    for (const file of req.files) {
      if (!file.mimetype.startsWith('image/')) continue;
      const result = await new Promise((resolve,reject)=>{
        const s=cloudinary.uploader.upload_stream({folder:'automation-note'},(e,r)=>e?reject(e):resolve(r));
        s.end(file.buffer);
      });
      const id=crypto.randomBytes(8).toString('hex');
      await pool.query('INSERT INTO photos (id,cloudinary_id,src,original_name,timestamp,owner) VALUES($1,$2,$3,$4,$5,$6)',
        [id, result.public_id, result.secure_url, file.originalname, now, req.username]);
      uploaded.push({id,cloudinary_id:result.public_id,src:result.secure_url,original_name:file.originalname,timestamp:now,owner:req.username});
    }
    res.status(201).json({ uploaded:uploaded.length, photos:uploaded });
  } catch(err) { res.status(500).json({ error: err.message }); }
});
app.delete('/api/photos/:id', requireAuth, async (req, res) => {
  try {
    const r=await pool.query('SELECT * FROM photos WHERE id=$1 AND owner=$2', [req.params.id,req.username]);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    await cloudinary.uploader.destroy(r.rows[0].cloudinary_id).catch(()=>{});
    await pool.query('DELETE FROM photos WHERE id=$1', [req.params.id]);
    res.json({message:'Deleted'});
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── NOTES ──────────────────────────────────────────────────
app.get('/api/notes', requireAuth, async (req,res) => {
  try { const r=await pool.query('SELECT * FROM notes WHERE owner=$1 ORDER BY updated_at DESC',[req.username]); res.json(r.rows.map(n=>({id:n.id,title:n.title,content:n.content,owner:n.owner,createdAt:n.created_at,updatedAt:n.updated_at}))); }
  catch(err){res.status(500).json({error:err.message});}
});
app.post('/api/notes', requireAuth, async (req,res) => {
  try {
    const{title,content}=req.body; if(!content) return res.status(400).json({error:'Content required'});
    const id=crypto.randomBytes(8).toString('hex'); const now=Date.now();
    await pool.query('INSERT INTO notes(id,title,content,owner,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6)',[id,title||'Untitled',content,req.username,now,now]);
    res.status(201).json({id,title:title||'Untitled',content,owner:req.username,createdAt:now,updatedAt:now});
  } catch(err){res.status(500).json({error:err.message});}
});
app.put('/api/notes/:id', requireAuth, async (req,res) => {
  try {
    const{title,content}=req.body; const now=Date.now();
    const r=await pool.query('UPDATE notes SET title=$1,content=$2,updated_at=$3 WHERE id=$4 AND owner=$5 RETURNING *',[title,content,now,req.params.id,req.username]);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    const n=r.rows[0]; res.json({id:n.id,title:n.title,content:n.content,owner:n.owner,createdAt:n.created_at,updatedAt:n.updated_at});
  } catch(err){res.status(500).json({error:err.message});}
});
app.delete('/api/notes/:id', requireAuth, async (req,res) => {
  try { await pool.query('DELETE FROM notes WHERE id=$1 AND owner=$2',[req.params.id,req.username]); res.json({message:'ok'}); }
  catch(err){res.status(500).json({error:err.message});}
});

// ── BLOG ───────────────────────────────────────────────────
app.post('/api/blog-image', requireAuth, upload.single('image'), async (req,res) => {
  try {
    if(!req.file) return res.status(400).json({error:'No file'});
    const result=await new Promise((resolve,reject)=>{
      const s=cloudinary.uploader.upload_stream({folder:'blog-images'},(e,r)=>e?reject(e):resolve(r)); s.end(req.file.buffer);
    });
    res.json({url:result.secure_url,cloudinary_id:result.public_id});
  } catch(err){res.status(500).json({error:err.message});}
});

app.post('/api/blog-video', requireAuth, upload.single('video'), async (req,res) => {
  try {
    if(!req.file) return res.status(400).json({error:'No file'});
    if(!req.file.mimetype.startsWith('video/')) return res.status(400).json({error:'Video files only'});
    const result=await new Promise((resolve,reject)=>{
      const s=cloudinary.uploader.upload_stream({folder:'blog-videos',resource_type:'video'},(e,r)=>e?reject(e):resolve(r)); s.end(req.file.buffer);
    });
    res.json({url:result.secure_url,cloudinary_id:result.public_id});
  } catch(err){res.status(500).json({error:err.message});}
});

// Helper to build blog query with rating avg
async function enrichBlogs(rows, viewerUsername) {
  const ids = rows.map(b => b.id);
  if (!ids.length) return rows;
  const ratings = await pool.query('SELECT blog_id, AVG(rating)::numeric(4,1) as avg_rating, COUNT(*) as rating_count FROM blog_ratings WHERE blog_id=ANY($1) GROUP BY blog_id', [ids]);
  const ratingMap = {};
  ratings.rows.forEach(r => ratingMap[r.blog_id] = { avg: parseFloat(r.avg_rating)||0, count: parseInt(r.rating_count)||0 });
  let myRatings = {};
  if (viewerUsername) {
    const mr = await pool.query('SELECT blog_id, rating FROM blog_ratings WHERE rater=$1 AND blog_id=ANY($2)', [viewerUsername, ids]);
    mr.rows.forEach(r => myRatings[r.blog_id] = r.rating);
  }
  return rows.map(b => ({
    ...b,
    avg_rating: ratingMap[b.id]?.avg || 0,
    rating_count: ratingMap[b.id]?.count || 0,
    my_rating: myRatings[b.id] || null,
  }));
}

app.get('/api/blogs/public', optionalAuth, async (req,res) => {
  try {
    const r=await pool.query(`SELECT b.*,u.display_name,u.avatar_url,u.user_tag,u.top_contributor FROM blogs b LEFT JOIN users u ON b.owner=u.username WHERE b.is_public=true ORDER BY b.created_at DESC`);
    res.json(await enrichBlogs(r.rows, req.username));
  } catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/blogs/mine', requireAuth, async (req,res) => {
  try { const r=await pool.query('SELECT * FROM blogs WHERE owner=$1 ORDER BY created_at DESC',[req.username]); res.json(r.rows); }
  catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/blogs/:id', optionalAuth, async (req,res) => {
  try {
    const r=await pool.query('SELECT b.*,u.display_name,u.avatar_url,u.user_tag FROM blogs b LEFT JOIN users u ON b.owner=u.username WHERE b.id=$1',[req.params.id]);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    const blog=r.rows[0];
    if(!blog.is_public && blog.owner!==req.username && !req.isAdmin) return res.status(403).json({error:'Private post', needsAuth:true});
    const comments=await pool.query('SELECT c.*,u.display_name,u.avatar_url FROM blog_comments c LEFT JOIN users u ON c.author=u.username WHERE c.blog_id=$1 ORDER BY c.created_at ASC',[req.params.id]);
    const enriched=(await enrichBlogs([blog], req.username))[0];
    res.json({...enriched, comments:comments.rows});
  } catch(err){res.status(500).json({error:err.message});}
});
app.post('/api/blogs', requireAuth, async (req,res) => {
  try {
    const{title,content,image_url,cloudinary_id,video_url,video_cloudinary_id,image_position,is_public,ai_tools,generation_type}=req.body;
    if(!title||!content) return res.status(400).json({error:'Title and content required'});
    const id=crypto.randomBytes(10).toString('hex'); const now=Date.now();
    await pool.query('INSERT INTO blogs(id,title,content,image_url,cloudinary_id,video_url,video_cloudinary_id,image_position,is_public,ai_tools,generation_type,owner,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
      [id,title,content,image_url||null,cloudinary_id||null,video_url||null,video_cloudinary_id||null,image_position||'left',is_public||false,ai_tools||[],generation_type||null,req.username,now,now]);
    res.status(201).json({id,title,content,image_url,video_url,ai_tools,generation_type,is_public,owner:req.username,created_at:now});
  } catch(err){res.status(500).json({error:err.message});}
});
app.put('/api/blogs/:id', requireAuth, async (req,res) => {
  try {
    const{title,content,image_url,cloudinary_id,video_url,video_cloudinary_id,image_position,is_public,ai_tools,generation_type}=req.body; const now=Date.now();
    const r=await pool.query('UPDATE blogs SET title=$1,content=$2,image_url=$3,cloudinary_id=$4,video_url=$5,video_cloudinary_id=$6,image_position=$7,is_public=$8,ai_tools=$9,generation_type=$10,updated_at=$11 WHERE id=$12 AND owner=$13 RETURNING *',
      [title,content,image_url||null,cloudinary_id||null,video_url||null,video_cloudinary_id||null,image_position||'left',is_public||false,ai_tools||[],generation_type||null,now,req.params.id,req.username]);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    res.json(r.rows[0]);
  } catch(err){res.status(500).json({error:err.message});}
});
app.delete('/api/blogs/:id', requireAuth, async (req,res) => {
  try {
    const clause=req.isAdmin?'WHERE id=$1':'WHERE id=$1 AND owner=$2';
    const params=req.isAdmin?[req.params.id]:[req.params.id,req.username];
    const r=await pool.query(`SELECT * FROM blogs ${clause}`,params);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    const b=r.rows[0];
    if(b.cloudinary_id) await cloudinary.uploader.destroy(b.cloudinary_id).catch(()=>{});
    if(b.video_cloudinary_id) await cloudinary.uploader.destroy(b.video_cloudinary_id,{resource_type:'video'}).catch(()=>{});
    await pool.query('DELETE FROM blogs WHERE id=$1',[req.params.id]);
    res.json({message:'Deleted'});
  } catch(err){res.status(500).json({error:err.message});}
});
app.patch('/api/blogs/:id/visibility', requireAuth, async (req,res) => {
  try {
    const r=await pool.query('UPDATE blogs SET is_public=$1 WHERE id=$2 AND owner=$3 RETURNING id,is_public',[req.body.is_public,req.params.id,req.username]);
    if(!r.rows.length) return res.status(404).json({error:'Not found'});
    res.json(r.rows[0]);
  } catch(err){res.status(500).json({error:err.message});}
});

// ── RATINGS ────────────────────────────────────────────────
app.post('/api/blogs/:id/rate', requireAuth, async (req,res) => {
  try {
    const{rating}=req.body;
    if(!rating||rating<1||rating>10) return res.status(400).json({error:'Rating must be 1-10'});
    const blog=await pool.query('SELECT owner FROM blogs WHERE id=$1',[req.params.id]);
    if(!blog.rows.length) return res.status(404).json({error:'Post not found'});
    if(blog.rows[0].owner===req.username) return res.status(400).json({error:'Cannot rate your own post'});
    const id=crypto.randomBytes(8).toString('hex');
    await pool.query('INSERT INTO blog_ratings(id,blog_id,rater,rating,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(blog_id,rater) DO UPDATE SET rating=$4',
      [id,req.params.id,req.username,rating,Date.now()]);
    const avg=await pool.query('SELECT AVG(rating)::numeric(4,1) as avg,COUNT(*) as cnt FROM blog_ratings WHERE blog_id=$1',[req.params.id]);
    res.json({avg_rating:parseFloat(avg.rows[0].avg)||0, rating_count:parseInt(avg.rows[0].cnt)||0, my_rating:rating});
  } catch(err){res.status(500).json({error:err.message});}
});

// ── COMMENTS ───────────────────────────────────────────────
app.post('/api/blogs/:id/comments', requireAuth, async (req,res) => {
  try {
    const{content}=req.body; if(!content?.trim()) return res.status(400).json({error:'Empty'});
    const blog=await pool.query('SELECT * FROM blogs WHERE id=$1',[req.params.id]);
    if(!blog.rows.length) return res.status(404).json({error:'Not found'});
    if(!blog.rows[0].is_public && blog.rows[0].owner!==req.username && !req.isAdmin) return res.status(403).json({error:'Private'});
    const id=crypto.randomBytes(8).toString('hex'); const now=Date.now();
    await pool.query('INSERT INTO blog_comments(id,blog_id,author,content,created_at) VALUES($1,$2,$3,$4,$5)',[id,req.params.id,req.username,content.trim(),now]);
    const u=await pool.query('SELECT display_name,avatar_url FROM users WHERE username=$1',[req.username]);
    res.status(201).json({id,blog_id:req.params.id,author:req.username,display_name:u.rows[0]?.display_name||req.username,avatar_url:u.rows[0]?.avatar_url,content:content.trim(),created_at:now});
  } catch(err){res.status(500).json({error:err.message});}
});
app.delete('/api/blogs/:blogId/comments/:commentId', requireAuth, async (req,res) => {
  try {
    const c=await pool.query('SELECT * FROM blog_comments WHERE id=$1 AND blog_id=$2',[req.params.commentId,req.params.blogId]);
    if(!c.rows.length) return res.status(404).json({error:'Not found'});
    const b=await pool.query('SELECT owner FROM blogs WHERE id=$1',[req.params.blogId]);
    if(c.rows[0].author!==req.username && b.rows[0]?.owner!==req.username && !req.isAdmin) return res.status(403).json({error:'Not allowed'});
    await pool.query('DELETE FROM blog_comments WHERE id=$1',[req.params.commentId]);
    res.json({message:'ok'});
  } catch(err){res.status(500).json({error:err.message});}
});

// ── MESSAGES ───────────────────────────────────────────────
app.get('/api/messages/conversations', requireAuth, async (req,res) => {
  try {
    const r=await pool.query(`
      SELECT DISTINCT ON(other_user) CASE WHEN from_user=$1 THEN to_user ELSE from_user END as other_user,
        content,created_at, CASE WHEN from_user=$1 THEN false ELSE NOT read END as has_unread
      FROM messages WHERE from_user=$1 OR to_user=$1 ORDER BY other_user,created_at DESC
    `,[req.username]);
    const users=[...new Set(r.rows.map(x=>x.other_user))];
    let pm={};
    if(users.length){const pr=await pool.query('SELECT username,display_name,avatar_url FROM users WHERE username=ANY($1)',[users]); pr.rows.forEach(u=>pm[u.username]=u);}
    res.json(r.rows.map(x=>({...x,display_name:pm[x.other_user]?.display_name||x.other_user,avatar_url:pm[x.other_user]?.avatar_url})));
  } catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/messages/:otherUser', requireAuth, async (req,res) => {
  try {
    const r=await pool.query('SELECT * FROM messages WHERE (from_user=$1 AND to_user=$2) OR (from_user=$2 AND to_user=$1) ORDER BY created_at ASC',[req.username,req.params.otherUser]);
    await pool.query('UPDATE messages SET read=true WHERE to_user=$1 AND from_user=$2',[req.username,req.params.otherUser]);
    res.json(r.rows);
  } catch(err){res.status(500).json({error:err.message});}
});
app.post('/api/messages/:toUser', requireAuth, async (req,res) => {
  try {
    const{content}=req.body; if(!content?.trim()) return res.status(400).json({error:'Empty'});
    if(req.params.toUser===req.username) return res.status(400).json({error:'Cannot message yourself'});
    const ex=await pool.query('SELECT username FROM users WHERE username=$1',[req.params.toUser]);
    if(!ex.rows.length) return res.status(404).json({error:'User not found'});
    const id=crypto.randomBytes(8).toString('hex'); const now=Date.now();
    await pool.query('INSERT INTO messages(id,from_user,to_user,content,read,created_at) VALUES($1,$2,$3,$4,$5,$6)',[id,req.username,req.params.toUser,content.trim(),false,now]);
    res.status(201).json({id,from_user:req.username,to_user:req.params.toUser,content:content.trim(),read:false,created_at:now});
  } catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/messages/unread/count', requireAuth, async (req,res) => {
  try { const r=await pool.query('SELECT COUNT(*) FROM messages WHERE to_user=$1 AND read=false',[req.username]); res.json({count:parseInt(r.rows[0].count)}); }
  catch(err){res.status(500).json({error:err.message});}
});

// ── FRIEND SUGGESTIONS ─────────────────────────────────────
app.get('/api/friends/suggestions', requireAuth, async (req,res) => {
  try {
    // Get users not already friends or pending, exclude self, order by blog count
    const r = await pool.query(`
      SELECT u.username, u.display_name, u.avatar_url, u.user_tag, u.top_contributor,
        (SELECT COUNT(*) FROM blogs b WHERE b.owner=u.username AND b.is_public=true) as post_count
      FROM users u
      WHERE u.username != $1
        AND u.status = 'active'
        AND u.username NOT IN (
          SELECT CASE WHEN requester=$1 THEN recipient ELSE requester END
          FROM friendships WHERE requester=$1 OR recipient=$1
        )
      ORDER BY post_count DESC, u.created_at DESC
      LIMIT 6
    `, [req.username]);
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── REPORTS / CONTACT ADMIN ─────────────────────────────────
app.post('/api/report', requireAuth, async (req,res) => {
  try {
    const { type, content } = req.body;
    if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
    const id = crypto.randomBytes(8).toString('hex');
    await pool.query('INSERT INTO reports (id,from_user,type,content,read,created_at) VALUES($1,$2,$3,$4,$5,$6)',
      [id, req.username, type||'general', content.trim(), false, Date.now()]);
    res.status(201).json({ message: 'Report submitted!' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/reports', requireAdmin, async (req,res) => {
  try {
    const r = await pool.query('SELECT * FROM reports ORDER BY created_at DESC');
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/admin/reports/:id/read', requireAdmin, async (req,res) => {
  try {
    await pool.query('UPDATE reports SET read=true WHERE id=$1', [req.params.id]);
    res.json({ message: 'ok' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── ADMIN ──────────────────────────────────────────────────
app.get('/api/admin/stats', requireAdmin, async (req,res) => {
  try {
    const [u,b,p,m,o]=await Promise.all([
      pool.query('SELECT COUNT(*) FROM users'),
      pool.query('SELECT COUNT(*) FROM blogs'),
      pool.query('SELECT COUNT(*) FROM photos'),
      pool.query('SELECT COUNT(*) FROM messages'),
      pool.query('SELECT COUNT(*) FROM users WHERE last_seen>$1',[Date.now()-5*60*1000]),
    ]);
    res.json({total_users:+u.rows[0].count,total_blogs:+b.rows[0].count,total_photos:+p.rows[0].count,total_messages:+m.rows[0].count,online_users:+o.rows[0].count});
  } catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/admin/users', requireAdmin, async (req,res) => {
  try {
    const r=await pool.query('SELECT id,username,display_name,avatar_url,user_tag,top_contributor,status,created_at,last_seen FROM users ORDER BY created_at DESC');
    const now=Date.now();
    res.json(r.rows.map(u=>({...u,is_online:u.last_seen&&(now-u.last_seen)<5*60*1000})));
  } catch(err){res.status(500).json({error:err.message});}
});
app.patch('/api/admin/users/:username/status', requireAdmin, async (req,res) => {
  try {
    const{status,reason}=req.body;
    if(!['active','suspended','banned'].includes(status)) return res.status(400).json({error:'Invalid'});
    if(req.params.username.toLowerCase()===ADMIN_USERNAME) return res.status(400).json({error:'Cannot modify admin'});
    await pool.query('UPDATE users SET status=$1 WHERE username=$2',[status,req.params.username]);
    if(status!=='active') await pool.query('DELETE FROM sessions WHERE username=$1',[req.params.username]);
    await pool.query('INSERT INTO admin_log(action,target,reason,created_at) VALUES($1,$2,$3,$4)',[status,req.params.username,reason||null,Date.now()]);
    res.json({message:`${req.params.username} is now ${status}`});
  } catch(err){res.status(500).json({error:err.message});}
});
app.patch('/api/admin/users/:username/top-contributor', requireAdmin, async (req,res) => {
  try {
    const { value } = req.body;
    if(req.params.username.toLowerCase()===ADMIN_USERNAME) return res.status(400).json({error:'Cannot modify admin'});
    await pool.query('UPDATE users SET top_contributor=$1 WHERE username=$2', [!!value, req.params.username]);
    await pool.query('INSERT INTO admin_log(action,target,reason,created_at) VALUES($1,$2,$3,$4)',
      [value?'top_contributor_added':'top_contributor_removed', req.params.username, null, Date.now()]);
    res.json({ message: 'Updated' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/admin/users/:username/tag', requireAdmin, async (req,res) => {
  try {
    const{tag}=req.body;
    if(req.params.username.toLowerCase()===ADMIN_USERNAME) return res.status(400).json({error:'Cannot modify admin'});
    await pool.query('UPDATE users SET user_tag=$1 WHERE username=$2',[tag||null,req.params.username]);
    await pool.query('INSERT INTO admin_log(action,target,reason,created_at) VALUES($1,$2,$3,$4)',['tagged',req.params.username,tag||'removed tag',Date.now()]);
    res.json({message:'Tag updated'});
  } catch(err){res.status(500).json({error:err.message});}
});
app.delete('/api/admin/users/:username', requireAdmin, async (req,res) => {
  try {
    if(req.params.username.toLowerCase()===ADMIN_USERNAME) return res.status(400).json({error:'Cannot delete admin'});
    await pool.query('DELETE FROM sessions WHERE username=$1',[req.params.username]);
    await pool.query('DELETE FROM messages WHERE from_user=$1 OR to_user=$1',[req.params.username]);
    await pool.query('DELETE FROM notes WHERE owner=$1',[req.params.username]);
    await pool.query('DELETE FROM photos WHERE owner=$1',[req.params.username]);
    await pool.query('DELETE FROM blogs WHERE owner=$1',[req.params.username]);
    await pool.query('DELETE FROM friendships WHERE requester=$1 OR recipient=$1',[req.params.username]);
    await pool.query('DELETE FROM users WHERE username=$1',[req.params.username]);
    await pool.query('INSERT INTO admin_log(action,target,reason,created_at) VALUES($1,$2,$3,$4)',['deleted',req.params.username,'Admin deleted',Date.now()]);
    res.json({message:'Deleted'});
  } catch(err){res.status(500).json({error:err.message});}
});
app.get('/api/admin/log', requireAdmin, async (req,res) => {
  try { res.json((await pool.query('SELECT * FROM admin_log ORDER BY created_at DESC LIMIT 100')).rows); }
  catch(err){res.status(500).json({error:err.message});}
});


// ── COLLECTIONS ────────────────────────────────────────────

// Get all my collections
app.get('/api/collections', requireAuth, async(req,res) => {
  try {
    const r = await pool.query(
      `SELECT c.*,
        (SELECT COUNT(*) FROM collection_photos WHERE collection_id=c.id) as photo_count,
        (SELECT COUNT(*) FROM collection_notes WHERE collection_id=c.id) as note_count
       FROM collections c WHERE c.owner=$1 ORDER BY c.updated_at DESC`,
      [req.username]
    );
    res.json(r.rows);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Get single collection with items
app.get('/api/collections/:id', optionalAuth, async(req,res) => {
  try {
    const r = await pool.query('SELECT * FROM collections WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    const col = r.rows[0];
    if (!col.is_public && col.owner !== req.username) return res.status(403).json({ error: 'Private collection' });
    const photos = await pool.query(
      `SELECT p.* FROM photos p JOIN collection_photos cp ON p.id=cp.photo_id WHERE cp.collection_id=$1 ORDER BY cp.added_at DESC`,
      [req.params.id]
    );
    const notes = await pool.query(
      `SELECT n.* FROM notes n JOIN collection_notes cn ON n.id=cn.note_id WHERE cn.collection_id=$1 ORDER BY cn.added_at DESC`,
      [req.params.id]
    );
    res.json({ ...col, photos: photos.rows, notes: notes.rows });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Create collection
app.post('/api/collections', requireAuth, async(req,res) => {
  try {
    const { name, description, type } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Name required' });
    const id = crypto.randomBytes(10).toString('hex');
    const now = Date.now();
    await pool.query(
      'INSERT INTO collections(id,name,description,type,is_public,owner,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, name.trim(), description||null, type||'mixed', false, req.username, now, now]
    );
    res.status(201).json({ id, name: name.trim(), description, type: type||'mixed', is_public: false, owner: req.username, created_at: now, updated_at: now, photo_count: 0, note_count: 0 });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Rename / update collection
app.put('/api/collections/:id', requireAuth, async(req,res) => {
  try {
    const { name, description, is_public } = req.body;
    const now = Date.now();
    const r = await pool.query(
      'UPDATE collections SET name=COALESCE($1,name), description=$2, is_public=COALESCE($3,is_public), updated_at=$4 WHERE id=$5 AND owner=$6 RETURNING *',
      [name?.trim()||null, description, is_public, now, req.params.id, req.username]
    );
    if (!r.rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0]);
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Delete collection
app.delete('/api/collections/:id', requireAuth, async(req,res) => {
  try {
    await pool.query('DELETE FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    res.json({ message: 'ok' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Upload collection cover
app.post('/api/collections/:id/cover', requireAuth, upload.single('cover'), async(req,res) => {
  try {
    if (!req.file || !req.file.mimetype.startsWith('image/')) return res.status(400).json({ error: 'Image required' });
    const old = await pool.query('SELECT cover_cloudinary_id FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    if (!old.rows.length) return res.status(404).json({ error: 'Not found' });
    if (old.rows[0].cover_cloudinary_id) await cloudinary.uploader.destroy(old.rows[0].cover_cloudinary_id).catch(()=>{});
    const result = await new Promise((resolve,reject) => {
      const s = cloudinary.uploader.upload_stream({ folder:'collection-covers', transformation:[{width:800,height:600,crop:'fill'}] }, (e,r)=>e?reject(e):resolve(r));
      s.end(req.file.buffer);
    });
    await pool.query('UPDATE collections SET cover_url=$1, cover_cloudinary_id=$2, updated_at=$3 WHERE id=$4 AND owner=$5',
      [result.secure_url, result.public_id, Date.now(), req.params.id, req.username]);
    res.json({ cover_url: result.secure_url });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Add photos to collection
app.post('/api/collections/:id/photos', requireAuth, async(req,res) => {
  try {
    const { photo_ids } = req.body;
    if (!photo_ids?.length) return res.status(400).json({ error: 'No photos specified' });
    const col = await pool.query('SELECT * FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    if (!col.rows.length) return res.status(404).json({ error: 'Collection not found' });
    const now = Date.now(); let added = 0;
    for (const pid of photo_ids) {
      try {
        const id = crypto.randomBytes(8).toString('hex');
        await pool.query('INSERT INTO collection_photos(id,collection_id,photo_id,added_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING', [id, req.params.id, pid, now]);
        added++;
      } catch(e) {}
    }
    // Auto-set cover from first photo if none set
    if (!col.rows[0].cover_url && photo_ids[0]) {
      const ph = await pool.query('SELECT src FROM photos WHERE id=$1', [photo_ids[0]]);
      if (ph.rows.length) await pool.query('UPDATE collections SET cover_url=$1,updated_at=$2 WHERE id=$3', [ph.rows[0].src, now, req.params.id]);
    }
    await pool.query('UPDATE collections SET updated_at=$1 WHERE id=$2', [now, req.params.id]);
    res.json({ added });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Remove photo from collection
app.delete('/api/collections/:id/photos/:photoId', requireAuth, async(req,res) => {
  try {
    const col = await pool.query('SELECT id FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    if (!col.rows.length) return res.status(403).json({ error: 'Not allowed' });
    await pool.query('DELETE FROM collection_photos WHERE collection_id=$1 AND photo_id=$2', [req.params.id, req.params.photoId]);
    res.json({ message: 'ok' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Add notes to collection
app.post('/api/collections/:id/notes', requireAuth, async(req,res) => {
  try {
    const { note_ids } = req.body;
    if (!note_ids?.length) return res.status(400).json({ error: 'No notes specified' });
    const col = await pool.query('SELECT * FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    if (!col.rows.length) return res.status(404).json({ error: 'Collection not found' });
    const now = Date.now(); let added = 0;
    for (const nid of note_ids) {
      try {
        const id = crypto.randomBytes(8).toString('hex');
        await pool.query('INSERT INTO collection_notes(id,collection_id,note_id,added_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING', [id, req.params.id, nid, now]);
        added++;
      } catch(e) {}
    }
    await pool.query('UPDATE collections SET updated_at=$1 WHERE id=$2', [now, req.params.id]);
    res.json({ added });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// Remove note from collection
app.delete('/api/collections/:id/notes/:noteId', requireAuth, async(req,res) => {
  try {
    const col = await pool.query('SELECT id FROM collections WHERE id=$1 AND owner=$2', [req.params.id, req.username]);
    if (!col.rows.length) return res.status(403).json({ error: 'Not allowed' });
    await pool.query('DELETE FROM collection_notes WHERE collection_id=$1 AND note_id=$2', [req.params.id, req.params.noteId]);
    res.json({ message: 'ok' });
  } catch(err) { res.status(500).json({ error: err.message }); }
});

// ── FALLBACK ───────────────────────────────────────────────
app.get('/collection/:id', (req,res)=>res.sendFile(__dirname+'/public/index.html'));
app.get('/blog/:id', (req,res) => res.sendFile(__dirname+'/public/index.html'));
app.get('/user/:username', (req,res) => res.sendFile(__dirname+'/public/index.html'));
app.get('*', (req,res) => res.sendFile(__dirname+'/public/index.html'));
app.use((err,req,res,next) => {
  if(err.code==='LIMIT_FILE_SIZE') return res.status(413).json({error:'File too large'});
  res.status(500).json({error:err.message});
});

app.listen(PORT, () => console.log(`✅ Automation Note v6 running on :${PORT}`));
