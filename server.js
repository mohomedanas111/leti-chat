/**
 * LETI Chat — Backend Server
 * Node.js + Express + MySQL + WebSocket (ws)
 * Configured for InfinityFree shared hosting database
 *
 * Install: npm install
 * Run:     node server.js
 */

'use strict';

const express    = require('express');
const http       = require('http');
const WebSocket  = require('ws');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcrypt');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const path       = require('path');
const fs         = require('fs');
const { v4: uuidv4 } = require('uuid');
const cors       = require('cors');
require('dotenv').config();

// ── CONFIG ─────────────────────────────────────────────────────────
const PORT        = process.env.PORT       || 3000;
const JWT_SECRET  = process.env.JWT_SECRET || 'leti_chat_jwt_secret_change_in_production';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// 7-day expiry in milliseconds
const EXPIRY_DAYS = 7;
function expiresAt() {
  const d = new Date();
  d.setDate(d.getDate() + EXPIRY_DAYS);
  return d.toISOString().slice(0, 19).replace('T', ' '); // MySQL DATETIME format
}

// ── DATABASE POOL ───────────────────────────────────────────────────
const pool = mysql.createPool({
  host:               process.env.DB_HOST     || 'localhost',
  port:               parseInt(process.env.DB_PORT) || 3306,
  user:               process.env.DB_USER     || 'root',
  password:           process.env.DB_PASSWORD || '',
  database:           process.env.DB_NAME     || 'leti_chat',
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  charset:            'utf8mb4',
  connectTimeout:     30000,
  enableKeepAlive:    true,
  keepAliveInitialDelay: 0,
});

async function db(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// Test DB connection on startup — print clear diagnostics
pool.getConnection()
  .then(conn => {
    console.log('✅ Database connected! Host:', process.env.DB_HOST, ' DB:', process.env.DB_NAME);
    conn.release();
  })
  .catch(err => {
    console.error('❌ Database connection failed:', err.message);
    console.error('   → Check your .env file: DB_HOST, DB_USER, DB_PASSWORD, DB_NAME');
    console.error('   → The server will keep running but API calls will return "Server error"');
  });

// ── EXPRESS APP ─────────────────────────────────────────────────────
const app = express();
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOADS_DIR));
// Serve index.html — works whether file is in /public or root directory
const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR) && fs.existsSync(path.join(PUBLIC_DIR, 'index.html'))) {
  app.use(express.static(PUBLIC_DIR));
  console.log('📁 Serving static files from /public');
} else {
  // Fallback: serve from root (index.html placed next to server.js)
  app.use(express.static(__dirname));
  console.log('📁 Serving static files from root (no /public folder found)');
}
// SPA catch-all — serve index.html for any non-API route
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api') || req.path.startsWith('/uploads') || req.path.startsWith('/ws')) return next();
  const htmlInPublic = path.join(__dirname, 'public', 'index.html');
  const htmlInRoot   = path.join(__dirname, 'index.html');
  if (fs.existsSync(htmlInPublic)) return res.sendFile(htmlInPublic);
  if (fs.existsSync(htmlInRoot))   return res.sendFile(htmlInRoot);
  next();
});

// ── MULTER (file uploads) ───────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_MB || 10) * 1024 * 1024 },
});

// ── AUTH MIDDLEWARE ─────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const token  = header.replace('Bearer ', '').trim();
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ═══════════════════════════════════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, avatar } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });

    const existing = await db('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const uid  = uuidv4();
    await db(
      'INSERT INTO users (id, name, email, password_hash, role, avatar) VALUES (?, ?, ?, ?, ?, ?)',
      [uid, name.trim(), email.toLowerCase(), hash, role || '', avatar || '👤']
    );
    // Auto-add to General group if it exists
    const gen = await db("SELECT id FROM `groups` WHERE id = 'g_general'");
    if (gen.length) {
      await db('INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', ['g_general', uid]);
    }
    const token = jwt.sign({ id: uid, name: name.trim(), email: email.toLowerCase(), is_admin: false }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: uid, name: name.trim(), email: email.toLowerCase(), role: role||'', avatar: avatar||'👤', is_admin: false }
    });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing fields' });

    const [user] = await db('SELECT * FROM users WHERE email = ?', [email.toLowerCase()]);
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

    await db("UPDATE users SET status = 'online', last_seen = NOW() WHERE id = ?", [user.id]);
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, is_admin: !!user.is_admin },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: { id: user.id, name: user.name, email: user.email, role: user.role, avatar: user.avatar, status: 'online', is_admin: !!user.is_admin }
    });
  } catch (e) {
    console.error('Login error:', e.message);
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// POST /api/auth/admin-register  ← SECRET URL, not linked anywhere in the UI
app.post('/api/auth/admin-register', async (req, res) => {
  try {
    const { name, email, password, secret_key } = req.body;
    // Read secret from DB settings (column is setting_key, not key)
    const [setting] = await db("SELECT value FROM app_settings WHERE setting_key = 'admin_secret_key'");
    const expectedSecret = setting?.value || 'LETI_SUPER_2024_@dm!n';

    if (secret_key !== expectedSecret) return res.status(403).json({ error: 'Invalid secret key' });
    if (!name || !email || !password)  return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 12)          return res.status(400).json({ error: 'Admin password must be at least 12 characters' });

    const existing = await db('SELECT id FROM users WHERE email = ?', [email.toLowerCase()]);
    if (existing.length) return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 12);
    const uid  = uuidv4();
    await db(
      "INSERT INTO users (id, name, email, password_hash, role, avatar, is_admin) VALUES (?, ?, ?, ?, 'Super Administrator', '🛡️', 1)",
      [uid, name.trim(), email.toLowerCase(), hash]
    );
    res.json({ message: 'Admin account created successfully' });
  } catch (e) {
    console.error('Admin register error:', e.message);
    res.status(500).json({ error: 'Server error: ' + e.message });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  await db("UPDATE users SET status = 'offline', last_seen = NOW() WHERE id = ?", [req.user.id]);
  res.json({ message: 'Logged out' });
});

// ═══════════════════════════════════════════════════════════════════
//  USERS
// ═══════════════════════════════════════════════════════════════════

app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await db(
    'SELECT id, name, email, role, avatar, status, last_seen FROM users WHERE is_admin = 0 AND id != ?',
    [req.user.id]
  );
  res.json(users);
});

app.get('/api/users/me', authMiddleware, async (req, res) => {
  const [user] = await db('SELECT id, name, email, role, avatar, status, is_admin FROM users WHERE id = ?', [req.user.id]);
  res.json(user);
});

app.patch('/api/users/me', authMiddleware, async (req, res) => {
  const { name, role, avatar, status } = req.body;
  await db(
    'UPDATE users SET name = COALESCE(?, name), role = COALESCE(?, role), avatar = COALESCE(?, avatar), status = COALESCE(?, status) WHERE id = ?',
    [name||null, role||null, avatar||null, status||null, req.user.id]
  );
  const [user] = await db('SELECT id, name, email, role, avatar, status FROM users WHERE id = ?', [req.user.id]);
  broadcast({ type: 'USER_STATUS', userId: req.user.id, status: user.status, name: user.name, avatar: user.avatar });
  res.json(user);
});

// ═══════════════════════════════════════════════════════════════════
//  CONVERSATIONS (Direct Messages)
// ═══════════════════════════════════════════════════════════════════

app.get('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.id;
    const convs = await db(`
      SELECT
        c.id AS conversation_id,
        c.updated_at,
        IF(c.user_a_id = ?, c.user_b_id, c.user_a_id)           AS partner_id,
        IF(c.user_a_id = ?, ub.name,   ua.name)                  AS partner_name,
        IF(c.user_a_id = ?, ub.avatar, ua.avatar)                AS partner_avatar,
        IF(c.user_a_id = ?, ub.status, ua.status)                AS partner_status,
        IF(c.user_a_id = ?, ub.role,   ua.role)                  AS partner_role,
        (SELECT content    FROM messages WHERE conversation_id = c.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message,
        (SELECT type       FROM messages WHERE conversation_id = c.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message_type,
        (SELECT created_at FROM messages WHERE conversation_id = c.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message_at,
        (SELECT COUNT(*)   FROM messages
          WHERE conversation_id = c.id AND from_user_id != ? AND is_deleted = 0 AND expires_at > NOW()
            AND id NOT IN (SELECT message_id FROM message_reads WHERE user_id = ?)) AS unread_count
      FROM conversations c
      JOIN users ua ON ua.id = c.user_a_id
      JOIN users ub ON ub.id = c.user_b_id
      WHERE c.user_a_id = ? OR c.user_b_id = ?
      ORDER BY COALESCE(last_message_at, c.updated_at) DESC`,
      [uid, uid, uid, uid, uid, uid, uid, uid, uid]
    );
    res.json(convs);
  } catch (e) {
    console.error('Conversations error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/conversations', authMiddleware, async (req, res) => {
  try {
    const { partner_id } = req.body;
    if (!partner_id) return res.status(400).json({ error: 'partner_id required' });

    const a = req.user.id, b = partner_id;
    const convId = a < b ? `${a}_${b}` : `${b}_${a}`;
    const userA  = a < b ? a : b;
    const userB  = a < b ? b : a;

    await db(
      'INSERT IGNORE INTO conversations (id, user_a_id, user_b_id) VALUES (?, ?, ?)',
      [convId, userA, userB]
    );
    res.json({ conversation_id: convId });
  } catch (e) {
    console.error('Create conv error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════
//  MESSAGES
// ═══════════════════════════════════════════════════════════════════

app.get('/api/messages/:convId', authMiddleware, async (req, res) => {
  try {
    const { convId } = req.params;
    const limit  = Math.min(parseInt(req.query.limit || 50), 100);
    const before = req.query.before;
    const isGroup = await isGroupId(convId);

    let msgs;
    const baseSelect = `
      SELECT m.id, m.from_user_id, u.name AS from_name, u.avatar AS from_avatar,
        m.type, m.content, m.reply_to_id, m.created_at, m.expires_at,
        m.conversation_id, m.group_id,
        (SELECT GROUP_CONCAT(CONCAT(emoji,'|',user_id) SEPARATOR ';;')
          FROM message_reactions WHERE message_id = m.id) AS reactions_raw,
        rm.id AS reply_id, rm.content AS reply_content, rm.from_user_id AS reply_from,
        ru.name AS reply_name
      FROM messages m
      JOIN users u ON u.id = m.from_user_id
      LEFT JOIN messages rm ON rm.id = m.reply_to_id
      LEFT JOIN users ru ON ru.id = rm.from_user_id`;

    if (isGroup) {
      msgs = await db(
        `${baseSelect}
        WHERE m.group_id = ? AND m.is_deleted = 0 AND m.expires_at > NOW()
          ${before ? 'AND m.created_at < ?' : ''}
        ORDER BY m.created_at DESC LIMIT ?`,
        before ? [convId, before, limit] : [convId, limit]
      );
    } else {
      msgs = await db(
        `${baseSelect}
        WHERE m.conversation_id = ? AND m.is_deleted = 0 AND m.expires_at > NOW()
          ${before ? 'AND m.created_at < ?' : ''}
        ORDER BY m.created_at DESC LIMIT ?`,
        before ? [convId, before, limit] : [convId, limit]
      );
    }

    // Parse reactions and reply_to from flat columns
    msgs = msgs.map(m => {
      const reactions = [];
      if (m.reactions_raw) {
        const counts = {};
        m.reactions_raw.split(';;').forEach(r => {
          const [emoji] = r.split('|');
          counts[emoji] = (counts[emoji] || 0) + 1;
        });
        Object.entries(counts).forEach(([emoji, count]) => reactions.push({ emoji, count }));
      }
      const reply_to = m.reply_id ? { id: m.reply_id, content: m.reply_content, from_user_id: m.reply_from, name: m.reply_name } : null;
      return { ...m, reactions, reply_to, reactions_raw: undefined };
    });

    // Get attachments for file/image messages
    const ids = msgs.filter(m => m.type !== 'text').map(m => m.id);
    if (ids.length) {
      const placeholders = ids.map(() => '?').join(',');
      const atts = await db(`SELECT * FROM message_attachments WHERE message_id IN (${placeholders})`, ids);
      const attMap = {};
      atts.forEach(a => { if (!attMap[a.message_id]) attMap[a.message_id] = []; attMap[a.message_id].push(a); });
      msgs = msgs.map(m => ({ ...m, attachments: attMap[m.id] || [] }));
    }

    // Mark messages as read
    for (const m of msgs) {
      if (m.from_user_id !== req.user.id) {
        await db('INSERT IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)', [m.id, req.user.id]).catch(() => {});
      }
    }

    res.json(msgs.reverse()); // oldest first
  } catch (e) {
    console.error('Get messages error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/messages — send text message
app.post('/api/messages', authMiddleware, async (req, res) => {
  try {
    const { conversation_id, group_id, content, reply_to_id, type = 'text' } = req.body;
    if (!content && type === 'text') return res.status(400).json({ error: 'Content required' });
    if (!conversation_id && !group_id) return res.status(400).json({ error: 'conversation_id or group_id required' });

    const msgId = uuidv4();
    const exp   = expiresAt();

    await db(
      'INSERT INTO messages (id, conversation_id, group_id, from_user_id, type, content, reply_to_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [msgId, conversation_id||null, group_id||null, req.user.id, type, content||null, reply_to_id||null, exp]
    );
    if (conversation_id) {
      await db('UPDATE conversations SET updated_at = NOW() WHERE id = ?', [conversation_id]);
    }

    const [msg] = await db(
      `SELECT m.*, u.name AS from_name, u.avatar AS from_avatar
       FROM messages m JOIN users u ON u.id = m.from_user_id WHERE m.id = ?`, [msgId]
    );

    const payload = { type: 'NEW_MESSAGE', message: { ...msg, reactions: [], attachments: [] } };
    if (group_id) broadcastToGroup(group_id, payload, req.user.id);
    else          broadcastToConversation(conversation_id, payload);

    res.json({ ...msg, reactions: [], attachments: [] });
  } catch (e) {
    console.error('Send message error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/messages/:id
app.delete('/api/messages/:id', authMiddleware, async (req, res) => {
  try {
    await db(
      'UPDATE messages SET is_deleted = 1, content = NULL WHERE id = ? AND (from_user_id = ? OR ? = 1)',
      [req.params.id, req.user.id, req.user.is_admin ? 1 : 0]
    );
    broadcast({ type: 'MESSAGE_DELETED', messageId: req.params.id });
    res.json({ message: 'Deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/messages/:id/react
app.post('/api/messages/:id/react', authMiddleware, async (req, res) => {
  try {
    const { emoji } = req.body;
    if (!emoji) return res.status(400).json({ error: 'emoji required' });
    await db(
      'INSERT INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE emoji = ?',
      [req.params.id, req.user.id, emoji, emoji]
    );
    const reactions = await db('SELECT emoji, user_id FROM message_reactions WHERE message_id = ?', [req.params.id]);
    const counts = {};
    reactions.forEach(r => { counts[r.emoji] = (counts[r.emoji]||0)+1; });
    const parsed = Object.entries(counts).map(([emoji, count]) => ({ emoji, count }));
    broadcast({ type: 'REACTION_UPDATE', messageId: req.params.id, reactions: parsed });
    res.json(parsed);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/messages/:id/pin
app.post('/api/messages/:id/pin', authMiddleware, async (req, res) => {
  try {
    const { conversation_id, group_id } = req.body;
    if (conversation_id) await db('DELETE FROM pinned_messages WHERE conversation_id = ?', [conversation_id]);
    if (group_id)        await db('DELETE FROM pinned_messages WHERE group_id = ?', [group_id]);
    await db(
      'INSERT INTO pinned_messages (conversation_id, group_id, message_id, pinned_by) VALUES (?, ?, ?, ?)',
      [conversation_id||null, group_id||null, req.params.id, req.user.id]
    );
    const [msg] = await db('SELECT content FROM messages WHERE id = ?', [req.params.id]);
    broadcast({ type: 'MESSAGE_PINNED', messageId: req.params.id, content: msg?.content, conversation_id, group_id });
    res.json({ message: 'Pinned' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/messages/:id/pin
app.delete('/api/messages/:id/pin', authMiddleware, async (req, res) => {
  await db('DELETE FROM pinned_messages WHERE message_id = ?', [req.params.id]);
  res.json({ message: 'Unpinned' });
});

// GET /api/messages/:convId/pinned
app.get('/api/messages/:convId/pinned', authMiddleware, async (req, res) => {
  try {
    const { convId } = req.params;
    const isGroup = await isGroupId(convId);
    let pins;
    if (isGroup) {
      pins = await db(`SELECT pm.*, m.content, m.type, u.name AS from_name
        FROM pinned_messages pm JOIN messages m ON m.id = pm.message_id JOIN users u ON u.id = m.from_user_id
        WHERE pm.group_id = ? ORDER BY pm.pinned_at DESC LIMIT 1`, [convId]);
    } else {
      pins = await db(`SELECT pm.*, m.content, m.type, u.name AS from_name
        FROM pinned_messages pm JOIN messages m ON m.id = pm.message_id JOIN users u ON u.id = m.from_user_id
        WHERE pm.conversation_id = ? ORDER BY pm.pinned_at DESC LIMIT 1`, [convId]);
    }
    res.json(pins[0] || null);
  } catch (e) {
    res.json(null);
  }
});

// POST /api/upload — file/image upload
app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file provided' });
    const { conversation_id, group_id, reply_to_id } = req.body;
    const isImage = req.file.mimetype.startsWith('image/');
    const isVoice = req.file.mimetype.startsWith('audio/');
    const msgType = isImage ? 'image' : isVoice ? 'voice' : 'file';
    const msgId   = uuidv4();
    const exp     = expiresAt();

    await db(
      'INSERT INTO messages (id, conversation_id, group_id, from_user_id, type, reply_to_id, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [msgId, conversation_id||null, group_id||null, req.user.id, msgType, reply_to_id||null, exp]
    );
    const attId = uuidv4();
    await db(
      'INSERT INTO message_attachments (id, message_id, file_name, file_type, file_size, file_path) VALUES (?, ?, ?, ?, ?, ?)',
      [attId, msgId, req.file.originalname, req.file.mimetype, req.file.size, req.file.filename]
    );
    if (conversation_id) await db('UPDATE conversations SET updated_at = NOW() WHERE id = ?', [conversation_id]);

    const [msg] = await db(
      'SELECT m.*, u.name AS from_name, u.avatar AS from_avatar FROM messages m JOIN users u ON u.id = m.from_user_id WHERE m.id = ?',
      [msgId]
    );
    const att = { id: attId, file_name: req.file.originalname, file_type: req.file.mimetype, file_size: req.file.size, file_path: req.file.filename };
    const fullMsg = { ...msg, reactions: [], attachments: [att] };

    const payload = { type: 'NEW_MESSAGE', message: fullMsg };
    if (group_id) broadcastToGroup(group_id, payload, req.user.id);
    else          broadcastToConversation(conversation_id, payload);

    res.json(fullMsg);
  } catch (e) {
    console.error('Upload error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/uploads/:filename', authMiddleware, (req, res) => {
  res.sendFile(path.join(UPLOADS_DIR, req.params.filename));
});

// ═══════════════════════════════════════════════════════════════════
//  GROUPS
// ═══════════════════════════════════════════════════════════════════

app.get('/api/groups', authMiddleware, async (req, res) => {
  try {
    const uid = req.user.id;
    const groups = await db(`
      SELECT g.id, g.name, g.description, g.avatar, g.admin_id, g.created_at,
        COUNT(DISTINCT gm2.user_id) AS member_count,
        (SELECT content    FROM messages WHERE group_id = g.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message,
        (SELECT type       FROM messages WHERE group_id = g.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message_type,
        (SELECT created_at FROM messages WHERE group_id = g.id AND is_deleted = 0 AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1) AS last_message_at,
        (SELECT COUNT(*) FROM messages WHERE group_id = g.id AND from_user_id != ? AND is_deleted = 0 AND expires_at > NOW()
          AND id NOT IN (SELECT message_id FROM message_reads WHERE user_id = ?)) AS unread_count
      FROM \`groups\` g
      JOIN group_members gm  ON gm.group_id  = g.id AND gm.user_id = ?
      LEFT JOIN group_members gm2 ON gm2.group_id = g.id
      GROUP BY g.id
      ORDER BY COALESCE(last_message_at, g.created_at) DESC`,
      [uid, uid, uid]
    );
    res.json(groups);
  } catch (e) {
    console.error('Groups error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/groups/:id/members', authMiddleware, async (req, res) => {
  try {
    const members = await db(`
      SELECT u.id, u.name, u.email, u.role, u.avatar, u.status,
        IF(g.admin_id = u.id, 1, 0) AS is_group_admin
      FROM group_members gm
      JOIN users u ON u.id = gm.user_id
      JOIN \`groups\` g ON g.id = gm.group_id
      WHERE gm.group_id = ?`, [req.params.id]);
    res.json(members);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/groups', authMiddleware, async (req, res) => {
  try {
    const { name, description, avatar, member_ids } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const gid = uuidv4();
    await db('INSERT INTO `groups` (id, name, description, avatar, admin_id) VALUES (?, ?, ?, ?, ?)',
      [gid, name.trim(), description||'', avatar||'👥', req.user.id]);
    const members = [...new Set([req.user.id, ...(member_ids||[])])];
    for (const uid of members) {
      await db('INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [gid, uid]);
    }
    const [group] = await db('SELECT * FROM `groups` WHERE id = ?', [gid]);
    res.json(group);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/groups/:id/members', authMiddleware, async (req, res) => {
  try {
    const { user_id } = req.body;
    const [g] = await db('SELECT admin_id FROM `groups` WHERE id = ?', [req.params.id]);
    if (!g) return res.status(404).json({ error: 'Group not found' });
    if (g.admin_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Only group admin can add members' });
    await db('INSERT IGNORE INTO group_members (group_id, user_id) VALUES (?, ?)', [req.params.id, user_id]);
    res.json({ message: 'Member added' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/groups/:id/members/:userId', authMiddleware, async (req, res) => {
  try {
    const targetId = req.params.userId;
    if (targetId !== req.user.id) {
      const [g] = await db('SELECT admin_id FROM `groups` WHERE id = ?', [req.params.id]);
      if (g?.admin_id !== req.user.id && !req.user.is_admin) return res.status(403).json({ error: 'Forbidden' });
    }
    await db('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [req.params.id, targetId]);
    res.json({ message: 'Removed' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════
//  SEARCH
// ═══════════════════════════════════════════════════════════════════

app.get('/api/search', authMiddleware, async (req, res) => {
  try {
    const q = `%${req.query.q||''}%`;
    const uid = req.user.id;
    const users = await db(
      'SELECT id, name, email, role, avatar, status FROM users WHERE is_admin = 0 AND (name LIKE ? OR email LIKE ? OR role LIKE ?) LIMIT 10',
      [q, q, q]
    );
    const messages = await db(`
      SELECT m.id, m.content, m.type, m.created_at, m.conversation_id, m.group_id,
        u.name AS from_name, u.avatar AS from_avatar
      FROM messages m JOIN users u ON u.id = m.from_user_id
      WHERE m.content LIKE ? AND m.is_deleted = 0 AND m.expires_at > NOW()
        AND (m.conversation_id IN (SELECT id FROM conversations WHERE user_a_id = ? OR user_b_id = ?)
          OR m.group_id IN (SELECT group_id FROM group_members WHERE user_id = ?))
      ORDER BY m.created_at DESC LIMIT 20`,
      [q, uid, uid, uid]
    );
    res.json({ users, messages });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ═══════════════════════════════════════════════════════════════════
//  NOTIFICATIONS
// ═══════════════════════════════════════════════════════════════════

app.get('/api/notifications', authMiddleware, async (req, res) => {
  const notifs = await db(
    'SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', [req.user.id]
  );
  res.json(notifs);
});

app.patch('/api/notifications/read-all', authMiddleware, async (req, res) => {
  await db('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [req.user.id]);
  res.json({ message: 'All read' });
});

// ═══════════════════════════════════════════════════════════════════
//  ADMIN ROUTES (super admin only)
// ═══════════════════════════════════════════════════════════════════

app.get('/api/admin/stats', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const [[tu]] = await pool.execute('SELECT COUNT(*) AS v FROM users WHERE is_admin = 0');
    const [[tm]] = await pool.execute('SELECT COUNT(*) AS v FROM messages WHERE is_deleted = 0');
    const [[tg]] = await pool.execute('SELECT COUNT(*) AS v FROM `groups`');
    const [[tf]] = await pool.execute('SELECT COUNT(*) AS v FROM message_attachments');
    const [[ou]] = await pool.execute("SELECT COUNT(*) AS v FROM users WHERE status = 'online' AND is_admin = 0");
    res.json({ total_users: tu.v, total_messages: tm.v, total_groups: tg.v, total_files: tf.v, online_users: ou.v });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const users = await db('SELECT id, name, email, role, avatar, status, is_admin, last_seen, created_at FROM users ORDER BY created_at DESC');
  res.json(users);
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    await db('DELETE FROM users WHERE id = ?', [req.params.id]);
    await db('INSERT INTO admin_logs (admin_id, action, target_type, target_id) VALUES (?, ?, ?, ?)',
      [req.user.id, 'DELETE_USER', 'user', req.params.id]);
    res.json({ message: 'User deleted' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/messages', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const msgs = await db(`
      SELECT m.id, m.conversation_id, m.group_id, m.from_user_id, m.type, m.content,
        m.created_at, m.is_deleted, m.expires_at, u.name AS from_name, u.avatar AS from_avatar
      FROM messages m JOIN users u ON u.id = m.from_user_id
      ORDER BY m.created_at DESC LIMIT 200`);
    res.json(msgs);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/admin/settings', authMiddleware, adminMiddleware, async (req, res) => {
  const settings = await db('SELECT * FROM app_settings');
  res.json(settings);
});

app.patch('/api/admin/settings/:key', authMiddleware, adminMiddleware, async (req, res) => {
  const { value } = req.body;
  await db('UPDATE app_settings SET value = ? WHERE setting_key = ?', [value, req.params.key]);
  res.json({ message: 'Updated' });
});

// ═══════════════════════════════════════════════════════════════════
//  WEBSOCKET SERVER
// ═══════════════════════════════════════════════════════════════════

const server = http.createServer(app);
const wss    = new WebSocket.Server({ server, path: '/ws' });

// Map: userId → Set of WebSocket connections
const clients = new Map();

wss.on('connection', (ws) => {
  let userId = null;

  ws.on('message', async (raw) => {
    let data;
    try { data = JSON.parse(raw); } catch { return; }

    if (data.type === 'AUTH') {
      try {
        const user = jwt.verify(data.token, JWT_SECRET);
        userId = user.id;
        if (!clients.has(userId)) clients.set(userId, new Set());
        clients.get(userId).add(ws);
        await db("UPDATE users SET status = 'online' WHERE id = ?", [userId]).catch(() => {});
        broadcast({ type: 'USER_STATUS', userId, status: 'online' }, ws);
        ws.send(JSON.stringify({ type: 'AUTH_OK', userId }));
      } catch {
        ws.send(JSON.stringify({ type: 'AUTH_FAIL' }));
      }
      return;
    }

    if (!userId) return;

    if (data.type === 'TYPING') {
      const { conversation_id, group_id, isTyping } = data;
      const payload = { type: 'TYPING', userId, conversation_id, group_id, isTyping };
      if (group_id) broadcastToGroup(group_id, payload, userId);
      else if (conversation_id) broadcastToConversation(conversation_id, payload, userId);
    }

    if (data.type === 'READ') {
      for (const mid of (data.message_ids||[])) {
        await db('INSERT IGNORE INTO message_reads (message_id, user_id) VALUES (?, ?)', [mid, userId]).catch(() => {});
      }
    }
  });

  ws.on('close', async () => {
    if (userId) {
      clients.get(userId)?.delete(ws);
      if (!clients.get(userId)?.size) {
        clients.delete(userId);
        await db("UPDATE users SET status = 'offline', last_seen = NOW() WHERE id = ?", [userId]).catch(() => {});
        broadcast({ type: 'USER_STATUS', userId, status: 'offline' });
      }
    }
  });

  ws.on('error', () => { try { ws.terminate(); } catch {} });
});

function broadcast(payload, excludeWs = null) {
  const msg = JSON.stringify(payload);
  wss.clients.forEach(client => {
    if (client !== excludeWs && client.readyState === WebSocket.OPEN) {
      try { client.send(msg); } catch {}
    }
  });
}

async function broadcastToGroup(groupId, payload, excludeUserId = null) {
  const members = await db('SELECT user_id FROM group_members WHERE group_id = ?', [groupId]).catch(() => []);
  const msg = JSON.stringify(payload);
  members.forEach(({ user_id }) => {
    if (user_id === excludeUserId) return;
    clients.get(user_id)?.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) try { ws.send(msg); } catch {}
    });
  });
}

async function broadcastToConversation(convId, payload, excludeUserId = null) {
  const [conv] = await db('SELECT user_a_id, user_b_id FROM conversations WHERE id = ?', [convId]).catch(() => []);
  if (!conv) return;
  const msg = JSON.stringify(payload);
  [conv.user_a_id, conv.user_b_id].forEach(uid => {
    if (uid === excludeUserId) return;
    clients.get(uid)?.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) try { ws.send(msg); } catch {}
    });
  });
}

// ═══════════════════════════════════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════════════════════════════════

async function isGroupId(id) {
  try {
    const rows = await db('SELECT id FROM `groups` WHERE id = ?', [id]);
    return rows.length > 0;
  } catch { return false; }
}

// Scheduled cleanup: purge expired messages every hour
setInterval(async () => {
  try {
    await db('DELETE FROM messages WHERE expires_at <= NOW()');
    await db('DELETE FROM sessions WHERE expires_at <= NOW()');
    await db('DELETE FROM typing_status WHERE updated_at < DATE_SUB(NOW(), INTERVAL 30 SECOND)');
  } catch (e) {
    console.error('Cleanup error:', e.message);
  }
}, 60 * 60 * 1000); // every hour

// ── START ──────────────────────────────────────────────────────────
server.listen(PORT, () => {
  console.log(`\n⚡ LETI Chat Server running → http://localhost:${PORT}`);
  console.log(`   WebSocket  → ws://localhost:${PORT}/ws`);
  console.log(`   Database   → ${process.env.DB_NAME} @ ${process.env.DB_HOST}`);
  console.log(`   Admin URL  → http://localhost:${PORT}/#/admin-register\n`);
});

process.on('unhandledRejection', err => console.error('Unhandled:', err?.message || err));
process.on('uncaughtException',  err => console.error('Uncaught:',  err?.message || err));
