const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const app = express();
const JWT_SECRET = 'driveready-secret-key-change-in-production';
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'driveready.json');

// ─── JSON store ────────────────────────────────────────────────────────────────
function loadDb() {
  if (!fs.existsSync(DB_PATH)) return { users: [], progress: {}, quizResults: [] };
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function saveDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.replace('Bearer ', '');
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ─── Auth routes ───────────────────────────────────────────────────────────────
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const db = loadDb();
  if (db.users.find(u => u.username === username)) {
    return res.status(400).json({ error: 'Username already taken' });
  }

  const hash = await bcrypt.hash(password, 10);
  const id = Date.now();
  db.users.push({ id, username, password: hash, createdAt: new Date().toISOString() });
  db.progress[id] = [];
  saveDb(db);

  const token = jwt.sign({ id, username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const db = loadDb();
  const user = db.users.find(u => u.username === username);
  if (!user) return res.status(400).json({ error: 'Invalid username or password' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).json({ error: 'Invalid username or password' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, username: user.username });
});

// ─── Progress routes ───────────────────────────────────────────────────────────
app.get('/api/progress', auth, (req, res) => {
  const db = loadDb();
  res.json({ completed: db.progress[req.user.id] || [] });
});

app.put('/api/progress', auth, (req, res) => {
  const { completed } = req.body;
  const db = loadDb();
  db.progress[req.user.id] = completed;
  saveDb(db);
  res.json({ ok: true });
});

// ─── Quiz result routes ────────────────────────────────────────────────────────
app.post('/api/quiz-result', auth, (req, res) => {
  const { lessonIndex, lessonTitle, score, total } = req.body;
  const db = loadDb();
  db.quizResults.push({ userId: req.user.id, lessonIndex, lessonTitle, score, total, takenAt: new Date().toISOString() });
  saveDb(db);
  res.json({ ok: true });
});

app.get('/api/quiz-results', auth, (req, res) => {
  const db = loadDb();
  const results = db.quizResults.filter(r => r.userId === req.user.id).reverse();
  res.json({ results });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.user.username });
});

app.listen(PORT, () => console.log(`DriveReady server running at http://localhost:${PORT}`));
