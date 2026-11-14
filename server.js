require('dotenv').config();
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');

const { MONGODB_URI, JWT_SECRET, GOOGLE_CLIENT_ID, PORT = 3000 } = process.env;
// Admins: comma-separated emails in ADMIN_EMAILS. Leave empty to turn the admin panel off.
const ADMINS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean);
const isAdmin = u => !!u && ADMINS.includes(u.email);
if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Missing MONGODB_URI or JWT_SECRET. Copy .env.example to .env and fill it in.');
  process.exit(1);
}
// Google sign-in is optional: without a client id the button is simply hidden
const gClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// progress is stored as a JSON string: chapter names contain spaces/punctuation, which makes poor Mongo field names
const User = mongoose.model('User', new mongoose.Schema({
  name:     { type: String, required: true, trim: true, maxlength: 60 },
  email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
  // Google-only accounts have no password; everyone else must have one
  password: { type: String, required: function () { return !this.googleId; } },
  googleId: { type: String, index: { unique: true, sparse: true } },
  picture:  { type: String, default: '' },
  school:   { type: String, default: '', trim: true, maxlength: 80 },
  target:   { type: Number, default: null, min: 0, max: 100 },
  subjects: { type: [String], default: [] },
  progress: { type: String, default: '{}' },
  exam:     { type: String, default: '' }
}, { timestamps: true }));

const app = express();
app.use(express.json({ limit: '200kb' }));
app.set('trust proxy', 1); // Render/Vercel sit behind a proxy; needed so rate limits see each visitor's real IP

// Connect lazily and reuse the connection. Works for a normal server and for serverless (Vercel).
let dbReady = null;
const connectDb = () => dbReady || (dbReady = mongoose.connect(MONGODB_URI).catch(e => { dbReady = null; throw e; }));
app.use('/api', async (req, res, next) => {
  try { await connectDb(); next(); }
  catch (e) { console.error('MongoDB connection failed:', e.message); res.status(503).json({ error: 'Database unavailable. Please try again.' }); }
});

const sign = u => jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '60d' });
const SUBJECT_IDS = ['hindi', 'english', 'maths', 'science', 'it', 'sst'];
const view = u => ({ isAdmin: isAdmin(u), subjects: u.subjects || [], name: u.name, email: u.email, picture: u.picture || '', school: u.school || '', target: u.target ?? null, hasPassword: !!u.password, hasGoogle: !!u.googleId });
const prog = u => ({ done: JSON.parse(u.progress || '{}'), exam: u.exam });

const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, message: { error: 'Too many attempts. Try again in a few minutes.' } });

const fail = (res, e) => {
  if (e.status) return res.status(e.status).json({ error: e.message });
  if (e.code === 11000) return res.status(409).json({ error: 'That account already exists. Please try again.' });
  console.error(e); res.status(500).json({ error: 'Server error. Please try again.' });
};

async function verifyGoogle(credential) {
  if (!gClient) { const e = new Error('Google sign-in is not set up on this server.'); e.status = 503; throw e; }
  try {
    const t = await gClient.verifyIdToken({ idToken: String(credential || ''), audience: GOOGLE_CLIENT_ID });
    const p = t.getPayload();
    if (!p || !p.sub || !p.email || !p.email_verified) throw new Error('unverified');
    return p;
  } catch { const e = new Error('Google sign-in failed. Please try again.'); e.status = 401; throw e; }
}
const safePicture = p => (typeof p === 'string' && p.startsWith('https://') && p.length < 500) ? p : '';

const auth = async (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const { id } = jwt.verify(t, JWT_SECRET);
    req.user = await User.findById(id);
    if (!req.user) throw new Error('no user');
    next();
  } catch { res.status(401).json({ error: 'Please log in again.' }); }
};

app.post('/api/signup', authLimit, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim(), email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
    if (!name) return res.status(400).json({ error: 'Please enter your name.' });
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Please enter a valid email.' });
    if (password.length < 6 || password.length > 100) return res.status(400).json({ error: 'Password must be 6 to 100 characters.' });
    const u = await User.create({ name: name.slice(0, 60), email, password: await bcrypt.hash(password, 10) });
    res.status(201).json({ token: sign(u), user: view(u), progress: prog(u) });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ error: 'That email already has an account. Try logging in.' });
    console.error(e); res.status(500).json({ error: 'Server error. Please try again.' });
  }
});

app.post('/api/login', authLimit, async (req, res) => {
  try {
    const u = await User.findOne({ email: String(req.body.email || '').trim().toLowerCase() });
    if (u && !u.password) return res.status(401).json({ error: 'This account uses Google sign-in. Please use the Google button.' });
    if (!u || !(await bcrypt.compare(String(req.body.password || ''), u.password))) return res.status(401).json({ error: 'Wrong email or password.' });
    res.json({ token: sign(u), user: view(u), progress: prog(u) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});

app.get('/api/config', (req, res) => res.json({ googleClientId: GOOGLE_CLIENT_ID || null }));

// Sign in / sign up with Google (ID token from Google Identity Services, verified server-side)
app.post('/api/auth/google', authLimit, async (req, res) => {
  try {
    const p = await verifyGoogle(req.body.credential);
    const email = p.email.toLowerCase();
    let u = await User.findOne({ googleId: p.sub });
    let passwordReset = false;
    if (!u) {
      u = await User.findOne({ email });
      if (u) {
        if (u.googleId && u.googleId !== p.sub) return res.status(409).json({ error: 'That email is linked to a different Google account.' });
        // Email/password signup is not email-verified, so someone else could have registered this address.
        // Google has verified the owner, so we link and drop the old password to lock out any squatter.
        if (u.password) { u.password = undefined; passwordReset = true; }
        u.googleId = p.sub;
      } else {
        u = new User({ name: String(p.name || email.split('@')[0]).trim().slice(0, 60) || 'Student', email, googleId: p.sub });
      }
    }
    const pic = safePicture(p.picture); if (pic) u.picture = pic;
    await u.save();
    res.json({ token: sign(u), user: view(u), progress: prog(u), passwordReset });
  } catch (e) { fail(res, e); }
});

// ---- profile management (all require login)
app.put('/api/profile', auth, async (req, res) => {
  try {
    const name = String(req.body.name ?? '').trim();
    if (!name) return res.status(400).json({ error: 'Please enter your name.' });
    const school = String(req.body.school ?? '').trim().slice(0, 80);
    let target = req.body.target;
    if (target === '' || target == null) target = null;
    else {
      target = Number(target);
      if (!Number.isInteger(target) || target < 0 || target > 100) return res.status(400).json({ error: 'Target must be a whole number from 0 to 100.' });
    }
    // subjects: list of subject ids the student studies; empty = all six
    // only touched when the client actually sends it, so an old cached page can never blank a saved choice
    Object.assign(req.user, { name: name.slice(0, 60), school, target });
    if (Array.isArray(req.body.subjects)) req.user.subjects = [...new Set(req.body.subjects.map(String).filter(s => SUBJECT_IDS.includes(s)))];
    await req.user.save();
    res.json({ user: view(req.user) });
  } catch (e) { fail(res, e); }
});

app.put('/api/password', auth, authLimit, async (req, res) => {
  try {
    const next = String(req.body.next || '');
    if (next.length < 6 || next.length > 100) return res.status(400).json({ error: 'New password must be 6 to 100 characters.' });
    if (req.user.password && !(await bcrypt.compare(String(req.body.current || ''), req.user.password))) return res.status(401).json({ error: 'Current password is wrong.' });
    req.user.password = await bcrypt.hash(next, 10);
    await req.user.save();
    res.json({ user: view(req.user) });
  } catch (e) { fail(res, e); }
});

app.post('/api/profile/google', auth, authLimit, async (req, res) => {
  try {
    const p = await verifyGoogle(req.body.credential);
    const other = await User.findOne({ googleId: p.sub });
    if (other && other.id !== req.user.id) return res.status(409).json({ error: 'That Google account is already linked to another BoardReady account.' });
    req.user.googleId = p.sub;
    const pic = safePicture(p.picture); if (pic) req.user.picture = pic;
    await req.user.save();
    res.json({ user: view(req.user) });
  } catch (e) { fail(res, e); }
});

app.delete('/api/profile/google', auth, async (req, res) => {
  try {
    if (!req.user.password) return res.status(400).json({ error: 'Set a password first, so you can still log in.' });
    req.user.googleId = undefined;
    await req.user.save();
    res.json({ user: view(req.user) });
  } catch (e) { fail(res, e); }
});

app.delete('/api/account', auth, authLimit, async (req, res) => {
  try {
    if (req.user.password && !(await bcrypt.compare(String(req.body.password || ''), req.user.password))) return res.status(401).json({ error: 'Password is wrong.' });
    await User.deleteOne({ _id: req.user._id });
    res.json({ ok: true });
  } catch (e) { fail(res, e); }
});

app.get('/api/me', auth, (req, res) => res.json({ user: view(req.user), progress: prog(req.user) }));

app.put('/api/progress', auth, async (req, res) => {
  try {
    const { done, exam } = req.body;
    if (!done || typeof done !== 'object' || Array.isArray(done)) return res.status(400).json({ error: 'Invalid progress.' });
    const keys = Object.keys(done);
    const ok = keys.length <= 600 && keys.every(k => k.length <= 200 && Array.isArray(done[k]) && done[k].length === 3 && done[k].every(v => v === 0 || v === 1));
    if (!ok) return res.status(400).json({ error: 'Invalid progress.' });
    if (exam && !/^\d{4}-\d{2}-\d{2}$/.test(exam)) return res.status(400).json({ error: 'Invalid exam date.' });
    req.user.progress = JSON.stringify(done);
    req.user.exam = exam || '';
    await req.user.save();
    res.json({ ok: true, savedAt: req.user.updatedAt });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error. Please try again.' }); }
});


// ---- admin panel (only emails listed in ADMIN_EMAILS). Never returns passwords or full progress.
const adminOnly = (req, res, next) => isAdmin(req.user) ? next() : res.status(403).json({ error: 'Admins only.' });
const tickCount = str => { try { return Object.values(JSON.parse(str || '{}')).reduce((a, v) => a + (Array.isArray(v) ? v.filter(Boolean).length : 0), 0); } catch { return 0; } };

app.get('/api/admin/stats', auth, adminOnly, async (req, res) => {
  try {
    const day = 864e5, now = Date.now(), d7 = new Date(now - 7 * day), d14 = new Date(now - 14 * day), d30 = new Date(now - 30 * day);
    const [total, new7, new30, active7, google, signups, subj] = await Promise.all([
      User.countDocuments(), User.countDocuments({ createdAt: { $gte: d7 } }), User.countDocuments({ createdAt: { $gte: d30 } }),
      User.countDocuments({ updatedAt: { $gte: d7 } }), User.countDocuments({ googleId: { $exists: true, $ne: null } }),
      User.aggregate([{ $match: { createdAt: { $gte: d14 } } }, { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, n: { $sum: 1 } } }]),
      User.aggregate([{ $unwind: '$subjects' }, { $group: { _id: '$subjects', n: { $sum: 1 } } }])
    ]);
    let withProgress = 0, ticks = 0;
    for await (const u of User.find({}).select('progress').lean().cursor()) { const t = tickCount(u.progress); if (t) { withProgress++; ticks += t; } }
    const noSubjects = await User.countDocuments({ $or: [{ subjects: { $size: 0 } }, { subjects: { $exists: false } }] });
    res.json({ total, new7, new30, active7, google, withProgress, avgTicks: withProgress ? Math.round(ticks / withProgress) : 0,
      signups: signups.map(x => ({ day: x._id, n: x.n })), subjects: Object.fromEntries(subj.map(x => [x._id, x.n])), noSubjects });
  } catch (e) { fail(res, e); }
});

app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1), per = 25, q = String(req.query.q || '').trim().slice(0, 60);
    const rx = q ? new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i') : null;
    const filter = rx ? { $or: [{ name: rx }, { email: rx }, { school: rx }] } : {};
    const [count, list] = await Promise.all([User.countDocuments(filter), User.find(filter).sort({ createdAt: -1 }).skip((page - 1) * per).limit(per).select('name email school subjects googleId progress createdAt updatedAt').lean()]);
    res.json({ page, pages: Math.max(1, Math.ceil(count / per)), count,
      users: list.map(u => ({ id: String(u._id), name: u.name, email: u.email, school: u.school || '', subjects: u.subjects || [], google: !!u.googleId, ticks: tickCount(u.progress), joined: u.createdAt, lastActive: u.updatedAt })) });
  } catch (e) { fail(res, e); }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ error: 'Bad user id.' });
    if (String(req.user._id) === req.params.id) return res.status(400).json({ error: 'Use Account > Delete my account for your own account.' });
    await User.findByIdAndDelete(req.params.id);
    res.json({ ok: true });
  } catch (e) { fail(res, e); }
});

app.use(express.static(path.join(__dirname, 'public')));

module.exports = app;

// Run as a normal server (local, Render). On Vercel the app is imported by api/index.js instead.
if (require.main === module) {
  connectDb()
    .then(() => app.listen(PORT, () => console.log(`BoardReady running at http://localhost:${PORT}`)))
    .catch(e => { console.error('MongoDB connection failed:', e.message); process.exit(1); });
}
