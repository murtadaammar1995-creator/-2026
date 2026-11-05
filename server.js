const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : undefined });
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"] } } }));
app.use(express.json({ limit: '7mb' }));
app.use(cookieParser());
app.use(express.static('public'));
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });
const submitLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 15, standardHeaders: true, legacyHeaders: false });

async function initDb() {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not configured');
  await pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id BIGSERIAL PRIMARY KEY,
      tracking_code VARCHAR(32) UNIQUE NOT NULL,
      department VARCHAR(160) NOT NULL,
      form_type VARCHAR(160) NOT NULL,
      full_name VARCHAR(180) NOT NULL,
      phone VARCHAR(32) NOT NULL,
      address TEXT NOT NULL,
      details TEXT NOT NULL,
      appointment_date DATE,
      declaration_name VARCHAR(180) NOT NULL,
      consent BOOLEAN NOT NULL DEFAULT FALSE,
      status VARCHAR(30) NOT NULL DEFAULT 'جديد',
      employee_note TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS attachments (
      id BIGSERIAL PRIMARY KEY,
      submission_id BIGINT NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
      file_name VARCHAR(255) NOT NULL,
      mime_type VARCHAR(120) NOT NULL,
      data BYTEA NOT NULL
    );
  `);
}

function auth(req, res, next) {
  try {
    const token = req.cookies.staff_token;
    if (!token || !JWT_SECRET) return res.status(401).json({ error: 'يرجى تسجيل دخول الموظف' });
    req.staff = jwt.verify(token, JWT_SECRET);
    next();
  } catch { res.status(401).json({ error: 'انتهت الجلسة، يرجى تسجيل الدخول مجدداً' }); }
}
function trackingCode() {
  return 'CIT-' + new Date().getFullYear() + '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
}
function clean(v, max = 5000) { return String(v || '').trim().slice(0, max); }

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});

app.post('/api/submit', submitLimiter, async (req, res) => {
  const { department, formType, fullName, phone, address, details, appointmentDate, declarationName, consent, attachment } = req.body || {};
  if (![department, formType, fullName, phone, address, details, declarationName].every(v => clean(v)) || consent !== true) {
    return res.status(400).json({ error: 'يرجى إكمال الحقول المطلوبة والموافقة على التعهد' });
  }
  if (attachment && (!attachment.data || !/^application\/(pdf)$|^image\/(jpeg|png)$/.test(attachment.mimeType) || attachment.data.length > 5_500_000)) {
    return res.status(400).json({ error: 'المرفق يجب أن يكون PDF أو صورة JPG/PNG وبحجم لا يتجاوز 4MB' });
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const code = trackingCode();
    const result = await client.query(
      `INSERT INTO submissions (tracking_code, department, form_type, full_name, phone, address, details, appointment_date, declaration_name, consent)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id, tracking_code, created_at`,
      [code, clean(department,160), clean(formType,160), clean(fullName,180), clean(phone,32), clean(address,1000), clean(details), appointmentDate || null, clean(declarationName,180), true]
    );
    if (attachment) {
      const raw = Buffer.from(attachment.data, 'base64');
      if (raw.length > 4 * 1024 * 1024) throw new Error('attachment too large');
      await client.query('INSERT INTO attachments (submission_id,file_name,mime_type,data) VALUES ($1,$2,$3,$4)', [result.rows[0].id, clean(attachment.fileName,255), attachment.mimeType, raw]);
    }
    await client.query('COMMIT');
    res.status(201).json({ message: 'تم استلام طلبك بنجاح', trackingCode: code, createdAt: result.rows[0].created_at });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'تعذر حفظ الطلب حالياً، يرجى المحاولة لاحقاً' });
  } finally { client.release(); }
});

app.get('/api/track/:code', async (req, res) => {
  const code = clean(req.params.code, 32).toUpperCase();
  try {
    const r = await pool.query('SELECT tracking_code, department, form_type, status, created_at, employee_note FROM submissions WHERE tracking_code=$1', [code]);
    if (!r.rowCount) return res.status(404).json({ error: 'لم يتم العثور على معاملة بهذا الرقم' });
    const x = r.rows[0];
    res.json({ trackingCode: x.tracking_code, department: x.department, formType: x.form_type, status: x.status, createdAt: x.created_at, note: x.employee_note });
  } catch { res.status(500).json({ error: 'تعذر الاستعلام حالياً' }); }
});

app.post('/api/staff/login', loginLimiter, (req, res) => {
  if (!ADMIN_USER || !ADMIN_PASSWORD || !JWT_SECRET) return res.status(503).json({ error: 'لم يتم إعداد حساب الموظف في إعدادات الاستضافة' });
  const username = clean(req.body?.username, 100);
  const password = String(req.body?.password || '');
  const a = Buffer.from(username), b = Buffer.from(ADMIN_USER);
  const c = Buffer.from(password), d = Buffer.from(ADMIN_PASSWORD);
  const userOk = a.length === b.length && crypto.timingSafeEqual(a,b);
  const passOk = c.length === d.length && crypto.timingSafeEqual(c,d);
  if (!userOk || !passOk) return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
  const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '8h' });
  res.cookie('staff_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8*60*60*1000 });
  res.json({ message: 'تم تسجيل الدخول' });
});
app.post('/api/staff/logout', (_req,res) => { res.clearCookie('staff_token'); res.json({ message: 'تم تسجيل الخروج' }); });
app.get('/api/staff/me', auth, (req,res) => res.json({ username: req.staff.username, role: req.staff.role }));
app.get('/api/staff/submissions', auth, async (req,res) => {
  try {
    const r = await pool.query('SELECT id, tracking_code, department, form_type, full_name, phone, address, details, appointment_date, status, employee_note, created_at, EXISTS(SELECT 1 FROM attachments a WHERE a.submission_id=s.id) AS has_attachment FROM submissions s ORDER BY created_at DESC LIMIT 300');
    res.json(r.rows);
  } catch { res.status(500).json({ error: 'تعذر تحميل الطلبات' }); }
});
app.patch('/api/staff/submissions/:id', auth, async (req,res) => {
  const status = clean(req.body?.status,30);
  const note = clean(req.body?.note,2000);
  if (!['جديد','قيد التدقيق','مكتمل','مرفوض'].includes(status)) return res.status(400).json({ error: 'حالة غير صحيحة' });
  try {
    const r = await pool.query('UPDATE submissions SET status=$1, employee_note=$2 WHERE id=$3 RETURNING tracking_code,status', [status,note,req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'الطلب غير موجود' });
    res.json(r.rows[0]);
  } catch { res.status(500).json({ error: 'تعذر تحديث الطلب' }); }
});
app.get('/api/staff/attachments/:id', auth, async (req,res) => {
  try {
    const r = await pool.query('SELECT file_name,mime_type,data FROM attachments WHERE submission_id=$1 LIMIT 1', [req.params.id]);
    if (!r.rowCount) return res.status(404).json({ error: 'لا يوجد مرفق' });
    res.setHeader('Content-Type', r.rows[0].mime_type);
    res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(r.rows[0].file_name)}`);
    res.send(r.rows[0].data);
  } catch { res.status(500).json({ error: 'تعذر تنزيل المرفق' }); }
});

app.get('*', (_req,res) => res.sendFile(require('path').join(__dirname,'public','index.html')));
initDb().then(() => app.listen(PORT, () => console.log('Citizen portal listening on ' + PORT))).catch(err => { console.error(err.message); process.exit(1); });