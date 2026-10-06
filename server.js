const express = require('express');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.set('trust proxy', 1);

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:local.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// ================= TIỆN ÍCH =================

const ALL_PERMS = ['submit', 'view_summary', 'view_duty'];
const GROUPS = ['CHỈ HUY', 'TỔ TỔNG HỢP', 'TỔ AN NINH', 'TỔ CSKV', 'TỔ PCTP', 'TỔ CSTT'];

// Chuẩn hoá tên tổ về đúng 6 giá trị chuẩn (tránh lệch "Tổ cảnh sát trật tự" / "TỔ CSTT"...)
function normalizeGroup(raw) {
  const s = String(raw || '').toUpperCase().trim();
  if (/CHỈ HUY|CHI HUY|LÃNH ĐẠO/.test(s)) return 'CHỈ HUY';
  if (/TỔNG HỢP|TONG HOP/.test(s)) return 'TỔ TỔNG HỢP';
  if (/AN NINH/.test(s)) return 'TỔ AN NINH';
  if (/CSKV|KHU VỰC|KHU VUC/.test(s)) return 'TỔ CSKV';
  if (/PCTP|TỘI PHẠM|TOI PHAM/.test(s)) return 'TỔ PCTP';
  if (/CSTT|TRẬT TỰ|TRAT TU/.test(s)) return 'TỔ CSTT';
  return null;
}

// Chuẩn hoá số điện thoại: bỏ khoảng trắng/dấu chấm, +84 -> 0, thêm số 0 đầu nếu bị mất
function cleanPhone(raw) {
  let s = String(raw == null ? '' : raw).trim().replace(/[^\d+]/g, '');
  if (!s) return '';
  if (/^\+?84\d{9}$/.test(s)) s = '0' + s.replace(/^\+?84/, '');
  else if (/^[35789]\d{8}$/.test(s)) s = '0' + s;
  return s.slice(0, 15);
}

function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `scrypt$${salt}$${crypto.scryptSync(pw, salt, 64).toString('hex')}`;
}
function checkPw(pw, stored) {
  stored = String(stored || '');
  if (stored.startsWith('scrypt$')) {
    const [, salt, h] = stored.split('$');
    const a = crypto.scryptSync(pw, salt, 64);
    const b = Buffer.from(h, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  return pw === stored; // mật khẩu cũ dạng thường (sẽ được nâng cấp sau khi đăng nhập)
}

// Ngày thứ 2 của tuần ISO
function isoWeekStart(year, week) {
  const jan4 = new Date(Date.UTC(year, 0, 4));
  const dow = (jan4.getUTCDay() + 6) % 7;
  const mon = new Date(jan4);
  mon.setUTCDate(jan4.getUTCDate() - dow + (week - 1) * 7);
  return mon;
}
function dateStr(year, week, dayIdx) {
  const d = isoWeekStart(year, week);
  d.setUTCDate(d.getUTCDate() + dayIdx);
  return `${d.getUTCDate()}/${d.getUTCMonth() + 1}`;
}

// Ghép tên nhập tay với danh sách cán bộ: chỉ tự khớp khi kết quả duy nhất, tránh gán nhầm người
function resolveName(input, all) {
  const q = input.trim().toLowerCase();
  if (!q) return '';
  const exact = all.filter(o => o.toLowerCase() === q);
  if (exact.length) return exact[0];
  const part = all.filter(o => o.toLowerCase().includes(q));
  if (part.length === 1) return part[0];
  const last = all.filter(o => o.split(' ').pop().toLowerCase() === q);
  if (last.length === 1) return last[0];
  return input.trim();
}

// Thông tin người dùng lưu trong phiên (dựng từ 1 dòng của bảng users)
function sessionUserFrom(u) {
  let perms = [];
  if (u.role === 'admin') perms = ['all'];
  else { try { perms = JSON.parse(u.permissions || '[]'); } catch (e) { perms = []; } }
  return {
    id: Number(u.id),
    username: u.username,
    role: u.role,
    group_name: normalizeGroup(u.group_name) || u.group_name || 'TỔ TỔNG HỢP',
    permissions: Array.isArray(perms) ? perms : []
  };
}

// Mỗi request /api đều đồng bộ lại vai trò + quyền từ CSDL, để khi admin đổi quyền thì tài khoản thành viên
// nhận quyền mới ngay (không phải đăng xuất/đăng nhập lại). Có cache ngắn để không truy vấn quá dày.
const userCache = new Map(); // id -> { t, user }
const USER_TTL = 4000;
async function refreshUser(req, res, next) {
  const su = req.session && req.session.user;
  if (!su) return next();
  try {
    const c = userCache.get(su.id);
    let fresh;
    if (c && Date.now() - c.t < USER_TTL) fresh = c.user;
    else {
      const r = await db.execute({ sql: 'SELECT id, username, role, group_name, permissions FROM users WHERE id = ?', args: [su.id] });
      if (!r.rows.length) {
        userCache.delete(su.id);
        return req.session.destroy(() => res.status(401).json({ error: 'Tài khoản không còn tồn tại, vui lòng đăng nhập lại' }));
      }
      fresh = sessionUserFrom(r.rows[0]);
      userCache.set(su.id, { t: Date.now(), user: fresh });
    }
    req.session.user = fresh;
  } catch (e) { console.error('Lỗi đồng bộ quyền:', e); }
  next();
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại' });
  next();
}
function requirePerm(...ps) {
  return (req, res, next) => {
    const u = req.session.user;
    if (!u) return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại' });
    if (u.role === 'admin' || ps.some(p => (u.permissions || []).includes(p))) return next();
    res.status(403).json({ error: 'Tài khoản chưa được cấp quyền này' });
  };
}
function requireAdmin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại' });
  if (req.session.user.role !== 'admin') return res.status(403).json({ error: 'Không có quyền truy cập' });
  next();
}

// ================= LƯU PHIÊN ĐĂNG NHẬP TRÊN TURSO (không mất khi server khởi động lại) =================

class TursoStore extends session.Store {
  get(sid, cb) {
    db.execute({ sql: 'SELECT data, expires FROM sessions WHERE sid = ?', args: [sid] })
      .then(r => {
        const row = r.rows[0];
        if (!row || Number(row.expires) < Date.now()) return cb(null, null);
        cb(null, JSON.parse(row.data));
      }).catch(cb);
  }
  set(sid, sess, cb) {
    const exp = sess.cookie && sess.cookie.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 12 * 3600 * 1000;
    db.execute({
      sql: `INSERT INTO sessions (sid, data, expires) VALUES (?, ?, ?)
            ON CONFLICT(sid) DO UPDATE SET data = excluded.data, expires = excluded.expires`,
      args: [sid, JSON.stringify(sess), exp]
    }).then(() => cb && cb(null)).catch(e => cb && cb(e));
  }
  destroy(sid, cb) {
    db.execute({ sql: 'DELETE FROM sessions WHERE sid = ?', args: [sid] })
      .then(() => cb && cb(null)).catch(e => cb && cb(e));
  }
}

// ================= KHỞI TẠO CSDL =================

async function initDB() {
  await db.execute(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, group_name TEXT, permissions TEXT)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS officers (
    id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT, gender TEXT, rank TEXT, position TEXT, group_name TEXT, no_night_shift INTEGER DEFAULT 0)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS daily_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT, week_number INTEGER, year INTEGER, day_index INTEGER, date_str TEXT, group_name TEXT, officer_name TEXT)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS duty_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT, week_number INTEGER, year INTEGER, day_index INTEGER, date_str TEXT, shift TEXT, officer_name TEXT)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS sessions (sid TEXT PRIMARY KEY, data TEXT, expires INTEGER)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS submissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, week_number INTEGER, year INTEGER, group_name TEXT, submitted_by TEXT, submitted_at TEXT,
    UNIQUE(week_number, year, group_name))`);

  await db.execute(`CREATE TABLE IF NOT EXISTS duty_rules (id INTEGER PRIMARY KEY AUTOINCREMENT, week_number INTEGER, year INTEGER, officer_id INTEGER, day_index INTEGER, shift INTEGER, rule TEXT)`);
  try { await db.execute("ALTER TABLE officers ADD COLUMN allowed_shifts TEXT DEFAULT '1,2,3'"); } catch (e) {}
  try { await db.execute("ALTER TABLE officers ADD COLUMN max_shifts INTEGER DEFAULT 2"); } catch (e) {}
  try { await db.execute("ALTER TABLE officers ADD COLUMN phone TEXT DEFAULT ''"); } catch (e) {}
  await db.execute(`CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT)`);
  await db.execute(`CREATE TABLE IF NOT EXISTS week_settings (week_number INTEGER, year INTEGER, locked INTEGER DEFAULT 0, PRIMARY KEY (week_number, year))`);
  await db.execute({ sql: 'UPDATE users SET permissions = ? WHERE permissions = ?', args: [JSON.stringify(ALL_PERMS), JSON.stringify(ALL_PERMS)] });

  // Admin mặc định
  const admin = await db.execute({ sql: 'SELECT id FROM users WHERE username = ?', args: ['admin'] });
  if (admin.rows.length === 0) {
    await db.execute({
      sql: 'INSERT INTO users (username, password, role, group_name, permissions) VALUES (?, ?, ?, ?, ?)',
      args: ['admin', hashPw(process.env.ADMIN_PASSWORD || 'admin123'), 'admin', 'TỔ TỔNG HỢP', JSON.stringify(['all'])]
    });
  }

  // 6 tài khoản thành viên (chỉ tạo nếu chưa có tên đăng nhập đó) — HÃY ĐỔI MẬT KHẨU MẶC ĐỊNH
  const members = [['chihuy', 'CHỈ HUY'], ['tonghop', 'TỔ TỔNG HỢP'], ['cstt', 'TỔ CSTT'],
                   ['pctp', 'TỔ PCTP'], ['cskv', 'TỔ CSKV'], ['anninh', 'TỔ AN NINH']];
  for (const [username, grp] of members) {
    const ex = await db.execute({ sql: 'SELECT id FROM users WHERE username = ?', args: [username] });
    if (ex.rows.length === 0) {
      await db.execute({
        sql: 'INSERT INTO users (username, password, role, group_name, permissions) VALUES (?, ?, ?, ?, ?)',
        args: [username, hashPw(process.env.DEFAULT_MEMBER_PASSWORD || 'cax@2026'), 'member', grp, JSON.stringify(ALL_PERMS)]
      });
    }
  }

  // Chuẩn hoá lại tên tổ của các tài khoản đã có
  const users = await db.execute('SELECT id, group_name FROM users');
  for (const u of users.rows) {
    const n = normalizeGroup(u.group_name);
    if (n && n !== u.group_name) await db.execute({ sql: 'UPDATE users SET group_name = ? WHERE id = ?', args: [n, u.id] });
  }
  console.log('Khởi tạo CSDL thành công!');
}

// ================= MIDDLEWARE =================

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

const publicDir = path.join(__dirname, 'public');
app.use(express.static(publicDir));
app.get('/', (req, res) => {
  const p = fs.existsSync(path.join(publicDir, 'index.html')) ? path.join(publicDir, 'index.html') : path.join(__dirname, 'index.html');
  res.sendFile(p);
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'cax_thuantrung_2026',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  store: new TursoStore(),
  cookie: { maxAge: 12 * 3600 * 1000, httpOnly: true, sameSite: 'lax' }
}));
app.use('/api', (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); }); // dữ liệu lịch luôn lấy mới, không dùng bản cache
app.use('/api', refreshUser);

// ================= TÀI KHOẢN =================

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const r = await db.execute({ sql: 'SELECT * FROM users WHERE username = ?', args: [String(username || '').trim()] });
    const u = r.rows[0];
    if (!u || !checkPw(String(password || ''), u.password)) {
      return res.status(401).json({ success: false, message: 'Sai tài khoản hoặc mật khẩu' });
    }
    if (!String(u.password).startsWith('scrypt$')) {
      await db.execute({ sql: 'UPDATE users SET password = ? WHERE id = ?', args: [hashPw(String(password)), u.id] });
    }
    req.session.user = sessionUserFrom(u);
    userCache.delete(Number(u.id));
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error('Lỗi login:', err);
    res.status(500).json({ error: 'Lỗi hệ thống' });
  }
});

// ================= LOGO + TIÊU ĐỀ HỆ THỐNG =================
const BRAND_DEFAULT = { title: 'CÔNG AN XÃ THUẦN TRUNG', subtitle: 'Phần mềm tổng hợp lịch trực', logo: '' }; // logo rỗng = dùng logo mặc định trong index.html
async function readBrand() {
  const r = await db.execute("SELECT value FROM app_settings WHERE key = 'branding'");
  if (!r.rows.length) return { ...BRAND_DEFAULT };
  try { return { ...BRAND_DEFAULT, ...JSON.parse(r.rows[0].value) }; } catch (e) { return { ...BRAND_DEFAULT }; }
}
app.get('/api/branding', async (req, res) => { // công khai: màn hình đăng nhập cũng cần hiển thị
  try { res.json(await readBrand()); } catch (e) { console.error(e); res.json({ ...BRAND_DEFAULT }); }
});
app.put('/api/branding', requireAdmin, async (req, res) => {
  try {
    const cur = await readBrand(), b = req.body || {};
    const title = String(b.title == null ? cur.title : b.title).replace(/\s+/g, ' ').trim();
    const subtitle = String(b.subtitle == null ? cur.subtitle : b.subtitle).replace(/\s+/g, ' ').trim();
    if (!title) return res.status(400).json({ error: 'Dòng tiêu đề không được để trống' });
    if (title.length > 80 || subtitle.length > 120) return res.status(400).json({ error: 'Tiêu đề tối đa 80 ký tự, dòng mô tả tối đa 120 ký tự' });
    let logo = cur.logo;
    if (b.reset_logo) logo = '';
    else if (typeof b.logo === 'string' && b.logo) {
      if (!/^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+\/=]+$/.test(b.logo)) return res.status(400).json({ error: 'Logo phải là ảnh PNG, JPG, WEBP hoặc GIF' });
      if (b.logo.length > 1.5 * 1024 * 1024) return res.status(400).json({ error: 'Ảnh logo quá lớn (tối đa khoảng 1 MB)' });
      logo = b.logo;
    }
    const val = JSON.stringify({ title, subtitle, logo });
    await db.execute({ sql: "INSERT INTO app_settings (key, value) VALUES ('branding', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [val] });
    res.json({ success: true, title, subtitle, logo });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu cấu hình giao diện: ' + (err && err.message ? err.message : '') }); }
});

// ================= ẢNH NỀN TRANG WEB =================
const BG_DEFAULT = { image: '', mode: 'cover', overlay: 55, blur: 0 }; // image rỗng = không dùng ảnh nền
const BG_MODES = ['cover', 'contain', 'repeat', 'center'];
async function readBg() {
  const r = await db.execute("SELECT value FROM app_settings WHERE key = 'background'");
  if (!r.rows.length) return { ...BG_DEFAULT };
  try { return { ...BG_DEFAULT, ...JSON.parse(r.rows[0].value) }; } catch (e) { return { ...BG_DEFAULT }; }
}
app.get('/api/background', async (req, res) => { // công khai: màn hình đăng nhập cũng dùng ảnh nền
  try { res.json(await readBg()); } catch (e) { console.error(e); res.json({ ...BG_DEFAULT }); }
});
app.put('/api/background', requireAdmin, async (req, res) => {
  try {
    const cur = await readBg(), b = req.body || {};
    const mode = b.mode == null ? cur.mode : String(b.mode);
    if (!BG_MODES.includes(mode)) return res.status(400).json({ error: 'Kiểu ghép ảnh không hợp lệ' });
    const overlay = Math.round(Number(b.overlay == null ? cur.overlay : b.overlay)), blur = Math.round(Number(b.blur == null ? cur.blur : b.blur));
    if (!(overlay >= 0 && overlay <= 90)) return res.status(400).json({ error: 'Độ phủ làm mờ phải từ 0 đến 90%' });
    if (!(blur >= 0 && blur <= 20)) return res.status(400).json({ error: 'Độ nhòe phải từ 0 đến 20' });
    let image = cur.image;
    if (b.remove_image) image = '';
    else if (typeof b.image === 'string' && b.image) {
      if (!/^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+\/=]+$/.test(b.image)) return res.status(400).json({ error: 'Ảnh nền phải là PNG, JPG hoặc WEBP' });
      if (b.image.length > 3.5 * 1024 * 1024) return res.status(400).json({ error: 'Ảnh nền quá lớn (tối đa khoảng 2,5 MB sau khi nén)' });
      image = b.image;
    }
    await db.execute({ sql: "INSERT INTO app_settings (key, value) VALUES ('background', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [JSON.stringify({ image, mode, overlay, blur })] });
    res.json({ success: true, image, mode, overlay, blur });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu ảnh nền: ' + (err && err.message ? err.message : '') }); }
});

app.get('/api/me', (req, res) => {
  res.json({ loggedIn: !!req.session.user, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

// ================= CÁN BỘ =================

app.get('/api/officers', requireLogin, async (req, res) => {
  try {
    const r = await db.execute('SELECT * FROM officers ORDER BY id DESC');
    res.json(r.rows || []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi tải danh sách cán bộ' });
  }
});

app.get('/api/officers/search', requireLogin, async (req, res) => {
  try {
    const r = await db.execute({ sql: 'SELECT full_name FROM officers WHERE full_name LIKE ? LIMIT 10', args: [`%${req.query.q || ''}%`] });
    res.json((r.rows || []).map(o => o.full_name));
  } catch (err) { res.json([]); }
});

app.post('/api/officers', requireAdmin, async (req, res) => {
  const { full_name, gender, rank, position, group_name, allowed_shifts, max_shifts, phone } = req.body;
  const allowed = allowed_shifts == null ? '1,2,3' : String(allowed_shifts); const no_night_shift = !allowed.split(',').includes('3'); const maxS = Number.isFinite(Number(max_shifts)) ? Number(max_shifts) : 2;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    const r = await db.execute({
      sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift, allowed_shifts, max_shifts, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      args: [full_name.trim(), gender || 'Nam', rank || 'Đại úy', position || 'Cán bộ', group_name || 'TỔ TỔNG HỢP', no_night_shift ? 1 : 0, allowed, maxS, cleanPhone(phone)]
    });
    res.json({ success: true, id: Number(r.lastInsertRowid) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Không thể lưu cán bộ vào CSDL' });
  }
});

app.put('/api/officers/:id', requireAdmin, async (req, res) => {
  const { full_name, gender, rank, position, group_name, allowed_shifts, max_shifts, phone } = req.body;
  const allowed = allowed_shifts == null ? '1,2,3' : String(allowed_shifts); const no_night_shift = !allowed.split(',').includes('3'); const maxS = Number.isFinite(Number(max_shifts)) ? Number(max_shifts) : 2;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    await db.execute({
      sql: 'UPDATE officers SET full_name = ?, gender = ?, rank = ?, position = ?, group_name = ?, no_night_shift = ?, allowed_shifts = ?, max_shifts = ?, phone = ? WHERE id = ?',
      args: [full_name.trim(), gender, rank, position, group_name, no_night_shift ? 1 : 0, allowed, maxS, cleanPhone(phone), req.params.id]
    });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi cập nhật CSDL' });
  }
});

app.delete('/api/officers/:id', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM officers WHERE id = ?', args: [req.params.id] });
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Lỗi xóa CSDL' });
  }
});

// ================= LỊCH TRỰC CHIẾN TỪNG TỔ =================

app.post('/api/schedule/submit', requirePerm('submit'), async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  if (!week || !year) return res.status(400).json({ error: 'Tuần/năm không hợp lệ' });

  const user = req.session.user;
  // Tài khoản thành viên chỉ được gửi cho ĐÚNG tổ của mình; admin được chọn tổ
  const targetGroup = user.role === 'admin'
    ? (normalizeGroup(req.body.group_name) || user.group_name)
    : user.group_name;
  if (!GROUPS.includes(targetGroup)) {
    return res.status(400).json({ error: 'Tài khoản chưa được gán tổ hợp lệ, hãy liên hệ admin' });
  }

  try {
    if (user.role !== 'admin' && await isLocked(week, year)) return res.status(423).json({ error: 'Tuần này đã bị khóa, liên hệ admin để chỉnh sửa' });
    const all = (await db.execute('SELECT full_name FROM officers')).rows.map(o => o.full_name);
    const stmts = [{
      sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ?',
      args: [week, year, targetGroup]
    }];
    let count = 0;
    (req.body.days_data || []).forEach(item => {
      const idx = Number(item.day_index);
      if (!(idx >= 0 && idx <= 6)) return;
      const seen = new Set();
      (item.officers || []).forEach(n => {
        const name = resolveName(String(n), all);
        if (!name || seen.has(name)) return;
        seen.add(name);
        count++;
        stmts.push({
          sql: 'INSERT INTO daily_schedule (week_number, year, day_index, date_str, group_name, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week, year, idx, dateStr(year, week, idx), targetGroup, name]
        });
      });
    });
    stmts.push({
      sql: `INSERT INTO submissions (week_number, year, group_name, submitted_by, submitted_at) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(week_number, year, group_name) DO UPDATE SET submitted_by = excluded.submitted_by, submitted_at = excluded.submitted_at`,
      args: [week, year, targetGroup, user.username, new Date().toISOString()]
    });
    await db.batch(stmts, 'write'); // xoá + ghi trong 1 giao dịch: lỗi thì không mất lịch cũ
    res.json({ success: true, count, group_name: targetGroup });
  } catch (err) {
    console.error('Lỗi lưu lịch trực:', err);
    res.status(500).json({ error: 'Lỗi hệ thống khi lưu lịch trực' });
  }
});

app.get('/api/schedule/summary', requirePerm('view_summary', 'submit'), async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});

// Tổ nào đã gửi lịch, ai gửi, lúc nào
app.get('/api/schedule/status', requirePerm('view_summary', 'submit'), async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT group_name, submitted_by, submitted_at FROM submissions WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});

// ================= PHÂN LỊCH TRỰC BAN =================

function isoWeekOf(d) {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
  t.setUTCDate(t.getUTCDate() + 3 - ((t.getUTCDay() + 6) % 7));
  const w1 = new Date(Date.UTC(t.getUTCFullYear(), 0, 4));
  return { year: t.getUTCFullYear(), week: 1 + Math.round(((t - w1) / 86400000 - 3 + ((w1.getUTCDay() + 6) % 7)) / 7) };
}
async function isLocked(week, year) {
  const r = await db.execute({ sql: 'SELECT locked FROM week_settings WHERE week_number = ? AND year = ?', args: [week, year] });
  return r.rows.length > 0 && Number(r.rows[0].locked) === 1;
}

// Sinh nhiều phương án phân ca để admin chọn.
// - Điểm phạt được ghi chi tiết từng vi phạm (loại, ngày/ca, nội dung, số điểm).
// - Cân bằng số ca 1/2/3 theo LUỸ KẾ nhiều tuần gần nhất (history_weeks, mặc định 4) cộng với tuần đang xếp.

// ================= RÀNG BUỘC CỨNG KHI PHÂN CA TRỰC BAN =================
// Thứ tự kiểm tra (không có nới lỏng/fallback):
//  1) số ca tối đa = 0 -> loại   2) bị đánh dấu "Không trực" ở ngày/ca -> loại
//  3) Ca 2, Ca 3 (và cả 3 ca của T7/CN) -> phải có tên trong lịch trực chiến của CHÍNH ngày đó
//  4) ca phải nằm trong phạm vi được phép trực (ca được phép của cán bộ + các ô ✅ "có thể trực" nếu có cài)
//  5) số ca tối đa trong tuần (kiểm tra theo số ca đã xếp)
const needsDutyRoster = (d, sh) => sh !== 1 || d >= 5;
// Quy tắc 2 ca trong tuần: tối đa 2 ca/người/tuần; chỉ được các cặp Ca1+Ca3, Ca2+Ca3, Ca3+Ca3 (cấm Ca1+Ca1, Ca1+Ca2, Ca2+Ca2)
// và 2 ngày trực phải cách nhau tối thiểu 1 ngày (tức chênh nhau từ 2 ngày trở lên, ví dụ T2 và T4).
const MAX_WEEK_SHIFTS = 2, MIN_DAY_GAP = 2;
const NO_OFF = new Set();
const pairOk = (d1, s1, d2, s2, off = NO_OFF) => (off.has('day_gap') || Math.abs(d1 - d2) >= MIN_DAY_GAP) && (off.has('pair_type') || s1 === 3 || s2 === 3);
const pairText = (off = NO_OFF) => [
  off.has('pair_type') ? '' : 'chỉ được trực 2 ca thuộc cặp Ca 1 + Ca 3, Ca 2 + Ca 3 hoặc Ca 3 + Ca 3',
  off.has('day_gap') ? '' : '2 ngày trực phải cách nhau tối thiểu 1 ngày'
].filter(Boolean).join(' và ');

// ================= DANH SÁCH RÀNG BUỘC NGẦM (admin bật/tắt) =================
// 'hard' = ràng buộc cứng (loại người khỏi ô), 'soft' = ràng buộc mềm (ưu tiên / tính điểm phạt).
// Trạng thái tắt lưu trong app_settings (key 'disabled_constraints'), áp dụng cho mọi tuần.
const CONSTRAINTS = [
  { id: 'max_zero', kind: 'hard', title: 'Loại cán bộ có số ca tối đa = 0', desc: 'Cán bộ được admin đặt số ca trực ban tối đa bằng 0 sẽ không được xếp bất kỳ ca nào.' },
  { id: 'block_cells', kind: 'hard', title: 'Ô đánh dấu "Không trực" là tuyệt đối', desc: 'Ô ⛔ Không trực của cán bộ (theo ngày/ca) không bao giờ được phân, kể cả khi thiếu người.' },
  { id: 'roster_required', kind: 'hard', title: 'Phải có tên trong lịch trực chiến của đúng ngày đó', desc: 'Ca 2, Ca 3 (và cả 3 ca của Thứ 7, Chủ nhật) chỉ phân cho người có tên trong lịch trực chiến của chính ngày đó; không có người thì để trống và cảnh báo.' },
  { id: 'allowed_shifts', kind: 'hard', title: 'Chỉ phân vào ca được phép của cán bộ', desc: 'Chỉ xếp cán bộ vào các ca được chọn "có thể trực" (Ca 1/2/3 của cán bộ) và các ô ✅ có thể trực nếu admin có cài.' },
  { id: 'ca1_consecutive', kind: 'hard', title: 'Không trực Ca 1 hai tuần liên tiếp', desc: 'Người đã trực Ca 1 ở tuần liền trước thì tuần này không được xếp Ca 1.' },
  { id: 'week_cap', kind: 'hard', title: 'Giới hạn số ca trong tuần', desc: 'Mỗi người tối đa 2 ca/tuần và không vượt số ca tối đa riêng của cán bộ (mặc định 2).' },
  { id: 'pair_type', kind: 'hard', title: 'Chỉ cho phép các cặp ca Ca1+Ca3, Ca2+Ca3, Ca3+Ca3', desc: 'Người trực 2 ca trong tuần thì cặp ca phải có Ca 3; cấm Ca1+Ca1, Ca1+Ca2, Ca2+Ca2.' },
  { id: 'day_gap', kind: 'hard', title: 'Hai ca của một người cách nhau tối thiểu 1 ngày', desc: 'Hai ca trực trong tuần của cùng một người phải chênh nhau từ 2 ngày trở lên (ví dụ Thứ 2 và Thứ 4).' },
  { id: 'prefer_fresh', kind: 'soft', title: 'Ưu tiên người chưa có ca nào trong tuần', desc: 'Chỉ dùng người đã có 1 ca khi không còn ai chưa trực.' },
  { id: 'balance', kind: 'soft', title: 'Cân bằng số ca 1/2/3 theo nhiều tuần', desc: 'Ưu tiên người có ít lượt hơn (luỹ kế các tuần gần nhất) và phạt điểm khi lệch quá 1 lượt so với trung bình nhóm.' },
  { id: 'ca1_gap2', kind: 'soft', title: 'Ca 1 chưa phân được người thích hợp: ưu tiên người trực Ca 1 cách tối thiểu 2 tuần', desc: 'Khi một ca sáng (Ca 1) không còn người chưa có ca nào trong tuần để xếp, hệ thống ưu tiên chọn người có lần trực Ca 1 gần nhất cách tuần này từ 2 tuần trở lên (người lâu chưa trực Ca 1 được ưu tiên trước).' },
  { id: 'repeat_prev', kind: 'soft', title: 'Hạn chế trùng loại ca với tuần liền trước', desc: 'Ưu tiên không xếp người vào đúng loại ca họ vừa trực tuần trước; nếu trùng sẽ bị phạt điểm.' }
];
async function loadDisabled() {
  try {
    const r = await db.execute("SELECT value FROM app_settings WHERE key = 'disabled_constraints'");
    const arr = r.rows.length ? JSON.parse(r.rows[0].value) : [];
    return new Set((Array.isArray(arr) ? arr : []).filter(id => CONSTRAINTS.some(c => c.id === id)));
  } catch (e) { return new Set(); }
}
const SHIFT_NAME = { 1: 'Ca 1', 2: 'Ca 2', 3: 'Ca 3' };
const DAY_NAME = ['Thứ 2', 'Thứ 3', 'Thứ 4', 'Thứ 5', 'Thứ 6', 'Thứ 7', 'Chủ nhật'];

async function loadDutyContext(week, year) {
  const duty = (await db.execute({ sql: 'SELECT officer_name, day_index FROM daily_schedule WHERE week_number = ? AND year = ?', args: [week, year] })).rows;
  const officers = (await db.execute('SELECT * FROM officers')).rows;
  const info = new Map(officers.map(o => [o.full_name, o]));
  const roster = Array.from({ length: 7 }, () => new Set());
  duty.forEach(r => { const d = Number(r.day_index); if (d >= 0 && d <= 6) roster[d].add(r.officer_name); });
  const er = await effectiveRules(week, year);
  const off = await loadDisabled(); // các ràng buộc ngầm admin đã vô hiệu hóa
  const blocked = new Set(), canCells = new Map();
  er.rows.forEach(r => {
    const k = `${Number(r.day_index)}|${Number(r.shift)}`;
    if (r.rule === 'block') blocked.add(`${r.full_name}|${k}`);
    else if (r.rule === 'force') { // 'force' (tên cũ trong CSDL) = nay hiểu là "CÓ THỂ trực", không phải bắt buộc
      if (!canCells.has(r.full_name)) canCells.set(r.full_name, new Set());
      canCells.get(r.full_name).add(k);
    }
  });
  const maxOf = n => { const m = Number((info.get(n) || {}).max_shifts); return Number.isFinite(m) ? m : 2; };
  // số ca tối đa thực tế trong tuần (tắt 'week_cap' = không giới hạn; tắt 'max_zero' thì số ca = 0 không còn chặn)
  const capOf = n => off.has('week_cap') ? Infinity : (maxOf(n) < 1 && off.has('max_zero')) ? MAX_WEEK_SHIFTS : Math.min(maxOf(n), MAX_WEEK_SHIFTS);
  // Tuần liền trước: ai đã trực Ca 1 thì không được trực Ca 1 tuần này (không 2 tuần liên tiếp)
  const ps = isoWeekStart(year, week); ps.setUTCDate(ps.getUTCDate() - 7);
  const pw = isoWeekOf(ps);
  const ca1Prev = new Set((await db.execute({ sql: "SELECT DISTINCT officer_name FROM duty_schedule WHERE week_number = ? AND year = ? AND shift = 'Ca1'", args: [pw.week, pw.year] })).rows.map(r => r.officer_name));
  const allowedOf = n => String((info.get(n) || {}).allowed_shifts == null ? '1,2,3' : (info.get(n) || {}).allowed_shifts)
    .split(',').map(Number).filter(x => x >= 1 && x <= 3);
  // Lý do loại người n khỏi ô (ngày d, ca sh) — chỉ các điều kiện cố định (chưa tính số ca đã xếp). '' = hợp lệ.
  const reason = (n, d, sh) => {
    if (!info.has(n)) return `${n} không có trong danh sách cán bộ`;
    if (!off.has('max_zero') && maxOf(n) < 1) return `${n} có số ca trực ban tối đa = 0`;
    if (!off.has('block_cells') && blocked.has(`${n}|${d}|${sh}`)) return `${n} được đánh dấu Không trực ${DAY_NAME[d]} ${SHIFT_NAME[sh]}`;
    if (!off.has('roster_required') && needsDutyRoster(d, sh) && !roster[d].has(n)) return `${n} không có tên trong lịch trực chiến ${DAY_NAME[d]} nên không được xếp ${SHIFT_NAME[sh]}`;
    if (!off.has('allowed_shifts') && !allowedOf(n).includes(sh)) return `${SHIFT_NAME[sh]} không nằm trong các ca ${n} được phép trực`;
    if (!off.has('ca1_consecutive') && sh === 1 && ca1Prev.has(n)) return `${n} đã trực Ca 1 ở tuần liền trước (tuần ${pw.week}/${pw.year}) nên không được trực Ca 1 hai tuần liên tiếp`;
    const cc = canCells.get(n);
    if (!off.has('allowed_shifts') && cc && cc.size && !cc.has(`${d}|${sh}`)) return `${DAY_NAME[d]} ${SHIFT_NAME[sh]} không nằm trong các ô ${n} có thể trực`;
    return '';
  };
  return { info, roster, maxOf, capOf, allowedOf, reason, ca1Prev, off, hasDuty: duty.length > 0 };
}

// Kiểm tra cả một danh sách phân ca (dùng khi áp dụng phương án / nhập Word): trả về danh sách lỗi
function validateAssignments(ctx, list) {
  const errs = [], mine = new Map(), seenCell = new Set();
  list.forEach(a => {
    if (!a.officer_name) return;
    const n = String(a.officer_name), d = Number(a.day_index), sh = Number(String(a.shift).slice(2));
    if (!(d >= 0 && d <= 6) || !(sh >= 1 && sh <= 3)) { errs.push(`Ô không hợp lệ (${a.shift}, ngày ${a.day_index})`); return; }
    const cell = `${d}|${sh}`; if (seenCell.has(cell)) { errs.push(`${DAY_NAME[d]} ${SHIFT_NAME[sh]} bị phân 2 người`); return; } seenCell.add(cell);
    const why = ctx.reason(n, d, sh); if (why) errs.push(why);
    if (!mine.has(n)) mine.set(n, []); mine.get(n).push([d, sh]);
  });
  mine.forEach((m, n) => {
    if (Number.isFinite(ctx.capOf(n)) && m.length > ctx.capOf(n)) errs.push(`${n} bị phân ${m.length} ca, vượt số ca tối đa trong tuần (${ctx.capOf(n)})`);
    for (let i = 0; i < m.length; i++) for (let j = i + 1; j < m.length; j++)
      if (!pairOk(m[i][0], m[i][1], m[j][0], m[j][1], ctx.off))
        errs.push(`${n} trực ${DAY_NAME[m[i][0]]} ${SHIFT_NAME[m[i][1]]} và ${DAY_NAME[m[j][0]]} ${SHIFT_NAME[m[j][1]]}: ${pairText(ctx.off)}`);
  });
  return [...new Set(errs)];
}

// Thứ tự phân ca: [ngày(0=T2…6=CN), ca]
const SLOT_ORDER = [[4, 2], [4, 3], [5, 1], [5, 2], [5, 3], [6, 1], [6, 2], [6, 3],
  [0, 2], [0, 3], [1, 2], [1, 3], [2, 2], [2, 3], [3, 2], [3, 3],
  [0, 1], [1, 1], [2, 1], [3, 1], [4, 1]];
const PEN = { REPEAT: 10, LIMIT: 100, ALLOWED: 100, CONSEC: 100, FORCED_OFF: 5, UNFILLED: 500, BAL: 3 };

app.post('/api/duty/generate', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  if (!week || !year) return res.status(400).json({ error: 'Tuần/năm không hợp lệ' });
  const hw = parseInt(req.body.history_weeks, 10);
  const histWeeks = Number.isFinite(hw) ? Math.min(12, Math.max(0, hw)) : 4;
  try {
    const duty = (await db.execute({ sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?', args: [week, year] })).rows;
    if (!duty.length && !(await loadDisabled()).has('roster_required')) return res.status(400).json({ error: 'Chưa có tổ nào gửi lịch trực chiến cho tuần này' });
    const officers = (await db.execute('SELECT * FROM officers')).rows;
    if (!officers.length) return res.status(400).json({ error: 'Chưa có cán bộ nào trong danh sách' });
    // Ràng buộc cứng gom về 1 chỗ (loadDutyContext). Thứ tự kiểm tra nằm trong ctx.reason — không có nới lỏng.
    const ctx = await loadDutyContext(week, year);
    const maxOf = ctx.maxOf, allowed = ctx.allowedOf;
    const off = ctx.off;
    const pool = officers.filter(o => (off.has('max_zero') || maxOf(o.full_name) >= 1) && (off.has('allowed_shifts') || allowed(o.full_name).length)).map(o => o.full_name); // bước 1: loại max = 0

    // Lịch sử các tuần trước: hist = luỹ kế số ca 1/2/3 trong cửa sổ histWeeks tuần; prev = ca đã trực ở tuần liền trước
    const prevWeeks = [];
    for (let i = 1; i <= Math.max(1, histWeeks); i++) {
      const s = isoWeekStart(year, week); s.setUTCDate(s.getUTCDate() - 7 * i);
      prevWeeks.push(isoWeekOf(s));
    }
    const hrows = (await db.execute({
      sql: 'SELECT week_number, year, officer_name, shift FROM duty_schedule WHERE ' + prevWeeks.map(() => '(week_number = ? AND year = ?)').join(' OR '),
      args: prevWeeks.flatMap(w => [w.week, w.year])
    })).rows;
    const win = new Set(prevWeeks.slice(0, histWeeks).map(w => `${w.year}-${w.week}`));
    const lastKey = `${prevWeeks[0].year}-${prevWeeks[0].week}`;
    const hist = new Map(), prev = new Map();
    hrows.forEach(r => {
      const sh = Number(String(r.shift).slice(2)); if (!(sh >= 1 && sh <= 3)) return;
      const k = `${Number(r.year)}-${Number(r.week_number)}`;
      if (win.has(k)) { const h = hist.get(r.officer_name) || [0, 0, 0, 0]; h[sh]++; hist.set(r.officer_name, h); }
      if (k === lastKey) { if (!prev.has(r.officer_name)) prev.set(r.officer_name, new Set()); prev.get(r.officer_name).add(sh); }
    });
    const H = n => hist.get(n) || [0, 0, 0, 0];
    // Số tuần kể từ lần trực Ca 1 gần nhất (tra tối đa 12 tuần trước; chưa có = 99). Dùng cho ràng buộc mềm 'ca1_gap2'.
    const gapMap = new Map();
    {
      const wk = [];
      for (let i = 1; i <= 12; i++) { const s0 = isoWeekStart(year, week); s0.setUTCDate(s0.getUTCDate() - 7 * i); wk.push(isoWeekOf(s0)); }
      const idx = new Map(wk.map((w, i) => [`${w.year}-${w.week}`, i + 1]));
      const rows = (await db.execute({
        sql: "SELECT week_number, year, officer_name FROM duty_schedule WHERE shift = 'Ca1' AND (" + wk.map(() => '(week_number = ? AND year = ?)').join(' OR ') + ')',
        args: wk.flatMap(w => [w.week, w.year])
      })).rows;
      rows.forEach(r => {
        const g = idx.get(`${Number(r.year)}-${Number(r.week_number)}`);
        if (g && g < (gapMap.get(r.officer_name) || 99)) gapMap.set(r.officer_name, g);
      });
    }
    const ca1Gap = n => gapMap.get(n) || 99;

    // Nhóm người "thuộc diện" từng ca dùng để đo độ cân bằng: ca 2, 3 chỉ tính người có lịch trực chiến tuần này
    const roster = new Set(duty.map(r => r.officer_name));
    const elig = { 1: [], 2: [], 3: [] };
    pool.forEach(n => [1, 2, 3].forEach(s => { if ((off.has('allowed_shifts') || allowed(n).includes(s)) && (off.has('max_zero') || maxOf(n) > 0) && (s === 1 || off.has('roster_required') || roster.has(n))) elig[s].push(n); }));
    const onDutyBy = [];
    for (let d = 0; d < 7; d++) onDutyBy.push([...new Set(duty.filter(r => Number(r.day_index) === d).map(r => r.officer_name))]);
    const r1 = x => Math.round(x * 10) / 10;

    const attempt = () => {
      const jit = 0.5 + Math.random() * 3;
      const load = new Map(), cw = new Map();
      const asg = [], pens = [], notes = [];
      const pen = (type, points, text, d, sh) => pens.push({ type, points, text, day_index: d, shift: sh });
      for (let d = 0; d < 7; d++) if (!onDutyBy[d].length) notes.push(`Ngày ${dateStr(year, week, d)}: chưa có lịch trực chiến`);
      const mine = new Map(); // người -> [[ngày, ca], ...] đã phân trong phương án này
      // Chọn người cho 1 ô. Chỉ xét người vượt qua TẤT CẢ điều kiện bắt buộc (không nới lỏng); cân bằng/lịch sử chỉ để chọn trong số người hợp lệ.
      // Ưu tiên người CHƯA có ca nào trong tuần; chỉ khi không còn ai mới dùng người đã có 1 ca (và cặp ca phải đúng quy tắc: với Ca 1 thì người đó phải đã có Ca 3 cách ít nhất 1 ngày).
      const pick = (d, sh) => {
        let nameA = '', bestA = Infinity, nameB = '', bestB = Infinity;
        for (const o of pool) {
          if (ctx.reason(o, d, sh)) continue;                 // Không trực -> trực chiến (Ca 2/3, T7/CN) -> ca được phép -> Ca 1 tuần trước
          const m = mine.get(o) || [];
          if (m.length >= ctx.capOf(o)) continue;             // số ca tối đa
          if (!m.every(([d2, s2]) => pairOk(d, sh, d2, s2, off))) continue; // cặp ca + khoảng cách ngày
          const h = H(o), c = cw.get(o) || [0, 0, 0, 0];
          const p = (!off.has('repeat_prev') && (prev.get(o) || new Set()).has(sh) ? 10 : 0)
            + (off.has('balance') ? 0 : (h[sh] + c[sh]) * 3    // luỹ kế đúng loại ca này
            + (h[1] + h[2] + h[3] + m.length) * 1.5)           // luỹ kế tổng số ca
            + Math.random() * jit;
          if (!m.length || off.has('prefer_fresh')) { if (p < bestA) { bestA = p; nameA = o; } }
          else {
            // Ca 1 không còn người chưa trực để xếp: ưu tiên người trực Ca 1 cách tối thiểu 2 tuần (càng lâu chưa trực Ca 1 càng được ưu tiên)
            const g1 = sh === 1 && !off.has('ca1_gap2') ? (ca1Gap(o) >= 2 ? 0 : 50) - Math.min(ca1Gap(o), 12) * 0.3 : 0;
            if (p + g1 < bestB) { bestB = p + g1; nameB = o; }
          }
        }
        return nameA ? { name: nameA, second: false } : nameB ? { name: nameB, second: true } : null;
      };
      const place = (d, sh, r) => {
        const name = r.name, ds = dateStr(year, week, d), m = mine.get(name) || [];
        if (!off.has('repeat_prev') && (prev.get(name) || new Set()).has(sh)) pen('repeat_prev', PEN.REPEAT, `${name} trực ca ${sh} trùng với ca đã trực ở tuần liền trước`, d, sh);
        if (r.second) notes.push(`${DAY_NAME[d]} ${SHIFT_NAME[sh]} (${ds}): không còn người chưa trực nên dùng ${name}, người đã trực ${m.map(([d2, s2]) => `${SHIFT_NAME[s2]} ${DAY_NAME[d2]}`).join(', ')}${sh === 1 && !off.has('ca1_gap2') ? (ca1Gap(name) >= 99 ? '; chưa có Ca 1 trong 12 tuần gần nhất' : `; lần trực Ca 1 gần nhất cách ${ca1Gap(name)} tuần`) : ''}`);
        m.push([d, sh]); mine.set(name, m); load.set(name, m.length);
        const c = cw.get(name) || [0, 0, 0, 0]; c[sh]++; cw.set(name, c);
        asg.push({ day_index: d, date_str: ds, shift: 'Ca' + sh, officer_name: name });
      };
      // Thứ tự phân (ô khó trước, ô dễ sau): (1) cuối tuần từ Ca 2 thứ 6 đến hết Chủ nhật; (2) Ca 2, Ca 3 thứ 2–thứ 5; (3) Ca 1 thứ 2–thứ 6
      const pending = [];
      for (const [d, sh] of SLOT_ORDER) { const r = pick(d, sh); if (r) place(d, sh, r); else pending.push([d, sh]); }
      // Thử lại các ô còn trống 1 lần: các ca đã phân sau đó có thể tạo ra người hợp lệ mới (ví dụ người đã có Ca 3 nay được dùng cho Ca 1)
      for (const [d, sh] of pending) {
        const r = pick(d, sh);
        if (r) { place(d, sh, r); continue; }
        const ds = dateStr(year, week, d);
        const why = !off.has('roster_required') && needsDutyRoster(d, sh) && !ctx.roster[d].size
          ? `${DAY_NAME[d]} chưa có ai trong lịch trực chiến`
          : 'mọi người hợp lệ đều đã bị loại (Không trực, ngoài ca được phép, Ca 1 tuần liền trước, đã đủ số ca tối đa hoặc không đúng quy tắc cặp ca/khoảng cách ngày)';
        pen('unfilled', PEN.UNFILLED, `Chưa phân được ${SHIFT_NAME[sh]} ${DAY_NAME[d]} (${ds}): không còn người hợp lệ — ${why}`, d, sh);
      }
      asg.sort((x, y) => x.day_index - y.day_index || x.shift.localeCompare(y.shift)); // trả về theo thứ tự ngày/ca cho dễ đọc

      // Điểm phạt mất cân bằng luỹ kế: mỗi người lệch quá 1 lượt so với trung bình của nhóm cùng ca
      let tie = 0;
      const span = histWeeks > 0 ? `${histWeeks} tuần trước + tuần này` : 'tuần này';
      for (const s of off.has('balance') ? [] : [1, 2, 3]) {
        const E = elig[s]; if (E.length < 2) continue;
        const cum = n => H(n)[s] + (cw.get(n) || [0, 0, 0, 0])[s];
        const avg = E.reduce((a, n) => a + cum(n), 0) / E.length;
        E.forEach(n => {
          const dev = cum(n) - avg; tie += dev * dev;
          if (Math.abs(dev) > 1) pen('balance', r1((Math.abs(dev) - 1) * PEN.BAL),
            `Ca ${s} luỹ kế (${span}): ${n} có ${cum(n)} lượt, ${dev > 0 ? 'cao hơn' : 'thấp hơn'} trung bình nhóm (${r1(avg)} lượt)`, null, s);
        });
      }
      const stats = [];
      pool.forEach(n => {
        const h = H(n), c = cw.get(n) || [0, 0, 0, 0];
        if (h[1] + h[2] + h[3] + c[1] + c[2] + c[3] > 0 || roster.has(n))
          stats.push({ name: n, hist: [h[1], h[2], h[3]], week: [c[1], c[2], c[3]] });
      });
      stats.sort((a, b) => a.name.localeCompare(b.name, 'vi'));
      const score = r1(pens.reduce((a, p) => a + p.points, 0));
      pens.sort((a, b) => b.points - a.points);
      return { score, tie, penalties: pens, warnings: pens.map(p => p.text), notes: [...new Set(notes)], assignments: asg, stats, history_weeks: histWeeks };
    };

    const opts = []; const seen = new Set();
    for (let t = 0; t < 300; t++) {
      const r = attempt();
      const sig = r.assignments.map(x => x.officer_name).join('|');
      if (seen.has(sig)) continue;
      seen.add(sig); opts.push(r);
    }
    opts.sort((a, b) => a.score - b.score || a.tie - b.tie); // điểm phạt nhỏ -> lớn
    res.json({ success: true, options: opts.slice(0, 5).map(({ tie, ...o }) => o) });
  } catch (err) {
    console.error('Lỗi phân lịch trực ban:', err);
    res.status(500).json({ error: 'Không thể phân lịch trực ban' });
  }
});

app.post('/api/duty/apply', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  const list = Array.isArray(req.body.assignments) ? req.body.assignments : [];
  try {
    // Quản trị viên được áp dụng mọi phương án bất kể vi phạm quy tắc: kiểm tra lại ở máy chủ chỉ để CẢNH BÁO, không chặn lưu
    const warnings = validateAssignments(await loadDutyContext(week, year), list);
    const stmts = [{ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [week, year] }];
    list.forEach(a => {
      if (!a.officer_name || !['Ca1', 'Ca2', 'Ca3'].includes(a.shift)) return;
      stmts.push({ sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
        args: [week, year, Number(a.day_index), dateStr(year, week, Number(a.day_index)), a.shift, String(a.officer_name)] });
    });
    await db.batch(stmts, 'write');
    res.json({ success: true, warnings });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu phương án' }); }
});

// Admin sửa 1 ô lịch trực ban
app.put('/api/duty/cell', requireAdmin, async (req, res) => {
  const { week_number, year, day_index, shift, officer_name } = req.body;
  if (!['Ca1', 'Ca2', 'Ca3'].includes(shift)) return res.status(400).json({ error: 'Ca không hợp lệ' });
  try {
    const stmts = [{ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ? AND day_index = ? AND shift = ?', args: [week_number, year, day_index, shift] }];
    const name = String(officer_name || '').trim();
    let warnings = [];
    if (name) {
      const wk = Number(week_number), yr = Number(year), d = Number(day_index), sh = Number(shift.slice(2));
      if (!(d >= 0 && d <= 6)) return res.status(400).json({ error: 'Ngày không hợp lệ' });
      // Quản trị viên được sửa mọi ô lịch trực ban bất kể vi phạm quy tắc: chỉ kiểm tra để CẢNH BÁO, không chặn lưu.
      // (Các ràng buộc cứng vẫn bắt buộc đối với phân ca tự động.)
      const ctx = await loadDutyContext(wk, yr);
      const others = (await db.execute({ sql: 'SELECT day_index, shift, officer_name FROM duty_schedule WHERE week_number = ? AND year = ?', args: [wk, yr] })).rows
        .filter(r => !(Number(r.day_index) === d && r.shift === shift));
      warnings = validateAssignments(ctx, others.map(r => ({ day_index: Number(r.day_index), shift: r.shift, officer_name: r.officer_name }))
        .concat([{ day_index: d, shift, officer_name: name }]));
      // chỉ giữ cảnh báo liên quan đến người vừa được xếp (không nhắc lại lỗi cũ của người khác)
      warnings = warnings.filter(w => w.includes(name));
      stmts.push({ sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
        args: [wk, yr, d, dateStr(yr, wk, d), shift, name] });
    }
    await db.batch(stmts, 'write');
    res.json({ success: true, warnings });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể sửa lịch trực ban' }); }
});

app.get('/api/duty/summary', requirePerm('view_duty'), async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT * FROM duty_schedule WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});


// ================= THỐNG KÊ / THEO DÕI TRỰC (cả đơn vị, khoảng thời gian tuỳ chọn) =================

function parseYMD(s) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(s || ''));
  if (!m) return null;
  const d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
  return isNaN(d) ? null : d;
}

app.get('/api/stats', requireAdmin, async (req, res) => {
  const from = parseYMD(req.query.from), to = parseYMD(req.query.to);
  if (!from || !to || to < from) return res.status(400).json({ error: 'Khoảng thời gian không hợp lệ' });
  if ((to - from) / 864e5 > 400) return res.status(400).json({ error: 'Chỉ thống kê tối đa 13 tháng mỗi lần' });
  try {
    const fmt = d => `${d.getUTCDate()}/${d.getUTCMonth() + 1}`;
    const weeks = [];
    const cur = new Date(from); cur.setUTCDate(cur.getUTCDate() - ((cur.getUTCDay() + 6) % 7)); // về thứ 2
    while (cur <= to) {
      const w = isoWeekOf(cur); const end = new Date(cur); end.setUTCDate(end.getUTCDate() + 6);
      weeks.push({ key: `${w.year}-${w.week}`, week: w.week, year: w.year, label: `${fmt(cur)}–${fmt(end)}` });
      cur.setUTCDate(cur.getUTCDate() + 7);
    }
    const cond = weeks.map(() => '(week_number = ? AND year = ?)').join(' OR ');
    const args = weeks.flatMap(w => [w.week, w.year]);
    const chienRows = (await db.execute({ sql: 'SELECT week_number, year, day_index, officer_name FROM daily_schedule WHERE ' + cond, args })).rows;
    const banRows = (await db.execute({ sql: 'SELECT week_number, year, day_index, shift, officer_name FROM duty_schedule WHERE ' + cond, args })).rows;

    const P = new Map();
    const get = name => {
      let p = P.get(name);
      if (!p) { p = { name, days: new Set(), chien: { total: 0, weeks: {} }, ban: { s: 0, c: 0, t: 0, total: 0, weeks: {} } }; P.set(name, p); }
      return p;
    };
    const dayOf = r => { const d = isoWeekStart(Number(r.year), Number(r.week_number)); d.setUTCDate(d.getUTCDate() + Number(r.day_index)); return d; };
    chienRows.forEach(r => {
      const d = dayOf(r); if (d < from || d > to) return;
      const p = get(r.officer_name); const dk = d.getTime();
      if (p.days.has(dk)) return; p.days.add(dk); // 1 người/ngày chỉ tính 1 lượt trực chiến
      const k = `${Number(r.year)}-${Number(r.week_number)}`;
      p.chien.total++; p.chien.weeks[k] = (p.chien.weeks[k] || 0) + 1;
    });
    banRows.forEach(r => {
      const d = dayOf(r); if (d < from || d > to) return;
      const sh = Number(String(r.shift).slice(2)); if (!(sh >= 1 && sh <= 3)) return;
      const p = get(r.officer_name); const k = `${Number(r.year)}-${Number(r.week_number)}`;
      p.ban[['s', 'c', 't'][sh - 1]]++; p.ban.total++;
      (p.ban.weeks[k] = p.ban.weeks[k] || [0, 0, 0])[sh - 1]++;
    });

    const officers = (await db.execute('SELECT full_name, rank, position, group_name, phone FROM officers')).rows;
    const meta = new Map(officers.map(o => [o.full_name, o]));
    officers.forEach(o => get(o.full_name));
    const people = [...P.values()].map(p => {
      const o = meta.get(p.name) || {};
      return { name: p.name, rank: o.rank || '', position: o.position || '', phone: o.phone || '',
        group_name: normalizeGroup(o.group_name) || o.group_name || '', chien: p.chien, ban: p.ban };
    });
    const gi = g => { const i = GROUPS.indexOf(g); return i < 0 ? 99 : i; };
    people.sort((a, b) => gi(a.group_name) - gi(b.group_name) || a.name.localeCompare(b.name, 'vi'));
    res.json({ from: req.query.from, to: req.query.to, weeks, people });
  } catch (err) { console.error('Lỗi thống kê:', err); res.status(500).json({ error: 'Không thể thống kê' }); }
});

// ================= QUẢN LÝ TUẦN =================

app.get('/api/week/info', requireLogin, async (req, res) => {
  const week = Number(req.query.week_number), year = Number(req.query.year);
  const sub = (await db.execute({ sql: 'SELECT group_name, submitted_by, submitted_at FROM submissions WHERE week_number = ? AND year = ?', args: [week, year] })).rows;
  res.json({ submissions: sub, locked: await isLocked(week, year) });
});

app.post('/api/week/lock', requireAdmin, async (req, res) => {
  const { week_number, year, locked } = req.body;
  await db.execute({ sql: `INSERT INTO week_settings (week_number, year, locked) VALUES (?, ?, ?)
    ON CONFLICT(week_number, year) DO UPDATE SET locked = excluded.locked`, args: [Number(week_number), Number(year), locked ? 1 : 0] });
  res.json({ success: true });
});

// Xoá lịch trực chiến của 1 tổ hoặc cả tuần (xoá cả tuần => mở khoá để các tổ báo lại)
app.delete('/api/schedule', requireAdmin, async (req, res) => {
  const week = Number(req.query.week_number), year = Number(req.query.year);
  const grp = req.query.group_name ? normalizeGroup(req.query.group_name) : null;
  try {
    const stmts = grp
      ? [{ sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ?', args: [week, year, grp] },
         { sql: 'DELETE FROM submissions WHERE week_number = ? AND year = ? AND group_name = ?', args: [week, year, grp] }]
      : [{ sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ?', args: [week, year] },
         { sql: 'DELETE FROM submissions WHERE week_number = ? AND year = ?', args: [week, year] },
         { sql: 'DELETE FROM week_settings WHERE week_number = ? AND year = ?', args: [week, year] }];
    await db.batch(stmts, 'write');
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể xóa lịch' }); }
});

// Admin sửa 1 ô lịch trực chiến (1 tổ, 1 ngày)
app.post('/api/schedule/cell', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year), idx = Number(req.body.day_index);
  const grp = normalizeGroup(req.body.group_name);
  if (!grp || !(idx >= 0 && idx <= 6)) return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
  try {
    const all = (await db.execute('SELECT full_name FROM officers')).rows.map(o => o.full_name);
    const names = [...new Set((req.body.officers || []).map(n => resolveName(String(n), all)).filter(Boolean))];
    const stmts = [{ sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ? AND day_index = ?', args: [week, year, grp, idx] }];
    names.forEach(n => stmts.push({ sql: 'INSERT INTO daily_schedule (week_number, year, day_index, date_str, group_name, officer_name) VALUES (?, ?, ?, ?, ?, ?)', args: [week, year, idx, dateStr(year, week, idx), grp, n] }));
    await db.batch(stmts, 'write');
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể sửa lịch' }); }
});

// ================= TÀI KHOẢN =================

const cleanPerms = p => (Array.isArray(p) ? p : []).filter(x => ALL_PERMS.includes(x));

app.get('/api/users', requireAdmin, async (req, res) => {
  const r = await db.execute('SELECT id, username, role, group_name, permissions FROM users ORDER BY id');
  res.json(r.rows);
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, password, group_name, role, permissions } = req.body;
  if (!username || !username.trim() || !password || String(password).length < 6) return res.status(400).json({ error: 'Cần tên đăng nhập và mật khẩu từ 6 ký tự' });
  try {
    await db.execute({ sql: 'INSERT INTO users (username, password, role, group_name, permissions) VALUES (?, ?, ?, ?, ?)',
      args: [username.trim(), hashPw(String(password)), role === 'admin' ? 'admin' : 'member', normalizeGroup(group_name) || 'TỔ TỔNG HỢP', JSON.stringify(cleanPerms(permissions))] });
    res.json({ success: true });
  } catch (err) { res.status(400).json({ error: 'Tên đăng nhập đã tồn tại' }); }
});

app.put('/api/users/:id', requireAdmin, async (req, res) => {
  const { password, group_name, role, permissions } = req.body;
  try {
    userCache.delete(Number(req.params.id)); // để tài khoản bị sửa nhận quyền mới ngay
    const cur = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.params.id] })).rows[0];
    if (!cur) return res.status(404).json({ error: 'Không tìm thấy tài khoản' });
    const newRole = role ? (role === 'admin' ? 'admin' : 'member') : cur.role;
    if (Number(cur.id) === req.session.user.id && newRole !== 'admin') return res.status(400).json({ error: 'Không thể tự hạ quyền admin của chính mình' });
    await db.execute({ sql: 'UPDATE users SET password = ?, group_name = ?, role = ?, permissions = ? WHERE id = ?',
      args: [password ? hashPw(String(password)) : cur.password, group_name ? (normalizeGroup(group_name) || cur.group_name) : cur.group_name, newRole,
             permissions ? JSON.stringify(cleanPerms(permissions)) : cur.permissions, req.params.id] });
    userCache.delete(Number(req.params.id));
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể cập nhật tài khoản' }); }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  if (Number(req.params.id) === req.session.user.id) return res.status(400).json({ error: 'Không thể xóa chính mình' });
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [req.params.id] });
  userCache.delete(Number(req.params.id));
  res.json({ success: true });
});

app.post('/api/password', requireLogin, async (req, res) => {
  const { old_password, new_password } = req.body;
  const u = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.session.user.id] })).rows[0];
  if (!u || !checkPw(String(old_password || ''), u.password)) return res.status(400).json({ error: 'Mật khẩu hiện tại không đúng' });
  if (!new_password || String(new_password).length < 6) return res.status(400).json({ error: 'Mật khẩu mới cần từ 6 ký tự' });
  await db.execute({ sql: 'UPDATE users SET password = ? WHERE id = ?', args: [hashPw(String(new_password)), u.id] });
  res.json({ success: true });
});


// Nhập hàng loạt cán bộ (từ file Word): người mới thì thêm; người đã có (trùng họ tên) thì chỉ cập nhật SĐT nếu file có SĐT
app.post('/api/officers/bulk', requireAdmin, async (req, res) => {
  const list = Array.isArray(req.body.officers) ? req.body.officers : [];
  if (!list.length) return res.status(400).json({ error: 'Không có dữ liệu để nhập' });
  const key = n => String(n || '').trim().replace(/\s+/g, ' ').toLowerCase();
  try {
    const exist = new Map((await db.execute('SELECT id, full_name FROM officers')).rows.map(o => [key(o.full_name), Number(o.id)]));
    const stmts = []; let added = 0, updated = 0, skipped = 0;
    list.forEach(o => {
      const name = String(o.full_name || '').trim().replace(/\s+/g, ' ');
      const phone = cleanPhone(o.phone);
      if (!name) { skipped++; return; }
      const k = key(name);
      if (exist.has(k)) {
        const id = exist.get(k);
        if (id > 0 && phone) { stmts.push({ sql: 'UPDATE officers SET phone = ? WHERE id = ?', args: [phone, id] }); updated++; }
        else skipped++;
        return;
      }
      exist.set(k, -1); // trùng ngay trong file thì bỏ qua
      const allowed = o.allowed_shifts == null ? '1,2,3' : String(o.allowed_shifts);
      const mx = Number.isFinite(Number(o.max_shifts)) ? Number(o.max_shifts) : 2;
      stmts.push({
        sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift, allowed_shifts, max_shifts, phone) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        args: [name, o.gender === 'Nữ' ? 'Nữ' : 'Nam', o.rank || 'Đại úy', o.position || 'Cán bộ', normalizeGroup(o.group_name) || 'TỔ TỔNG HỢP', allowed.split(',').includes('3') ? 0 : 1, allowed, mx, phone]
      });
      added++;
    });
    if (stmts.length) await db.batch(stmts, 'write');
    res.json({ success: true, added, updated, skipped });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể nhập danh sách cán bộ' }); }
});

// Nhập lịch trực chiến / trực ban đã quét từ file Word theo mẫu hệ thống.
// - Ghi đúng vào tuần/năm trình duyệt gửi lên; dữ liệu cũ của phần được nhập bị thay thế trong CÙNG 1 giao dịch (lỗi thì giữ nguyên dữ liệu cũ, không bao giờ trùng).
// - Trực chiến: chỉ thay thế các tổ có mặt trong file (tổ không có trong file giữ nguyên). Trực ban: thay thế cả tuần.
app.post('/api/schedule/import', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year), mode = String(req.body.mode || '');
  const rows = Array.isArray(req.body.rows) ? req.body.rows : [];
  if (!Number.isInteger(week) || week < 1 || week > 53 || !Number.isInteger(year) || year < 2000 || year > 2100)
    return res.status(400).json({ error: `Tuần/năm không hợp lệ (nhận được tuần ${req.body.week_number}, năm ${req.body.year})` });
  if (!['daily', 'duty'].includes(mode)) return res.status(400).json({ error: 'Loại lịch không hợp lệ (cần "daily" hoặc "duty")' });
  if (!rows.length && mode === 'duty') return res.status(400).json({ error: 'File không có dòng lịch nào để nhập' });
  try {
    const officers = (await db.execute('SELECT full_name, max_shifts FROM officers')).rows;
    const norm = n => String(n || '').trim().replace(/\s+/g, ' ');
    const byName = new Map(officers.map(o => [norm(o.full_name).toLowerCase(), o]));
    const fold = n => norm(n).normalize('NFD').replace(/[\u0300-\u036f]/g, '').replace(/đ/g, 'd').replace(/Đ/g, 'D').toLowerCase();
    // Khớp tên: đúng họ tên -> đúng không phân biệt dấu (nếu duy nhất) -> chỉ ghi tên/các chữ cuối của họ tên (nếu duy nhất)
    const known = n => {
      const e = byName.get(norm(n).toLowerCase()); if (e) return e;
      const f = fold(n); if (!f) return undefined;
      const a = officers.filter(o => fold(o.full_name) === f); if (a.length === 1) return a[0];
      const w = f.split(' ').filter(Boolean); if (w.join('').length < 2) return undefined;
      const s2 = officers.filter(o => { const ow = fold(o.full_name).split(' '); return ow.length >= w.length && w.every((t, i) => ow[ow.length - w.length + i] === t); });
      return s2.length === 1 ? s2[0] : undefined;
    };
    const stmts = [], unknown = new Set(), zeroMax = new Set(), warnings = [];
    let count = 0, replaced = 0;
    const seen = new Set();
    if (mode === 'daily') {
      let groups = (Array.isArray(req.body.groups) ? req.body.groups : []).map(normalizeGroup).filter(Boolean);
      if (!groups.length) groups = rows.map(r => normalizeGroup(r.group_name)).filter(Boolean);
      groups = [...new Set(groups)];
      if (!groups.length) return res.status(400).json({ error: 'Không nhận diện được tổ nào trong file (cột đầu tiên cần ghi tên tổ: CHỈ HUY, TỔ TỔNG HỢP, TỔ AN NINH, TỔ CSKV, TỔ PCTP, TỔ CSTT)' });
      const old = await db.execute({ sql: `SELECT COUNT(*) AS c FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name IN (${groups.map(() => '?').join(',')})`, args: [week, year, ...groups] });
      replaced = Number(old.rows[0].c);
      groups.forEach(g => stmts.push({ sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ?', args: [week, year, g] }));
      rows.forEach(r => {
        const d = Number(r.day_index), g = normalizeGroup(r.group_name), o = known(r.officer_name);
        if (!o) { unknown.add(norm(r.officer_name)); return; }
        if (!(d >= 0 && d <= 6) || !g || !groups.includes(g)) return;
        const k = `${g}|${d}|${o.full_name}`; if (seen.has(k)) return; seen.add(k); // 1 người/1 tổ/1 ngày chỉ ghi 1 lần
        stmts.push({ sql: 'INSERT INTO daily_schedule (week_number, year, day_index, date_str, group_name, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week, year, d, dateStr(year, week, d), g, o.full_name] });
        count++;
      });
      groups.forEach(g => stmts.push({ sql: `INSERT INTO submissions (week_number, year, group_name, submitted_by, submitted_at) VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(week_number, year, group_name) DO UPDATE SET submitted_by = excluded.submitted_by, submitted_at = excluded.submitted_at`,
        args: [week, year, g, req.session.user.username + ' (nhập Word)', new Date().toISOString()] }));
      if (!count && !groups.length) return res.status(400).json({ error: 'Không có dòng hợp lệ để nhập' });
    } else {
      replaced = Number((await db.execute({ sql: 'SELECT COUNT(*) AS c FROM duty_schedule WHERE week_number = ? AND year = ?', args: [week, year] })).rows[0].c);
      stmts.push({ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [week, year] });
      const ctx = await loadDutyContext(week, year), accepted = [];
      for (const r of rows) {
        const d = Number(r.day_index), sh = String(r.shift || ''), o = known(r.officer_name);
        if (!o) { unknown.add(norm(r.officer_name)); continue; }
        if (!(d >= 0 && d <= 6) || !['Ca1', 'Ca2', 'Ca3'].includes(sh)) continue;
        if (Number(o.max_shifts == null ? 2 : o.max_shifts) < 1) { zeroMax.add(o.full_name); continue; } // max=0: tuyệt đối không phân trực ban
        const k = `${d}|${sh}`; if (seen.has(k)) continue; seen.add(k);
        accepted.push({ day_index: d, shift: sh, officer_name: o.full_name });
        stmts.push({ sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week, year, d, dateStr(year, week, d), sh, o.full_name] });
        count++;
      }
      warnings.push(...validateAssignments(ctx, accepted)); // lịch có sẵn từ bên ngoài: vẫn ghi nhận nhưng cảnh báo vi phạm để admin kiểm tra
      if (!count) {
        const parts = [];
        if (unknown.size) parts.push(`${unknown.size} tên không khớp danh sách cán bộ (${[...unknown].slice(0, 8).join(', ')})`);
        if (zeroMax.size) parts.push(`${zeroMax.size} người có số ca tối đa = 0 (${[...zeroMax].join(', ')})`);
        return res.status(400).json({ error: 'Không có dòng hợp lệ để nhập' + (parts.length ? ': ' + parts.join('; ') : '') + '. Dữ liệu cũ được giữ nguyên.' });
      }
    }
    await db.batch(stmts, 'write'); // xoá cũ + ghi mới cùng 1 giao dịch
    userCache.clear();
    res.json({ success: true, count, replaced, week, year, unknown: [...unknown], zero_max: [...zeroMax], warnings: [...new Set(warnings)].slice(0, 20) });
  } catch (err) {
    console.error('Lỗi nhập lịch Word:', err);
    res.status(500).json({ error: 'Không thể lưu lịch vào cơ sở dữ liệu: ' + (err && err.message ? err.message : 'lỗi không xác định') });
  }
});

// Xoá toàn bộ lịch trực ban của 1 tuần
app.delete('/api/duty', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [Number(req.query.week_number), Number(req.query.year)] });
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể xóa lịch trực ban' }); }
});


// ================= RÀNG BUỘC TRỰC BAN THEO NGÀY/CA =================
// Ràng buộc riêng của tuần (week_number, year) hoặc mặc định (0, 0). Tuần chưa cài riêng sẽ dùng mặc định.

async function effectiveRules(week, year) {
  const own = Number((await db.execute({ sql: 'SELECT COUNT(*) AS c FROM duty_rules WHERE week_number = ? AND year = ?', args: [week, year] })).rows[0].c) > 0;
  const sc = own ? [week, year] : [0, 0];
  const rows = (await db.execute({
    sql: 'SELECT r.*, o.full_name FROM duty_rules r JOIN officers o ON o.id = r.officer_id WHERE r.week_number = ? AND r.year = ?', args: sc
  })).rows;
  return { source: own ? 'week' : (rows.length ? 'default' : 'none'), rows };
}

app.get('/api/rules', requireAdmin, async (req, res) => {
  const er = await effectiveRules(Number(req.query.week_number), Number(req.query.year));
  res.json({ source: er.source, rules: er.rows.map(r => ({ officer_id: Number(r.officer_id), officer_name: r.full_name, day_index: Number(r.day_index), shift: Number(r.shift), rule: r.rule })) });
});

// Lưu ràng buộc của 1 cán bộ trong 1 tuần
app.put('/api/rules/officer', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year), oid = Number(req.body.officer_id);
  if (!week || !year || !oid) return res.status(400).json({ error: 'Dữ liệu không hợp lệ' });
  try {
    const own = Number((await db.execute({ sql: 'SELECT COUNT(*) AS c FROM duty_rules WHERE week_number = ? AND year = ?', args: [week, year] })).rows[0].c) > 0;
    const ins = 'INSERT INTO duty_rules (week_number, year, officer_id, day_index, shift, rule) VALUES (?, ?, ?, ?, ?, ?)';
    const stmts = [];
    if (!own) { // tuần chưa cài riêng: sao chép mặc định sang tuần này rồi mới sửa
      const def = (await db.execute('SELECT officer_id, day_index, shift, rule FROM duty_rules WHERE week_number = 0 AND year = 0 AND officer_id > 0')).rows;
      def.forEach(r => stmts.push({ sql: ins, args: [week, year, r.officer_id, r.day_index, r.shift, r.rule] }));
      stmts.push({ sql: ins, args: [week, year, 0, 0, 0, 'marker'] }); // đánh dấu tuần đã có cài riêng
    }
    stmts.push({ sql: 'DELETE FROM duty_rules WHERE week_number = ? AND year = ? AND officer_id = ?', args: [week, year, oid] });
    const cleanCells = [];
    (req.body.cells || []).forEach(c => {
      const d = Number(c.day_index), sh = Number(c.shift);
      if (d >= 0 && d <= 6 && sh >= 1 && sh <= 3 && ['block', 'force'].includes(c.rule)) {
        cleanCells.push({ d, sh, rule: c.rule });
        stmts.push({ sql: ins, args: [week, year, oid, d, sh, c.rule] });
      }
    });
    if (req.body.set_default) {
      stmts.push({ sql: 'DELETE FROM duty_rules WHERE week_number = 0 AND year = 0 AND officer_id = ?', args: [oid] });
      cleanCells.forEach(c => stmts.push({ sql: ins, args: [0, 0, oid, c.d, c.sh, c.rule] }));
    }
    await db.batch(stmts, 'write');
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu ràng buộc' }); }
});

// Đặt ràng buộc của tuần này làm mặc định cho các tuần tiếp theo (tuần nào chưa cài riêng sẽ dùng)
app.post('/api/rules/default', requireAdmin, async (req, res) => {
  try {
    const er = await effectiveRules(Number(req.body.week_number), Number(req.body.year));
    const stmts = [{ sql: 'DELETE FROM duty_rules WHERE week_number = 0 AND year = 0', args: [] }];
    er.rows.forEach(r => stmts.push({ sql: 'INSERT INTO duty_rules (week_number, year, officer_id, day_index, shift, rule) VALUES (0, 0, ?, ?, ?, ?)', args: [r.officer_id, r.day_index, r.shift, r.rule] }));
    await db.batch(stmts, 'write');
    res.json({ success: true, count: er.rows.length });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể đặt mặc định' }); }
});

// Bỏ cài riêng của tuần, quay về dùng mặc định
app.delete('/api/rules', requireAdmin, async (req, res) => {
  await db.execute({ sql: 'DELETE FROM duty_rules WHERE week_number = ? AND year = ?', args: [Number(req.query.week_number), Number(req.query.year)] });
  res.json({ success: true });
});

// Danh sách ràng buộc ngầm + trạng thái bật/tắt (áp dụng cho mọi tuần)
app.get('/api/constraints', requireAdmin, async (req, res) => {
  const off = await loadDisabled();
  res.json(CONSTRAINTS.map(c => ({ ...c, enabled: !off.has(c.id) })));
});
// Body: { id, enabled } để đổi 1 ràng buộc, hoặc { reset: true } để bật lại tất cả
app.put('/api/constraints', requireAdmin, async (req, res) => {
  try {
    const off = await loadDisabled();
    if (req.body.reset) off.clear();
    else {
      const id = String(req.body.id || '');
      if (!CONSTRAINTS.some(c => c.id === id)) return res.status(400).json({ error: 'Ràng buộc không hợp lệ' });
      if (req.body.enabled) off.delete(id); else off.add(id);
    }
    await db.execute({ sql: "INSERT INTO app_settings (key, value) VALUES ('disabled_constraints', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", args: [JSON.stringify([...off])] });
    res.json({ success: true, disabled: [...off] });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu ràng buộc' }); }
});

const PORT = process.env.PORT || 3000;
initDB()
  .then(() => app.listen(PORT, () => console.log(`Server CAX đang chạy tại port ${PORT}`)))
  .catch(err => { console.error('Lỗi khởi tạo CSDL:', err); process.exit(1); });
