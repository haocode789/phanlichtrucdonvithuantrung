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

const GROUPS = ['CHỈ HUY', 'TỔ TỔNG HỢP', 'TỔ CSTT', 'TỔ PCTP', 'TỔ CSKV', 'TỔ AN NINH'];

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

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Phiên đăng nhập đã hết hạn, vui lòng đăng nhập lại' });
  next();
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
        args: [username, hashPw(process.env.DEFAULT_MEMBER_PASSWORD || 'cax@2026'), 'member', grp, JSON.stringify(['submit'])]
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

app.use(express.json());
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
    req.session.user = {
      id: Number(u.id),
      username: u.username,
      role: u.role,
      group_name: normalizeGroup(u.group_name) || u.group_name || 'TỔ TỔNG HỢP'
    };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    console.error('Lỗi login:', err);
    res.status(500).json({ error: 'Lỗi hệ thống' });
  }
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
  const { full_name, gender, rank, position, group_name, no_night_shift } = req.body;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    const r = await db.execute({
      sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift) VALUES (?, ?, ?, ?, ?, ?)',
      args: [full_name.trim(), gender || 'Nam', rank || 'Đại úy', position || 'Cán bộ', group_name || 'TỔ TỔNG HỢP', no_night_shift ? 1 : 0]
    });
    res.json({ success: true, id: Number(r.lastInsertRowid) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Không thể lưu cán bộ vào CSDL' });
  }
});

app.put('/api/officers/:id', requireAdmin, async (req, res) => {
  const { full_name, gender, rank, position, group_name, no_night_shift } = req.body;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    await db.execute({
      sql: 'UPDATE officers SET full_name = ?, gender = ?, rank = ?, position = ?, group_name = ?, no_night_shift = ? WHERE id = ?',
      args: [full_name.trim(), gender, rank, position, group_name, no_night_shift ? 1 : 0, req.params.id]
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

app.post('/api/schedule/submit', requireLogin, async (req, res) => {
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

app.get('/api/schedule/summary', requireLogin, async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});

// Tổ nào đã gửi lịch, ai gửi, lúc nào
app.get('/api/schedule/status', requireLogin, async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT group_name, submitted_by, submitted_at FROM submissions WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});

// ================= PHÂN LỊCH TRỰC BAN =================

app.post('/api/duty/generate', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  if (!week || !year) return res.status(400).json({ error: 'Tuần/năm không hợp lệ' });

  try {
    const duty = (await db.execute({
      sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?', args: [week, year]
    })).rows;
    if (!duty.length) return res.status(400).json({ error: 'Chưa có tổ nào gửi lịch trực chiến cho tuần này' });

    const officers = (await db.execute('SELECT * FROM officers')).rows;
    const info = new Map(officers.map(o => [o.full_name, o]));
    const noNight = n => Number((info.get(n) || {}).no_night_shift) === 1;
    const pool = officers.map(o => o.full_name);

    const load = new Map(), nightLoad = new Map();
    const inc = (m, n) => m.set(n, (m.get(n) || 0) + 1);
    // Chọn người có số ca ít nhất (ngẫu nhiên khi bằng nhau) để chia đều
    const pick = (cands, score) => {
      if (!cands.length) return '';
      const s = [...cands].sort(() => Math.random() - 0.5);
      s.sort((a, b) => score(a) - score(b));
      return s[0];
    };

    const warnings = [];
    const stmts = [{ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [week, year] }];
    let prevCa3 = '';

    for (let d = 0; d < 7; d++) {
      const ds = dateStr(year, week, d);
      const onDuty = [...new Set(duty.filter(r => Number(r.day_index) === d).map(r => r.officer_name))];
      let ca3 = '', ca2 = '';

      if (!onDuty.length) {
        warnings.push(`Ngày ${ds}: chưa có ai trong lịch trực chiến nên chưa xếp được ca 2 và ca 3.`);
      } else {
        // Ca 3 (đêm): trong danh sách trực, không thuộc diện "không trực đêm"
        ca3 = pick(onDuty.filter(n => !noNight(n)), n => (nightLoad.get(n) || 0) * 10 + (load.get(n) || 0));
        if (!ca3) {
          ca3 = pick(onDuty, n => (nightLoad.get(n) || 0) * 10 + (load.get(n) || 0));
          warnings.push(`Ngày ${ds}: mọi người trực chiến đều bị ràng buộc không trực đêm, vẫn phải xếp ${ca3} vào ca 3.`);
        }
        // Ca 2: trong danh sách trực, khác người trực ca 3
        ca2 = pick(onDuty.filter(n => n !== ca3), n => load.get(n) || 0);
        if (!ca2) {
          ca2 = ca3;
          warnings.push(`Ngày ${ds}: chỉ có 1 người trực chiến (${ca3}) nên phải xếp cả ca 2 và ca 3.`);
        }
      }

      // Ca 1: cán bộ bất kỳ, khác ca 2/ca 3 hôm nay và không phải người vừa trực ca 3 đêm trước
      let ca1 = pick(pool.filter(n => n !== ca2 && n !== ca3 && n !== prevCa3), n => load.get(n) || 0)
             || pick(pool.filter(n => n !== ca2 && n !== ca3), n => load.get(n) || 0)
             || pick(pool, n => load.get(n) || 0);

      [['Ca1', ca1], ['Ca2', ca2], ['Ca3', ca3]].forEach(([shift, name]) => {
        if (!name) return;
        inc(load, name);
        if (shift === 'Ca3') inc(nightLoad, name);
        stmts.push({
          sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week, year, d, ds, shift, name]
        });
      });
      prevCa3 = ca3;
    }

    await db.batch(stmts, 'write');
    res.json({ success: true, message: 'Đã phân lịch trực ban tự động!', warnings });
  } catch (err) {
    console.error('Lỗi phân lịch trực ban:', err);
    res.status(500).json({ error: 'Không thể phân lịch trực ban' });
  }
});

app.get('/api/duty/summary', requireLogin, async (req, res) => {
  try {
    const r = await db.execute({
      sql: 'SELECT * FROM duty_schedule WHERE week_number = ? AND year = ?',
      args: [Number(req.query.week_number), Number(req.query.year)]
    });
    res.json(r.rows || []);
  } catch (err) { res.json([]); }
});

const PORT = process.env.PORT || 3000;
initDB()
  .then(() => app.listen(PORT, () => console.log(`Server CAX đang chạy tại port ${PORT}`)))
  .catch(err => { console.error('Lỗi khởi tạo CSDL:', err); process.exit(1); });
