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

  try { await db.execute("ALTER TABLE officers ADD COLUMN allowed_shifts TEXT DEFAULT '1,2,3'"); } catch (e) {}
  try { await db.execute("ALTER TABLE officers ADD COLUMN max_shifts INTEGER DEFAULT 2"); } catch (e) {}
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
      group_name: normalizeGroup(u.group_name) || u.group_name || 'TỔ TỔNG HỢP',
      permissions: u.role === 'admin' ? ['all'] : (() => { try { return JSON.parse(u.permissions || '[]'); } catch (e) { return []; } })()
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
  const { full_name, gender, rank, position, group_name, allowed_shifts, max_shifts } = req.body;
  const allowed = String(allowed_shifts || '1,2,3'); const no_night_shift = !allowed.split(',').includes('3'); const maxS = Number.isFinite(Number(max_shifts)) ? Number(max_shifts) : 2;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    const r = await db.execute({
      sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift, allowed_shifts, max_shifts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      args: [full_name.trim(), gender || 'Nam', rank || 'Đại úy', position || 'Cán bộ', group_name || 'TỔ TỔNG HỢP', no_night_shift ? 1 : 0, allowed, maxS]
    });
    res.json({ success: true, id: Number(r.lastInsertRowid) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Không thể lưu cán bộ vào CSDL' });
  }
});

app.put('/api/officers/:id', requireAdmin, async (req, res) => {
  const { full_name, gender, rank, position, group_name, allowed_shifts, max_shifts } = req.body;
  const allowed = String(allowed_shifts || '1,2,3'); const no_night_shift = !allowed.split(',').includes('3'); const maxS = Number.isFinite(Number(max_shifts)) ? Number(max_shifts) : 2;
  if (!full_name || !full_name.trim()) return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  try {
    await db.execute({
      sql: 'UPDATE officers SET full_name = ?, gender = ?, rank = ?, position = ?, group_name = ?, no_night_shift = ?, allowed_shifts = ?, max_shifts = ? WHERE id = ?',
      args: [full_name.trim(), gender, rank, position, group_name, no_night_shift ? 1 : 0, allowed, maxS, req.params.id]
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

// Sinh nhiều phương án phân ca để admin chọn
app.post('/api/duty/generate', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  if (!week || !year) return res.status(400).json({ error: 'Tuần/năm không hợp lệ' });
  try {
    const duty = (await db.execute({ sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?', args: [week, year] })).rows;
    if (!duty.length) return res.status(400).json({ error: 'Chưa có tổ nào gửi lịch trực chiến cho tuần này' });
    const officers = (await db.execute('SELECT * FROM officers')).rows;
    if (!officers.length) return res.status(400).json({ error: 'Chưa có cán bộ nào trong danh sách' });
    const info = new Map(officers.map(o => [o.full_name, o]));
    const allowed = o => String((info.get(o) || {}).allowed_shifts || '1,2,3').split(',').map(Number);
    const maxOf = o => { const m = Number((info.get(o) || {}).max_shifts); return Number.isFinite(m) ? m : 2; };
    const pool = officers.filter(o => allowed(o.full_name).length).map(o => o.full_name);

    // Ca đã trực tuần trước
    const ps = isoWeekStart(year, week); ps.setUTCDate(ps.getUTCDate() - 7);
    const pw = isoWeekOf(ps);
    const prevRows = (await db.execute({ sql: 'SELECT officer_name, shift FROM duty_schedule WHERE week_number = ? AND year = ?', args: [pw.week, pw.year] })).rows;
    const prev = new Map();
    prevRows.forEach(r => { if (!prev.has(r.officer_name)) prev.set(r.officer_name, new Set()); prev.get(r.officer_name).add(Number(String(r.shift).slice(2))); });

    const attempt = () => {
      const load = new Map(); const asg = []; const warns = []; let score = 0; let prevCa3 = '';
      for (let d = 0; d < 7; d++) {
        const ds = dateStr(year, week, d);
        const onDuty = [...new Set(duty.filter(r => Number(r.day_index) === d).map(r => r.officer_name))];
        if (!onDuty.length) warns.push(`Ngày ${ds}: chưa có lịch trực chiến`);
        const used = new Set(); let ca3 = '';
        for (const sh of [3, 2, 1]) {
          const needDuty = onDuty.length > 0 && (sh !== 1 || d >= 5); // T7, CN: cả 3 ca lấy từ người trực chiến
          let name = '', lvl = 0;
          for (; lvl < 4 && !name; lvl++) {
            let best = Infinity;
            for (const o of pool) {
              if (used.has(o)) continue;
              if (needDuty && !onDuty.includes(o)) continue;
              if (lvl < 3 && !allowed(o).includes(sh)) continue;
              if (lvl < 1 && (load.get(o) || 0) >= maxOf(o)) continue;
              if (lvl < 2 && sh === 1 && o === prevCa3) continue;
              const p = ((prev.get(o) || new Set()).has(sh) ? 10 : 0) + (load.get(o) || 0) * 2 + Math.random() * 3;
              if (p < best) { best = p; name = o; }
            }
          }
          lvl--;
          if (name) {
            if ((prev.get(name) || new Set()).has(sh)) { score += 10; warns.push(`Ngày ${ds} ca ${sh}: ${name} trùng số ca với tuần trước`); }
            if (lvl > 0) { score += lvl * 100; warns.push(`Ngày ${ds} ca ${sh}: ${name} vượt ràng buộc (số ca tối đa/ca được phép)`); }
            used.add(name); load.set(name, (load.get(name) || 0) + 1);
            if (sh === 3) ca3 = name;
            asg.push({ day_index: d, date_str: ds, shift: 'Ca' + sh, officer_name: name });
          } else { score += 500; warns.push(`Ngày ${ds} ca ${sh}: không xếp được`); }
        }
        prevCa3 = ca3;
      }
      const vals = [...load.values()]; const avg = vals.reduce((a, b) => a + b, 0) / (vals.length || 1);
      score += vals.reduce((a, b) => a + (b - avg) ** 2, 0);
      return { score: Math.round(score * 10) / 10, warnings: [...new Set(warns)], assignments: asg };
    };

    const opts = []; const seen = new Set();
    for (let t = 0; t < 80; t++) {
      const r = attempt();
      const sig = r.assignments.map(x => x.officer_name).join('|');
      if (seen.has(sig)) continue;
      seen.add(sig); opts.push(r);
    }
    opts.sort((a, b) => a.score - b.score);
    res.json({ success: true, options: opts.slice(0, 3) });
  } catch (err) {
    console.error('Lỗi phân lịch trực ban:', err);
    res.status(500).json({ error: 'Không thể phân lịch trực ban' });
  }
});

app.post('/api/duty/apply', requireAdmin, async (req, res) => {
  const week = Number(req.body.week_number), year = Number(req.body.year);
  const list = Array.isArray(req.body.assignments) ? req.body.assignments : [];
  try {
    const stmts = [{ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [week, year] }];
    list.forEach(a => {
      if (!a.officer_name || !['Ca1', 'Ca2', 'Ca3'].includes(a.shift)) return;
      stmts.push({ sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
        args: [week, year, Number(a.day_index), dateStr(year, week, Number(a.day_index)), a.shift, String(a.officer_name)] });
    });
    await db.batch(stmts, 'write');
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể lưu phương án' }); }
});

// Admin sửa 1 ô lịch trực ban
app.put('/api/duty/cell', requireAdmin, async (req, res) => {
  const { week_number, year, day_index, shift, officer_name } = req.body;
  if (!['Ca1', 'Ca2', 'Ca3'].includes(shift)) return res.status(400).json({ error: 'Ca không hợp lệ' });
  try {
    const stmts = [{ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ? AND day_index = ? AND shift = ?', args: [week_number, year, day_index, shift] }];
    const name = String(officer_name || '').trim();
    if (name) stmts.push({ sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
      args: [week_number, year, day_index, dateStr(Number(year), Number(week_number), Number(day_index)), shift, name] });
    await db.batch(stmts, 'write');
    res.json({ success: true });
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
    const cur = (await db.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [req.params.id] })).rows[0];
    if (!cur) return res.status(404).json({ error: 'Không tìm thấy tài khoản' });
    const newRole = role ? (role === 'admin' ? 'admin' : 'member') : cur.role;
    if (Number(cur.id) === req.session.user.id && newRole !== 'admin') return res.status(400).json({ error: 'Không thể tự hạ quyền admin của chính mình' });
    await db.execute({ sql: 'UPDATE users SET password = ?, group_name = ?, role = ?, permissions = ? WHERE id = ?',
      args: [password ? hashPw(String(password)) : cur.password, group_name ? (normalizeGroup(group_name) || cur.group_name) : cur.group_name, newRole,
             permissions ? JSON.stringify(cleanPerms(permissions)) : cur.permissions, req.params.id] });
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể cập nhật tài khoản' }); }
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  if (Number(req.params.id) === req.session.user.id) return res.status(400).json({ error: 'Không thể xóa chính mình' });
  await db.execute({ sql: 'DELETE FROM users WHERE id = ?', args: [req.params.id] });
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


// Nhập hàng loạt cán bộ (từ file Word) — bỏ qua người trùng tên
app.post('/api/officers/bulk', requireAdmin, async (req, res) => {
  const list = Array.isArray(req.body.officers) ? req.body.officers : [];
  if (!list.length) return res.status(400).json({ error: 'Không có dữ liệu để nhập' });
  try {
    const exist = new Set((await db.execute('SELECT full_name FROM officers')).rows.map(o => String(o.full_name).trim().toLowerCase()));
    const stmts = []; let skipped = 0;
    list.forEach(o => {
      const name = String(o.full_name || '').trim().replace(/\s+/g, ' ');
      if (!name || exist.has(name.toLowerCase())) { skipped++; return; }
      exist.add(name.toLowerCase());
      const allowed = String(o.allowed_shifts || '1,2,3');
      const mx = Number.isFinite(Number(o.max_shifts)) ? Number(o.max_shifts) : 2;
      stmts.push({
        sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift, allowed_shifts, max_shifts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        args: [name, o.gender === 'Nữ' ? 'Nữ' : 'Nam', o.rank || 'Đại úy', o.position || 'Cán bộ', normalizeGroup(o.group_name) || 'TỔ TỔNG HỢP', allowed.split(',').includes('3') ? 0 : 1, allowed, mx]
      });
    });
    if (stmts.length) await db.batch(stmts, 'write');
    res.json({ success: true, added: stmts.length, skipped });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể nhập danh sách cán bộ' }); }
});

// Xoá toàn bộ lịch trực ban của 1 tuần
app.delete('/api/duty', requireAdmin, async (req, res) => {
  try {
    await db.execute({ sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?', args: [Number(req.query.week_number), Number(req.query.year)] });
    res.json({ success: true });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Không thể xóa lịch trực ban' }); }
});

const PORT = process.env.PORT || 3000;
initDB()
  .then(() => app.listen(PORT, () => console.log(`Server CAX đang chạy tại port ${PORT}`)))
  .catch(err => { console.error('Lỗi khởi tạo CSDL:', err); process.exit(1); });
