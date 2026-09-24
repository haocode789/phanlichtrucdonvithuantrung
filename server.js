const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const db = new Database('data.db');

// Khởi tạo bảng dữ liệu
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT, -- 'admin' hoặc 'member'
    group_name TEXT, -- Tên tổ công tác
    permissions TEXT -- JSON lưu các quyền tùy biến
  );

  CREATE TABLE IF NOT EXISTS officers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT UNIQUE,
    no_night_shift INTEGER DEFAULT 0 -- 1 nếu không trực được ca tối
  );

  CREATE TABLE IF NOT EXISTS daily_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    week_number INTEGER,
    year INTEGER,
    day_of_week TEXT, -- Thu2, Thu3, ... ChiNhat
    group_name TEXT,
    officer_name TEXT
  );

  CREATE TABLE IF NOT EXISTS duty_schedule (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    week_number INTEGER,
    year INTEGER,
    day_of_week TEXT,
    shift TEXT, -- Sang, Chieu, Toi
    officer_name TEXT
  );
`);

// Tạo tài khoản Admin mặc định nếu chưa có
const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('admin');
if (!adminExists) {
  db.prepare(`
    INSERT INTO users (username, password, role, group_name, permissions)
    VALUES (?, ?, ?, ?, ?)
  `).run('admin', 'admin123', 'admin', 'Ban Chỉ huy', JSON.stringify(['all']));
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'cax_secret_key_2026',
  resave: false,
  saveUninitialized: true
}));

// API Đăng nhập / Đăng xuất
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password = ?').get(username, password);
  if (user) {
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      group_name: user.group_name,
      permissions: JSON.parse(user.permissions || '[]')
    };
    return res.json({ success: true, user: req.session.user });
  }
  res.status(401).json({ success: false, message: 'Sai tài khoản hoặc mật khẩu' });
});

app.get('/api/me', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// --- ADMIN MANAGEMENT ---
// Tạo/quản lý tài khoản
app.get('/api/users', (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Deny' });
  const users = db.prepare('SELECT id, username, role, group_name, permissions FROM users').all();
  res.json(users);
});

app.post('/api/users', (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Deny' });
  const { username, password, role, group_name, permissions } = req.body;
  try {
    db.prepare(`
      INSERT INTO users (username, password, role, group_name, permissions)
      VALUES (?, ?, ?, ?, ?)
    `).run(username, password, role, group_name, JSON.stringify(permissions || []));
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Tài khoản đã tồn tại hoặc dữ liệu lỗi' });
  }
});

// Quản lý danh sách Cán bộ Công an xã
app.get('/api/officers', (req, res) => {
  const officers = db.prepare('SELECT * FROM officers ORDER BY full_name ASC').all();
  res.json(officers);
});

app.post('/api/officers', (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Deny' });
  const { full_name, no_night_shift } = req.body;
  try {
    db.prepare('INSERT INTO officers (full_name, no_night_shift) VALUES (?, ?)').run(full_name, no_night_shift ? 1 : 0);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: 'Cán bộ đã tồn tại' });
  }
});

// API Gợi ý tên cán bộ (Autocomplete)
app.get('/api/officers/search', (req, res) => {
  const q = req.query.q || '';
  const results = db.prepare('SELECT full_name FROM officers WHERE full_name LIKE ? LIMIT 10').all(`%${q}%`);
  res.json(results.map(r => r.full_name));
});

// --- TỔNG HỢP LỊCH TRỰC ---
// Gửi lịch trực tuần từ Tổ công tác
app.post('/api/schedule/submit', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { week_number, year, schedule } = req.body; 
  // schedule = { Thu2: ["Nguyễn Văn A", "Trần Văn B"], Thu3: [...] }
  const group_name = req.session.user.group_name;

  const deleteStmt = db.prepare('DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ?');
  const insertStmt = db.prepare('INSERT INTO daily_schedule (week_number, year, day_of_week, group_name, officer_name) VALUES (?, ?, ?, ?, ?)');

  const transaction = db.transaction(() => {
    deleteStmt.run(week_number, year, group_name);
    for (const [day, officers] of Object.entries(schedule)) {
      for (const name of officers) {
        if (name.trim()) {
          // Khớp chính xác tên trong DB nếu gõ tắt
          const matched = db.prepare('SELECT full_name FROM officers WHERE full_name LIKE ? LIMIT 1').get(`%${name.trim()}%`);
          const fullName = matched ? matched.full_name : name.trim();
          insertStmt.run(week_number, year, day, group_name, fullName);
        }
      }
    }
  });

  transaction();
  res.json({ success: true });
});

// Lấy lịch trực tổng hợp của cả đơn vị
app.get('/api/schedule/summary', (req, res) => {
  const { week_number, year } = req.query;
  const rows = db.prepare('SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?').all(week_number, year);
  res.json(rows);
});

// --- PHÂN LỊCH TRỰC BAN TỰ ĐỘNG ---
app.post('/api/duty/generate', (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Deny' });
  const { week_number, year } = req.body;

  const days = ['Thu2', 'Thu3', 'Thu4', 'Thu5', 'Thu6', 'Thu7', 'ChiNhat'];
  const shifts = ['Sang', 'Chieu', 'Toi'];

  // Lấy toàn bộ cán bộ trực trong tuần
  const availableOfficers = db.prepare('SELECT DISTINCT day_of_week, officer_name FROM daily_schedule WHERE week_number = ? AND year = ?').all(week_number, year);
  const officersInfo = db.prepare('SELECT * FROM officers').all();
  const officerMap = new Map(officersInfo.map(o => [o.full_name, o]));

  const deleteStmt = db.prepare('DELETE FROM duty_schedule WHERE week_number = ? AND year = ?');
  const insertStmt = db.prepare('INSERT INTO duty_schedule (week_number, year, day_of_week, shift, officer_name) VALUES (?, ?, ?, ?, ?)');

  const transaction = db.transaction(() => {
    deleteStmt.run(week_number, year);

    for (const day of days) {
      // Danh sách người trực ngày hôm đó
      const todaysOfficers = availableOfficers.filter(o => o.day_of_week === day).map(o => o.officer_name);
      if (todaysOfficers.length === 0) continue;

      let assignedForDay = [];

      for (const shift of shifts) {
        let candidate = null;

        if (shift === 'Sang') {
          // Bất kỳ ai trong danh sách trực ngày hôm đó
          candidate = todaysOfficers[Math.floor(Math.random() * todaysOfficers.length)];
        } else {
          // Ca Chiều và Tối: Ràng buộc PHẢI nằm trong danh sách trực ngày hôm đó
          let validCandidates = todaysOfficers.filter(name => {
            const info = officerMap.get(name);
            if (shift === 'Toi' && info && info.no_night_shift === 1) {
              return false; // Ràng buộc: Đồng chí A không trực ban ca tối
            }
            return true;
          });

          if (validCandidates.length > 0) {
            candidate = validCandidates[Math.floor(Math.random() * validCandidates.length)];
          }
        }

        if (candidate) {
          insertStmt.run(week_number, year, day, shift, candidate);
        }
      }
    }
  });

  transaction();
  res.json({ success: true, message: 'Đã phân lịch trực ban tự động thành công!' });
});

// Lấy lịch trực ban đã phân
app.get('/api/duty/summary', (req, res) => {
  const { week_number, year } = req.query;
  const rows = db.prepare('SELECT * FROM duty_schedule WHERE week_number = ? AND year = ?').all(week_number, year);
  res.json(rows);
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server CAX đang chạy tại http://localhost:${PORT}`);
});