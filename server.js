const express = require('express');
const session = require('express-session');
const { createClient } = require('@libsql/client');
const path = require('path');

const app = express();

// Kết nối Turso DB qua biến môi trường (Hoặc dùng file local.db khi chạy thử nghiệm ở local)
const db = createClient({
  url: process.env.TURSO_DATABASE_URL || 'file:local.db',
  authToken: process.env.TURSO_AUTH_TOKEN,
});

// Khởi tạo các bảng dữ liệu trên Turso DB
async function initDB() {
  try {
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT,
        group_name TEXT,
        permissions TEXT
      )
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS officers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT,
        gender TEXT,
        rank TEXT,
        position TEXT,
        group_name TEXT,
        no_night_shift INTEGER DEFAULT 0
      )
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS daily_schedule (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        week_number INTEGER,
        year INTEGER,
        day_index INTEGER,
        date_str TEXT,
        group_name TEXT,
        officer_name TEXT
      )
    `);

    await db.execute(`
      CREATE TABLE IF NOT EXISTS duty_schedule (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        week_number INTEGER,
        year INTEGER,
        day_index INTEGER,
        date_str TEXT,
        shift TEXT,
        officer_name TEXT
      )
    `);

    // Tạo tài khoản admin mặc định nếu chưa có
    const adminCheck = await db.execute({
      sql: 'SELECT * FROM users WHERE username = ?',
      args: ['admin']
    });

    if (adminCheck.rows.length === 0) {
      await db.execute({
        sql: `INSERT INTO users (username, password, role, group_name, permissions) VALUES (?, ?, ?, ?, ?)`,
        args: ['admin', 'admin123', 'admin', 'TỔ TỔNG HỢP', JSON.stringify(['all'])]
      });
    }
    console.log('Khởi tạo CSDL Turso thành công!');
  } catch (err) {
    console.error('Lỗi khởi tạo CSDL:', err);
  }
}

initDB();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// Phục vụ tĩnh giao diện từ thư mục public
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'cax_thuantrung_2026',
  resave: false,
  saveUninitialized: true
}));

// ================= API TÀI KHOẢN & PHIÊN ĐĂNG NHẬP =================

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM users WHERE username = ? AND password = ?',
      args: [username, password]
    });

    if (result.rows.length > 0) {
      const user = result.rows[0];
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        group_name: user.group_name || 'TỔ TỔNG HỢP'
      };
      return res.json({ success: true, user: req.session.user });
    }
    res.status(401).json({ success: false, message: 'Sai tài khoản hoặc mật khẩu' });
  } catch (err) {
    console.error('Lỗi login:', err);
    res.status(500).json({ error: 'Lỗi hệ thống' });
  }
});

app.get('/api/me', (req, res) => {
  res.json({ loggedIn: !!req.session.user, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// ================= API QUẢN LÝ CÁN BỘ =================

// Lấy danh sách toàn bộ cán bộ
app.get('/api/officers', async (req, res) => {
  try {
    const result = await db.execute('SELECT * FROM officers ORDER BY id DESC');
    res.json(result.rows || []);
  } catch (err) {
    console.error('Lỗi lấy danh sách cán bộ:', err);
    res.status(500).json({ error: 'Lỗi tải danh sách cán bộ' });
  }
});

// Thêm cán bộ mới
app.post('/api/officers', async (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Không có quyền truy cập' });
  const { full_name, gender, rank, position, group_name, no_night_shift } = req.body;
  
  if (!full_name || !full_name.trim()) {
    return res.status(400).json({ error: 'Vui lòng nhập Họ và Tên' });
  }

  try {
    const result = await db.execute({
      sql: 'INSERT INTO officers (full_name, gender, rank, position, group_name, no_night_shift) VALUES (?, ?, ?, ?, ?, ?)',
      args: [full_name.trim(), gender || 'Nam', rank || 'Đại úy', position || 'Cán bộ', group_name || 'TỔ TỔNG HỢP', no_night_shift ? 1 : 0]
    });
    res.json({ success: true, id: Number(result.lastInsertRowid) });
  } catch (err) {
    console.error('Lỗi thêm cán bộ:', err);
    res.status(500).json({ error: 'Không thể lưu cán bộ vào CSDL' });
  }
});

// Cập nhật thông tin cán bộ
app.put('/api/officers/:id', async (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Không có quyền truy cập' });
  const { full_name, gender, rank, position, group_name, no_night_shift } = req.body;
  
  try {
    await db.execute({
      sql: 'UPDATE officers SET full_name = ?, gender = ?, rank = ?, position = ?, group_name = ?, no_night_shift = ? WHERE id = ?',
      args: [full_name.trim(), gender, rank, position, group_name, no_night_shift ? 1 : 0, req.params.id]
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Lỗi cập nhật cán bộ:', err);
    res.status(500).json({ error: 'Lỗi cập nhật CSDL' });
  }
});

// Xóa cán bộ
app.delete('/api/officers/:id', async (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Không có quyền truy cập' });
  
  try {
    await db.execute({
      sql: 'DELETE FROM officers WHERE id = ?',
      args: [req.params.id]
    });
    res.json({ success: true });
  } catch (err) {
    console.error('Lỗi xóa cán bộ:', err);
    res.status(500).json({ error: 'Lỗi xóa CSDL' });
  }
});

// Tìm kiếm tên cán bộ (Autocomplete)
app.get('/api/officers/search', async (req, res) => {
  const q = req.query.q || '';
  try {
    const result = await db.execute({
      sql: 'SELECT full_name FROM officers WHERE full_name LIKE ? LIMIT 10',
      args: [`%${q}%`]
    });
    res.json((result.rows || []).map(r => r.full_name));
  } catch (err) {
    res.json([]);
  }
});

// ================= API LỊCH TRỰC CHIẾN TỔ =================

app.post('/api/schedule/submit', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const { week_number, year, group_name, days_data } = req.body;
  const targetGroup = group_name || req.session.user.group_name || 'TỔ TỔNG HỢP';

  try {
    const officerRows = await db.execute('SELECT full_name FROM officers');
    const allOfficers = (officerRows.rows || []).map(o => o.full_name);

    await db.execute({
      sql: 'DELETE FROM daily_schedule WHERE week_number = ? AND year = ? AND group_name = ?',
      args: [week_number, year, targetGroup]
    });

    const batchStatements = [];
    (days_data || []).forEach(item => {
      (item.officers || []).forEach(inputName => {
        if (inputName.trim()) {
          let matchedName = allOfficers.find(
            o => o.toLowerCase().includes(inputName.trim().toLowerCase()) || 
                 o.split(' ').pop().toLowerCase() === inputName.trim().toLowerCase()
          );
          const finalName = matchedName || inputName.trim();
          batchStatements.push({
            sql: 'INSERT INTO daily_schedule (week_number, year, day_index, date_str, group_name, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
            args: [week_number, year, item.day_index, item.date_str, targetGroup, finalName]
          });
        }
      });
    });

    if (batchStatements.length > 0) {
      await db.batch(batchStatements, 'write');
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Lỗi lưu lịch trực:', err);
    res.status(500).json({ error: 'Lỗi hệ thống khi lưu lịch trực' });
  }
});

app.get('/api/schedule/summary', async (req, res) => {
  const { week_number, year } = req.query;
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?',
      args: [week_number, year]
    });
    res.json(result.rows || []);
  } catch (err) {
    res.json([]);
  }
});

// ================= API PHÂN LỊCH TRỰC BAN TỰ ĐỘNG =================

app.post('/api/duty/generate', async (req, res) => {
  if (req.session.user?.role !== 'admin') return res.status(403).json({ error: 'Deny' });
  const { week_number, year } = req.body;

  try {
    const directDutyRes = await db.execute({
      sql: 'SELECT * FROM daily_schedule WHERE week_number = ? AND year = ?',
      args: [week_number, year]
    });
    const directDutyOfficers = directDutyRes.rows || [];

    const allOfficersRes = await db.execute('SELECT * FROM officers');
    const allOfficers = allOfficersRes.rows || [];
    const officerMap = new Map(allOfficers.map(o => [o.full_name, o]));

    await db.execute({
      sql: 'DELETE FROM duty_schedule WHERE week_number = ? AND year = ?',
      args: [week_number, year]
    });

    const batchStatements = [];

    for (let dayIdx = 0; dayIdx < 7; dayIdx++) {
      const dayItems = directDutyOfficers.filter(o => Number(o.day_index) === dayIdx);
      const dateStr = dayItems.length > 0 ? dayItems[0].date_str : '';
      const todaysDutyOfficers = dayItems.map(o => o.officer_name);

      let candidate1 = allOfficers.length > 0 ? allOfficers[Math.floor(Math.random() * allOfficers.length)].full_name : '';
      let candidate2 = '';
      let candidate3 = '';

      if (todaysDutyOfficers.length > 0) {
        candidate2 = todaysDutyOfficers[Math.floor(Math.random() * todaysDutyOfficers.length)];
        let validNightCandidates = todaysDutyOfficers.filter(name => {
          const info = officerMap.get(name);
          return !(info && Number(info.no_night_shift) === 1);
        });
        candidate3 = validNightCandidates.length > 0 ? validNightCandidates[Math.floor(Math.random() * validNightCandidates.length)] : candidate2;
      }

      if (candidate1) {
        batchStatements.push({
          sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week_number, year, dayIdx, dateStr, 'Ca1', candidate1]
        });
      }
      if (candidate2) {
        batchStatements.push({
          sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week_number, year, dayIdx, dateStr, 'Ca2', candidate2]
        });
      }
      if (candidate3) {
        batchStatements.push({
          sql: 'INSERT INTO duty_schedule (week_number, year, day_index, date_str, shift, officer_name) VALUES (?, ?, ?, ?, ?, ?)',
          args: [week_number, year, dayIdx, dateStr, 'Ca3', candidate3]
        });
      }
    }

    if (batchStatements.length > 0) {
      await db.batch(batchStatements, 'write');
    }

    res.json({ success: true, message: 'Đã phân lịch trực ban tự động!' });
  } catch (err) {
    console.error('Lỗi phân lịch trực ban:', err);
    res.status(500).json({ error: 'Không thể phân lịch trực ban' });
  }
});

app.get('/api/duty/summary', async (req, res) => {
  const { week_number, year } = req.query;
  try {
    const result = await db.execute({
      sql: 'SELECT * FROM duty_schedule WHERE week_number = ? AND year = ?',
      args: [week_number, year]
    });
    res.json(result.rows || []);
  } catch (err) {
    res.json([]);
  }
});

// Port tự động nhận từ Render (hoặc chạy port 3000 ở máy local)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server CAX đang chạy tại port ${PORT}`));