const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = 3300;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

// Koneksi Database
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'SachaFoxie8', 
    database: process.env.DB_NAME || 'apikey_db',
    port: process.env.DB_PORT || 3306
});

db.connect((err) => {
    if (err) console.error('❌ Gagal konek DB:', err);
    else console.log('✅ Terhubung ke MySQL');
});

// --- 1. REGISTER ADMIN ---
app.post('/api/admin/register', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const query = 'INSERT INTO admin_users (email, password_hash) VALUES (?, ?)';
    db.query(query, [email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Email sudah ada" });
        res.json({ success: true, message: "Admin berhasil didaftarkan!" });
    });
});

// --- 2. LOGIN ADMIN ---
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const query = 'SELECT * FROM admin_users WHERE email = ? AND password_hash = ?';
    db.query(query, [email, hashedPassword], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length > 0) res.json({ success: true, message: "Login berhasil!" });
        else res.status(401).json({ success: false, message: "Email/Password salah" });
    });
});

// --- 3. REGISTER USER & GENERATE KEY ---
app.post('/api/register-user', (req, res) => {
    const { nama_depan, nama_belakang, email } = req.body;
    const apiKey = `sk-${crypto.randomBytes(16).toString('hex')}`;
    
    const now = new Date();
    const expiredDate = new Date(now);
    expiredDate.setDate(now.getDate() + 30);

    const queryUser = 'INSERT INTO registered_users (nama_depan, nama_belakang, email, api_key) VALUES (?, ?, ?, ?)';
    
    db.query(queryUser, [nama_depan, nama_belakang, email, apiKey], (err, result) => {
        if (err) return res.status(500).json({ success: false, message: 'Email sudah terdaftar.' });

        const queryKey = 'INSERT INTO api_keys (api_key, expired_at) VALUES (?, ?)';
        db.query(queryKey, [apiKey, expiredDate], () => {
            res.json({ success: true, apiKey: apiKey, message: "User berhasil didaftarkan & Key digenerate!" });
        });
    });
});

// --- 4. USER LOGIN --- 
app.post('/api/user/login', (req, res) => {
    const { apiKey } = req.body;
    const query = `SELECT u.*, k.is_active FROM registered_users u JOIN api_keys k ON u.api_key = k.api_key WHERE u.api_key = ?`;

    db.query(query, [apiKey], (err, results) => {
        if (results.length > 0) {
            db.query('UPDATE registered_users SET last_login = NOW() WHERE api_key = ?', [apiKey]);
            res.json({ 
                success: true, 
                message: "Login User Berhasil!", 
                user: { nama: results[0].nama_depan, email: results[0].email }
            });
        } else {
            res.status(401).json({ success: false, message: "API Key Salah / User tidak ditemukan" });
        }
    });
});

// --- 5. VALIDATE KEY (Versi Simple) ---
app.post('/api/validate', (req, res) => {
    const { apiKey } = req.body;
    const query = `SELECT u.nama_depan, k.is_active, k.expired_at FROM registered_users u JOIN api_keys k ON u.api_key = k.api_key WHERE k.api_key = ?`;
    db.query(query, [apiKey], (err, results) => {
        if (results.length === 0) return res.json({ valid: false, message: 'Key tidak ditemukan' });
        const data = results[0];
        const now = new Date();
        if (data.is_active === 0) return res.json({ valid: false, message: 'Key non-aktif' });
        if (data.expired_at && now > new Date(data.expired_at)) return res.json({ valid: false, message: 'Key Expired' });
        db.query('UPDATE api_keys SET last_used = NOW() WHERE api_key = ?', [apiKey]);
        res.json({ valid: true, message: 'API Key Valid!', user: data.nama_depan });
    });
});

// --- 6. CHECK API LENGKAP (New! Sesuai Screenshot Teman) ---
app.post('/api/checkapi', (req, res) => {
    const { apiKey } = req.body;

    const query = `
        SELECT u.id, u.nama_depan, u.nama_belakang, u.email, u.last_login, k.created_at, k.is_active 
        FROM registered_users u 
        JOIN api_keys k ON u.api_key = k.api_key 
        WHERE k.api_key = ?
    `;

    db.query(query, [apiKey], (err, results) => {
        if (err) return res.status(500).json({ valid: false, message: 'Server Error' });

        if (results.length === 0) {
            return res.json({ valid: false, active: false, message: "API Key tidak ditemukan" });
        }

        const data = results[0];
        const isActive = data.is_active === 1;

        // Format respon persis seperti di foto temanmu
        res.json({
            valid: true,
            active: isActive,
            message: isActive ? "API Key valid dan aktif!" : "API Key tidak aktif",
            data: {
                id: data.id,
                created_at: data.created_at,
                last_login: data.last_login,
                user: {
                    nama: `${data.nama_depan} ${data.nama_belakang}`,
                    email: data.email
                }
            }
        });
    });
});

// --- ROUTING DASHBOARD ---
app.get('/api/users', (req, res) => {
    const query = `SELECT u.*, k.expired_at, k.is_active FROM registered_users u LEFT JOIN api_keys k ON u.api_key = k.api_key ORDER BY u.reg_date DESC`;
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);
        const now = new Date();
        const users = results.map(user => ({
            ...user,
            status_key: (user.is_active === 0) ? 'Tidak Aktif' : (user.expired_at && now > new Date(user.expired_at)) ? 'Expired' : 'Aktif'
        }));
        res.json(users);
    });
});

app.delete('/api/users/:id', (req, res) => {
    db.query('DELETE FROM registered_users WHERE id = ?', [req.params.id], (err) => {
        if(err) return res.status(500).json({success: false});
        res.json({success: true});
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin-register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.listen(port, () => {
    console.log(`🚀 Server jalan di http://localhost:${port}`);
});