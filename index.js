const express = require('express');
const path = require('path');
const mysql = require('mysql2');
const crypto = require('crypto');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = 3300;

// Middleware
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

// --- ROUTES USER ---

// 1. Generate API Key & Daftar User Baru
app.post('/api/register-user', (req, res) => {
    const { nama_depan, nama_belakang, email } = req.body;
    const apiKey = `sk-${crypto.randomBytes(16).toString('hex')}`;

    // --- LOGIKA BARU: Hitung Tanggal Expired (Sekarang + 30 Hari) ---
    const now = new Date();
    const expiredDate = new Date(now);
    expiredDate.setDate(now.getDate() + 30); // Tambah 30 hari
    // ----------------------------------------------------------------

    // Query 1: Simpan User
    const queryUser = 'INSERT INTO registered_users (nama_depan, nama_belakang, email, api_key) VALUES (?, ?, ?, ?)';
    
    db.query(queryUser, [nama_depan, nama_belakang, email, apiKey], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Email mungkin sudah terdaftar.' });
        }

        // Query 2: Simpan API Key + Tanggal Expired
        const queryKey = 'INSERT INTO api_keys (api_key, expired_at) VALUES (?, ?)';
        db.query(queryKey, [apiKey, expiredDate], (errKey, resultKey) => {
            if (errKey) console.error('Gagal simpan api_keys:', errKey);
            
            console.log(`✅ User ${nama_depan} daftar. Expired: ${expiredDate}`);
            res.json({ success: true, apiKey: apiKey });
        });
    });
});

// --- ROUTES ADMIN ---

app.post('/api/admin/register', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const query = 'INSERT INTO admin_users (email, password_hash) VALUES (?, ?)';
    db.query(query, [email, hashedPassword], (err, result) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const query = 'SELECT * FROM admin_users WHERE email = ? AND password_hash = ?';
    db.query(query, [email, hashedPassword], (err, results) => {
        if (err) throw err;
        if (results.length > 0) res.json({ success: true });
        else res.status(401).json({ success: false });
    });
});

// 4. Ambil Data Dashboard (Updated Logic)
app.get('/api/users', (req, res) => {
    // Kita perlu join tabel supaya bisa lihat tanggal expired dari tabel api_keys
    const query = `
        SELECT u.*, k.expired_at, k.is_active
        FROM registered_users u
        LEFT JOIN api_keys k ON u.api_key = k.api_key
        ORDER BY u.reg_date DESC
    `;
    
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);

        const now = new Date();
        const usersWithStatus = results.map(user => {
            let status = 'Aktif';
            
            // Cek 1: Apakah status manualnya dimatikan (is_active = 0)?
            if (user.is_active === 0) {
                status = 'Tidak Aktif';
            } 
            // Cek 2: Apakah tanggal sekarang sudah melewati tanggal expired?
            else if (user.expired_at && now > new Date(user.expired_at)) {
                status = 'Expired';
            }

            return {
                ...user,
                status_key: status
            };
        });

        res.json(usersWithStatus);
    });
});

app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'DELETE FROM registered_users WHERE id = ?';
    db.query(query, [userId], (err, result) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin-register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.listen(port, () => {
    console.log(`🚀 Server jalan di http://localhost:${port}`);
});