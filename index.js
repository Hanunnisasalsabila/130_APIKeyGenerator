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

// Koneksi Database (Pake Env atau Default)
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

// --- ROUTES USER (HALAMAN DEPAN) ---

// 1. Generate API Key & Daftar User Baru
app.post('/api/register-user', (req, res) => {
    const { nama_depan, nama_belakang, email } = req.body;
    
    // Generate API Key Random
    const apiKey = `sk-${crypto.randomBytes(16).toString('hex')}`;

    // QUERY 1: Simpan ke tabel registered_users (Data Lengkap)
    const queryUser = 'INSERT INTO registered_users (nama_depan, nama_belakang, email, api_key) VALUES (?, ?, ?, ?)';
    
    db.query(queryUser, [nama_depan, nama_belakang, email, apiKey], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Email mungkin sudah terdaftar.' });
        }

        // QUERY 2: Simpan JUGA ke tabel api_keys (Biar mirip punya temanmu)
        const queryKey = 'INSERT INTO api_keys (api_key) VALUES (?)';
        db.query(queryKey, [apiKey], (errKey, resultKey) => {
            if (errKey) {
                console.error('Gagal simpan ke tabel api_keys:', errKey);
                // Kita tidak return error disini, karena user intinya sudah berhasil daftar
            }
            
            console.log(`✅ User ${nama_depan} berhasil daftar dengan key: ${apiKey}`);
            res.json({ success: true, apiKey: apiKey });
        });
    });
});

// --- ROUTES ADMIN ---

// 2. Admin Register (Hash Password)
app.post('/api/admin/register', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    const query = 'INSERT INTO admin_users (email, password_hash) VALUES (?, ?)';
    db.query(query, [email, hashedPassword], (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ success: false, message: 'Gagal register admin.' });
        }
        res.json({ success: true, message: 'Admin berhasil didaftarkan.' });
    });
});

// 3. Admin Login (Cek Hash)
app.post('/api/admin/login', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    const query = 'SELECT * FROM admin_users WHERE email = ? AND password_hash = ?';
    db.query(query, [email, hashedPassword], (err, results) => {
        if (err) throw err;
        
        if (results.length > 0) {
            res.json({ success: true, message: 'Login berhasil!' });
        } else {
            res.status(401).json({ success: false, message: 'Email atau password salah.' });
        }
    });
});

// 4. Ambil Data Dashboard
app.get('/api/users', (req, res) => {
    const query = 'SELECT * FROM registered_users ORDER BY reg_date DESC';
    
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err);

        const now = new Date();
        const usersWithStatus = results.map(user => {
            const regDate = new Date(user.reg_date);
            const diffTime = Math.abs(now - regDate);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
            
            return {
                ...user,
                status_key: diffDays > 30 ? 'Tidak Aktif' : 'Aktif'
            };
        });

        res.json(usersWithStatus);
    });
});

// 5. Hapus User
app.delete('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const query = 'DELETE FROM registered_users WHERE id = ?';
    db.query(query, [userId], (err, result) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true });
    });
});

// Routing HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin-login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/admin-register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));

app.listen(port, () => {
    console.log(`🚀 Server jalan di http://localhost:${port}`);
});