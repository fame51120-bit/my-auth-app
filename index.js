require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

// 1. สมัครสมาชิก /signup
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        await db.execute('INSERT INTO users (name, email, password) VALUES (?,?,?)', [name, email, hashedPassword]);
        res.json({ message: 'สมัครสำเร็จ' });
    } catch (err) {
        res.status(400).json({ error: 'อีเมลซ้ำ' });
    }
});

// 2. เข้าสู่ระบบ /login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const [rows] = await db.execute('SELECT * FROM users WHERE email =?', [email]);
    if (rows.length === 0) return res.status(400).json({ error: 'ไม่เจอผู้ใช้' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: 'รหัสผ่านผิด' });

    const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET);
    res.json({ token });
});

// Middleware เช็ค Token
const auth = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'ต้องมี Token' });
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Token ไม่ถูกต้อง' });
    }
};

// 3. Route ที่ต้อง Login ก่อน /profile
app.get('/profile', auth, async (req, res) => {
    const [rows] = await db.execute('SELECT id, name, email, role FROM users WHERE id =?', [req.user.id]);
    res.json(rows[0]);
});

app.listen(3000, () => console.log('Server