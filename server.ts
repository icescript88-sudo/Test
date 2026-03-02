import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const db = new Database("school.db");
const JWT_SECRET = "impagme-secret-key-2024";

// Initialize Database Schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT, -- admin, teacher, student, finance
    profile_id INTEGER
  );

  CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    registration_no TEXT UNIQUE,
    name TEXT,
    bi TEXT UNIQUE,
    dob TEXT,
    guardian TEXT,
    contact TEXT,
    address TEXT,
    status TEXT DEFAULT 'Ativo'
  );

  CREATE TABLE IF NOT EXISTS staff (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    bi TEXT UNIQUE,
    role TEXT, -- Secretário, Limpeza, Segurança, etc.
    contact TEXT
  );

  CREATE TABLE IF NOT EXISTS teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    bi TEXT UNIQUE,
    contact TEXT,
    degree TEXT
  );

  CREATE TABLE IF NOT EXISTS classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    year TEXT,
    shift TEXT -- Manhã, Tarde, Noite
  );

  CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT
  );

  CREATE TABLE IF NOT EXISTS class_students (
    class_id INTEGER,
    student_id INTEGER,
    PRIMARY KEY (class_id, student_id)
  );

  CREATE TABLE IF NOT EXISTS class_teachers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    class_id INTEGER,
    teacher_id INTEGER,
    subject_id INTEGER
  );

  CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    subject_id INTEGER,
    class_id INTEGER,
    period TEXT, -- T1, T2, T3
    score REAL
  );

  CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    amount REAL,
    date TEXT,
    month TEXT,
    type TEXT, -- Propina, Matrícula, Multa
    receipt_no TEXT UNIQUE
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER,
    class_id INTEGER,
    date TEXT,
    status TEXT -- Presente, Falta
  );
`);

// Seed Admin User if not exists
const adminExists = db.prepare("SELECT * FROM users WHERE username = ?").get("admin");
if (!adminExists) {
  const hashedPassword = bcrypt.hashSync("admin123", 10);
  db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run("admin", hashedPassword, "admin");
}

async function startServer() {
  const app = express();
  app.use(express.json());

  // Auth Middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err: any, user: any) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  // --- API ROUTES ---

  // Auth
  app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username) as any;
    
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = jwt.sign({ id: user.id, username: user.username, role: user.role, profile_id: user.profile_id }, JWT_SECRET);
      res.json({ token, user: { username: user.username, role: user.role } });
    } else {
      res.status(401).json({ error: "Credenciais inválidas" });
    }
  });

  app.post("/api/change-password", authenticateToken, (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get((req as any).user.id) as any;

    if (user && bcrypt.compareSync(currentPassword, user.password)) {
      const hashedPassword = bcrypt.hashSync(newPassword, 10);
      db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, (req as any).user.id);
      res.json({ success: true });
    } else {
      res.status(400).json({ error: "Senha atual incorreta" });
    }
  });

  app.post("/api/admin/reset-password", authenticateToken, (req, res) => {
    if ((req as any).user.role !== 'admin') return res.sendStatus(403);
    const { userId, newPassword } = req.body;
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, userId);
    res.json({ success: true });
  });

  app.get("/api/admin/users", authenticateToken, (req, res) => {
    if ((req as any).user.role !== 'admin') return res.sendStatus(403);
    const users = db.prepare("SELECT id, username, role, profile_id FROM users").all();
    res.json(users);
  });

  // Dashboard Stats
  app.get("/api/stats", authenticateToken, (req, res) => {
    const studentCount = db.prepare("SELECT COUNT(*) as count FROM students").get() as any;
    const teacherCount = db.prepare("SELECT COUNT(*) as count FROM teachers").get() as any;
    const classCount = db.prepare("SELECT COUNT(*) as count FROM classes").get() as any;
    const totalRevenue = db.prepare("SELECT SUM(amount) as total FROM payments").get() as any;
    
    res.json({
      students: studentCount.count,
      teachers: teacherCount.count,
      classes: classCount.count,
      revenue: totalRevenue.total || 0
    });
  });

  // Students
  app.get("/api/students", authenticateToken, (req, res) => {
    const students = db.prepare("SELECT * FROM students").all();
    res.json(students);
  });

  app.post("/api/students", authenticateToken, (req, res) => {
    const { registration_no, name, bi, dob, guardian, contact, address } = req.body;
    try {
      const info = db.prepare("INSERT INTO students (registration_no, name, bi, dob, guardian, contact, address) VALUES (?, ?, ?, ?, ?, ?, ?)").run(registration_no, name, bi, dob, guardian, contact, address);
      // Create user account for student
      const hashedPassword = bcrypt.hashSync(bi, 10); // Default password is BI
      db.prepare("INSERT INTO users (username, password, role, profile_id) VALUES (?, ?, ?, ?)").run(bi, hashedPassword, 'student', info.lastInsertRowid);
      res.json({ id: info.lastInsertRowid });
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  // Teachers
  app.get("/api/teachers", authenticateToken, (req, res) => {
    const teachers = db.prepare("SELECT * FROM teachers").all();
    res.json(teachers);
  });

  app.post("/api/teachers", authenticateToken, (req, res) => {
    const { name, bi, contact, degree } = req.body;
    try {
      const info = db.prepare("INSERT INTO teachers (name, bi, contact, degree) VALUES (?, ?, ?, ?)").run(name, bi, contact, degree);
      const hashedPassword = bcrypt.hashSync(bi, 10);
      db.prepare("INSERT INTO users (username, password, role, profile_id) VALUES (?, ?, ?, ?)").run(bi, hashedPassword, 'teacher', info.lastInsertRowid);
      res.json({ id: info.lastInsertRowid });
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  // Classes
  app.get("/api/classes", authenticateToken, (req, res) => {
    const classes = db.prepare("SELECT * FROM classes").all();
    res.json(classes);
  });

  app.post("/api/classes", authenticateToken, (req, res) => {
    const { name, year, shift } = req.body;
    const info = db.prepare("INSERT INTO classes (name, year, shift) VALUES (?, ?, ?)").run(name, year, shift);
    res.json({ id: info.lastInsertRowid });
  });

  // Payments
  app.get("/api/payments", authenticateToken, (req, res) => {
    const payments = db.prepare(`
      SELECT p.*, s.name as student_name 
      FROM payments p 
      JOIN students s ON p.student_id = s.id
    `).all();
    res.json(payments);
  });

  app.post("/api/payments", authenticateToken, (req, res) => {
    const { student_id, amount, date, month, type, receipt_no } = req.body;
    try {
      const info = db.prepare("INSERT INTO payments (student_id, amount, date, month, type, receipt_no) VALUES (?, ?, ?, ?, ?, ?)").run(student_id, amount, date, month, type, receipt_no);
      res.json({ id: info.lastInsertRowid });
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  // Grades
  app.get("/api/grades/:studentId", authenticateToken, (req, res) => {
    const grades = db.prepare(`
      SELECT g.*, sub.name as subject_name 
      FROM grades g 
      JOIN subjects sub ON g.subject_id = sub.id 
      WHERE g.student_id = ?
    `).all(req.params.studentId);
    res.json(grades);
  });

  app.post("/api/grades", authenticateToken, (req, res) => {
    const { student_id, subject_id, class_id, period, score } = req.body;
    const info = db.prepare("INSERT INTO grades (student_id, subject_id, class_id, period, score) VALUES (?, ?, ?, ?, ?)").run(student_id, subject_id, class_id, period, score);
    res.json({ id: info.lastInsertRowid });
  });

  // DELETE Routes
  app.delete("/api/students/:id", authenticateToken, (req, res) => {
    db.prepare("DELETE FROM students WHERE id = ?").run(req.params.id);
    db.prepare("DELETE FROM users WHERE role = 'student' AND profile_id = ?").run(req.params.id);
    res.json({ success: true });
  });

  app.delete("/api/teachers/:id", authenticateToken, (req, res) => {
    db.prepare("DELETE FROM teachers WHERE id = ?").run(req.params.id);
    db.prepare("DELETE FROM users WHERE role = 'teacher' AND profile_id = ?").run(req.params.id);
    res.json({ success: true });
  });

  app.delete("/api/classes/:id", authenticateToken, (req, res) => {
    db.prepare("DELETE FROM classes WHERE id = ?").run(req.params.id);
    res.json({ success: true });
  });

  app.delete("/api/payments/:id", authenticateToken, (req, res) => {
    db.prepare("DELETE FROM payments WHERE id = ?").run(req.params.id);
    res.json({ success: true });
  });

  // Staff Routes
  app.get("/api/staff", authenticateToken, (req, res) => {
    const staff = db.prepare("SELECT * FROM staff").all();
    res.json(staff);
  });

  app.post("/api/staff", authenticateToken, (req, res) => {
    const { name, bi, role, contact } = req.body;
    try {
      const info = db.prepare("INSERT INTO staff (name, bi, role, contact) VALUES (?, ?, ?, ?)").run(name, bi, role, contact);
      // If secretary, create user account
      if (role.toLowerCase().includes('secret')) {
        const hashedPassword = bcrypt.hashSync(bi, 10);
        db.prepare("INSERT INTO users (username, password, role, profile_id) VALUES (?, ?, ?, ?)").run(bi, hashedPassword, 'admin', info.lastInsertRowid);
      }
      res.json({ id: info.lastInsertRowid });
    } catch (e: any) {
      res.status(400).json({ error: e.message });
    }
  });

  app.delete("/api/staff/:id", authenticateToken, (req, res) => {
    db.prepare("DELETE FROM staff WHERE id = ?").run(req.params.id);
    db.prepare("DELETE FROM users WHERE profile_id = ? AND role != 'student' AND role != 'teacher'").run(req.params.id);
    res.json({ success: true });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(__dirname, "dist")));
    app.get("*", (req, res) => {
      res.sendFile(path.join(__dirname, "dist", "index.html"));
    });
  }

  const PORT = 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
