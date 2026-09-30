const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://sistema-camaras-cioe.onrender.com";
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(cors({ origin: FRONTEND_ORIGIN }));
app.use(express.json({ limit: "10mb" }));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    INSERT INTO app_state (id, data) VALUES (1, '{}'::jsonb)
    ON CONFLICT (id) DO NOTHING;

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(30) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'user',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const exists = await pool.query("SELECT id FROM users WHERE username=$1", ["admin"]);
  if (!exists.rowCount) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || "1234", 12);
    await pool.query(
      "INSERT INTO users(username,password_hash,role,active) VALUES($1,$2,'admin',TRUE)",
      ["admin", hash]
    );
  }
}

app.get("/", (req, res) => res.json({ ok: true, service: "CIOE API" }));

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  const q = await pool.query(
    "SELECT id,username,password_hash,role,active FROM users WHERE username=$1",
    [String(username || "")]
  );
  if (!q.rowCount || !q.rows[0].active) return res.status(401).json({ ok:false });
  const u = q.rows[0];
  if (!(await bcrypt.compare(String(password || ""), u.password_hash))) {
    return res.status(401).json({ ok:false });
  }
  res.json({ ok:true, user:{ id:u.id, username:u.username, role:u.role } });
});

app.get("/api/state", async (_req, res) => {
  const q = await pool.query("SELECT data,updated_at FROM app_state WHERE id=1");
  res.json({ ok:true, data:q.rows[0].data, updatedAt:q.rows[0].updated_at });
});

app.put("/api/state", async (req, res) => {
  const data = req.body?.data;
  if (!data || typeof data !== "object") return res.status(400).json({ ok:false, error:"data inválida" });
  const q = await pool.query(
    "UPDATE app_state SET data=$1::jsonb, updated_at=NOW() WHERE id=1 RETURNING updated_at",
    [JSON.stringify(data)]
  );
  res.json({ ok:true, updatedAt:q.rows[0].updated_at });
});

app.get("/api/users", async (_req, res) => {
  const q = await pool.query("SELECT id,username,role,active,created_at FROM users ORDER BY id");
  res.json({ ok:true, users:q.rows });
});

app.post("/api/users", async (req, res) => {
  const { username, password, role="user" } = req.body || {};
  if (!/^[A-Za-z0-9._-]{3,30}$/.test(String(username||"")) || String(password||"").length < 4)
    return res.status(400).json({ ok:false, error:"Datos inválidos" });
  const hash = await bcrypt.hash(String(password), 12);
  try {
    await pool.query(
      "INSERT INTO users(username,password_hash,role,active) VALUES($1,$2,$3,TRUE)",
      [username, hash, role === "admin" ? "admin" : "user"]
    );
    res.json({ ok:true });
  } catch(e) {
    res.status(409).json({ ok:false, error:"El usuario ya existe" });
  }
});

app.patch("/api/users/:id/password", async (req, res) => {
  const password = String(req.body?.password || "");
  if (password.length < 4) return res.status(400).json({ok:false,error:"Contraseña muy corta"});
  const hash = await bcrypt.hash(password, 12);
  await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [hash, req.params.id]);
  res.json({ok:true});
});

app.patch("/api/users/:id/active", async (req, res) => {
  await pool.query("UPDATE users SET active=$1 WHERE id=$2 AND username<>'admin'", [!!req.body?.active, req.params.id]);
  res.json({ok:true});
});

app.delete("/api/users/:id", async (req, res) => {
  await pool.query("DELETE FROM users WHERE id=$1 AND username<>'admin'", [req.params.id]);
  res.json({ok:true});
});

initDb()
  .then(() => app.listen(PORT, () => console.log(`CIOE API activa en puerto ${PORT}`)))
  .catch(err => { console.error("Error iniciando BD:", err); process.exit(1); });
