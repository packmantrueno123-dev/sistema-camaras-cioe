const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://sistema-camaras-cioe.onrender.com";

const JWT_SECRET = process.env.JWT_SECRET;

// ======================================================
// COMPROBACIÓN DE VARIABLES
// ======================================================

if (!process.env.DATABASE_URL) {
  throw new Error("Falta DATABASE_URL");
}

if (!JWT_SECRET) {
  throw new Error("Falta JWT_SECRET");
}

// ======================================================
// POSTGRESQL
// ======================================================

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ======================================================
// EXPRESS / CORS
// ======================================================

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json({ limit: "10mb" }));

// ======================================================
// AUTENTICACIÓN
// ======================================================

function auth(req, res, next) {
  const header = req.headers.authorization || "";

  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: "No autorizado"
    });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({
      ok: false,
      error: "Sesión inválida o vencida"
    });
  }
}

// ======================================================
// SOLO ADMINISTRADOR
// ======================================================

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") {
    return res.status(403).json({
      ok: false,
      error: "Solo administrador"
    });
  }

  next();
}

// ======================================================
// INICIALIZAR BASE DE DATOS
// ======================================================

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      id INTEGER PRIMARY KEY,
      data JSONB NOT NULL DEFAULT '{}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    INSERT INTO app_state (id, data)
    VALUES (1, '{}'::jsonb)
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

  // ====================================================
  // CREAR ADMIN SI NO EXISTE
  // ====================================================

  const exists = await pool.query(
    "SELECT id FROM users WHERE username=$1",
    ["admin"]
  );

  if (!exists.rowCount) {
    const adminPassword = process.env.ADMIN_PASSWORD;

    if (!adminPassword || adminPassword.length < 4) {
      throw new Error(
        "Falta ADMIN_PASSWORD o es demasiado corta"
      );
    }

    const hash = await bcrypt.hash(adminPassword, 12);

    await pool.query(
      `INSERT INTO users(
        username,
        password_hash,
        role,
        active
      )
      VALUES($1,$2,'admin',TRUE)`,
      ["admin", hash]
    );

    console.log("Usuario admin creado correctamente.");
  }

  // ====================================================
  // RECUPERACIÓN DE CONTRASEÑA ADMIN
  // ====================================================

  if (process.env.RESET_ADMIN_PASSWORD === "true") {
    const resetPassword =
      process.env.ADMIN_RESET_PASSWORD;

    if (!resetPassword || resetPassword.length < 8) {
      throw new Error(
        "ADMIN_RESET_PASSWORD debe tener al menos 8 caracteres"
      );
    }

    const resetHash = await bcrypt.hash(
      resetPassword,
      12
    );

    const result = await pool.query(
      `UPDATE users
       SET password_hash=$1,
           active=TRUE
       WHERE username='admin'
       RETURNING id`,
      [resetHash]
    );

    if (!result.rowCount) {
      throw new Error(
        "No se encontró el usuario admin"
      );
    }

    console.log(
      "Contraseña del administrador restablecida correctamente."
    );
  }
}

// ======================================================
// API PRINCIPAL
// ======================================================

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "CIOE API"
  });
});

// ======================================================
// LOGIN
// ======================================================

app.post("/api/login", async (req, res) => {
  try {
    const username = String(
      req.body?.username || ""
    ).trim();

    const password = String(
      req.body?.password || ""
    );

    const q = await pool.query(
      `SELECT
        id,
        username,
        password_hash,
        role,
        active
       FROM users
       WHERE username=$1`,
      [username]
    );

    if (!q.rowCount || !q.rows[0].active) {
      return res.status(401).json({
        ok: false,
        error: "Usuario o contraseña incorrectos"
      });
    }

    const u = q.rows[0];

    const valid = await bcrypt.compare(
      password,
      u.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        ok: false,
        error: "Usuario o contraseña incorrectos"
      });
    }

    const token = jwt.sign(
      {
        id: u.id,
        username: u.username,
        role: u.role
      },
      JWT_SECRET,
      {
        expiresIn: "8h"
      }
    );

    res.json({
      ok: true,
      token,
      user: {
        id: u.id,
        username: u.username,
        role: u.role
      }
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      ok: false,
      error: "Error interno"
    });
  }
});

// ======================================================
// OBTENER ESTADO COMPARTIDO
// TODOS LOS USUARIOS AUTENTICADOS
// ======================================================

app.get("/api/state", auth, async (_req, res) => {
  try {
    const q = await pool.query(
      `SELECT data,updated_at
       FROM app_state
       WHERE id=1`
    );

    res.json({
      ok: true,
      data: q.rows[0].data,
      updatedAt: q.rows[0].updated_at
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      ok: false,
      error: "Error interno"
    });
  }
});

// ======================================================
// GUARDAR ESTADO COMPARTIDO
// TODOS LOS USUARIOS AUTENTICADOS PUEDEN EDITAR
// ======================================================

app.put("/api/state", auth, async (req, res) => {
  try {
    const data = req.body?.data;

    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data)
    ) {
      return res.status(400).json({
        ok: false,
        error: "data inválida"
      });
    }

    const q = await pool.query(
      `UPDATE app_state
       SET data=$1::jsonb,
           updated_at=NOW()
       WHERE id=1
       RETURNING updated_at`,
      [JSON.stringify(data)]
    );

    res.json({
      ok: true,
      updatedAt: q.rows[0].updated_at
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      ok: false,
      error: "Error interno"
    });
  }
});

// ======================================================
// LISTAR USUARIOS
// SOLO ADMIN
// ======================================================

app.get(
  "/api/users",
  auth,
  adminOnly,
  async (_req, res) => {
    try {
      const q = await pool.query(
        `SELECT
          id,
          username,
          role,
          active,
          created_at
         FROM users
         ORDER BY id`
      );

      res.json({
        ok: true,
        users: q.rows
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        ok: false,
        error: "Error interno"
      });
    }
  }
);

// ======================================================
// CREAR USUARIO
// SOLO ADMIN
// ======================================================

app.post(
  "/api/users",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const username = String(
        req.body?.username || ""
      ).trim();

      const password = String(
        req.body?.password || ""
      );

      const role =
        req.body?.role === "admin"
          ? "admin"
          : "user";

      if (
        !/^[A-Za-z0-9._-]{3,30}$/.test(username) ||
        password.length < 4
      ) {
        return res.status(400).json({
          ok: false,
          error: "Datos inválidos"
        });
      }

      const hash = await bcrypt.hash(
        password,
        12
      );

      await pool.query(
        `INSERT INTO users(
          username,
          password_hash,
          role,
          active
        )
        VALUES($1,$2,$3,TRUE)`,
        [username, hash, role]
      );

      res.json({
        ok: true
      });
    } catch (err) {
      if (err.code === "23505") {
        return res.status(409).json({
          ok: false,
          error: "El usuario ya existe"
        });
      }

      console.error(err);

      res.status(500).json({
        ok: false,
        error: "Error interno"
      });
    }
  }
);

// ======================================================
// CAMBIAR CONTRASEÑA
// SOLO ADMIN
// ======================================================

app.patch(
  "/api/users/:id/password",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const password = String(
        req.body?.password || ""
      );

      if (password.length < 4) {
        return res.status(400).json({
          ok: false,
          error: "Contraseña muy corta"
        });
      }

      const hash = await bcrypt.hash(
        password,
        12
      );

      const q = await pool.query(
        `UPDATE users
         SET password_hash=$1
         WHERE id=$2
         RETURNING id`,
        [hash, req.params.id]
      );

      if (!q.rowCount) {
        return res.status(404).json({
          ok: false,
          error: "Usuario no encontrado"
        });
      }

      res.json({
        ok: true
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        ok: false,
        error: "Error interno"
      });
    }
  }
);

// ======================================================
// ACTIVAR / DESACTIVAR USUARIO
// SOLO ADMIN
// ======================================================

app.patch(
  "/api/users/:id/active",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const q = await pool.query(
        `UPDATE users
         SET active=$1
         WHERE id=$2
         AND username<>'admin'
         RETURNING id`,
        [
          !!req.body?.active,
          req.params.id
        ]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          ok: false,
          error: "No se puede modificar ese usuario"
        });
      }

      res.json({
        ok: true
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        ok: false,
        error: "Error interno"
      });
    }
  }
);

// ======================================================
// ELIMINAR USUARIO
// SOLO ADMIN
// ======================================================

app.delete(
  "/api/users/:id",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const q = await pool.query(
        `DELETE FROM users
         WHERE id=$1
         AND username<>'admin'
         RETURNING id`,
        [req.params.id]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          ok: false,
          error: "No se puede eliminar ese usuario"
        });
      }

      res.json({
        ok: true
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        ok: false,
        error: "Error interno"
      });
    }
  }
);

// ======================================================
// INICIAR SERVIDOR
// ======================================================

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(
        `CIOE API activa en puerto ${PORT}`
      );
    });
  })
  .catch((err) => {
    console.error(
      "Error iniciando BD:",
      err
    );

    process.exit(1);
  });
