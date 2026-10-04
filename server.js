const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomUUID } = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://sistema-camaras-cioe.onrender.com";

const JWT_SECRET = process.env.JWT_SECRET;

// ======================================================
// PERMISOS DEL SISTEMA
// ======================================================

const DEFAULT_PERMISSIONS = {
  ver_centro_control: true,
  cambiar_estado: true,
  agregar_camara: true,
  editar_camara: true,
  eliminar_camara: true,
  buscar_filtrar: true,
  ver_reportes: true,
  editar_reportes: true,
  reporte_whatsapp: true,
  exportar_csv: true,
  personalizar_colores: true,
  telefono_perifoneo: true,
  editar_perifoneo: true,
  estado_perifoneo: true,
  barrio_seguro: true,
  barrio_agregar: true,
  barrio_editar: true,
  barrio_eliminar: true,
  camaras_fijas: true,
  fijas_agregar: true,
  fijas_editar: true,
  fijas_eliminar: true,
  estaciones_pares: true,
  ep_crear_grupo: true,
  ep_agregar_camara: true,
  ep_editar: true,
  ep_eliminar: true,
  turnos: true,
  turno_manana: true,
  turno_tarde: true,
  turno_noche: true,
  turnos_crear: true,
  turnos_editar: true,
  turnos_eliminar: true,
  totems: true,
  totems_agregar: true,
  totems_editar: true,
  totems_eliminar: true
};

function normalizePermissions(value) {
  const source =
    value && typeof value === "object" && !Array.isArray(value)
      ? value
      : {};

  const result = {};

  for (const key of Object.keys(DEFAULT_PERMISSIONS)) {
    result[key] =
      typeof source[key] === "boolean"
        ? source[key]
        : DEFAULT_PERMISSIONS[key];
  }

  return result;
}

function allPermissions() {
  return Object.fromEntries(
    Object.keys(DEFAULT_PERMISSIONS).map((key) => [key, true])
  );
}

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

async function auth(req, res, next) {
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

    // El administrador no tiene límite de sesiones.
    if (req.user?.role === "admin") {
      return next();
    }

    // Cada usuario normal debe tener una sesión registrada y activa.
    if (!req.user?.sid) {
      return res.status(401).json({
        ok: false,
        error: "Sesión inválida. Inicia sesión nuevamente."
      });
    }

    const session = await pool.query(
      `UPDATE user_sessions
       SET last_seen=NOW()
       WHERE session_id=$1
         AND user_id=$2
         AND last_seen > NOW() - INTERVAL '5 minutes'
       RETURNING session_id`,
      [req.user.sid, req.user.id]
    );

    if (!session.rowCount) {
      return res.status(401).json({
        ok: false,
        error: "La sesión venció o fue cerrada. Inicia sesión nuevamente."
      });
    }

    next();
  } catch (err) {
    if (err?.name === "JsonWebTokenError" || err?.name === "TokenExpiredError") {
      return res.status(401).json({
        ok: false,
        error: "Sesión inválida o vencida"
      });
    }

    console.error("Error validando sesión:", err);
    return res.status(500).json({
      ok: false,
      error: "Error validando la sesión"
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
// OBTENER USUARIO ACTUAL DESDE LA BD
// ======================================================

async function getCurrentUser(userId) {
  const q = await pool.query(
    `SELECT
      id,
      username,
      role,
      active,
      permissions
     FROM users
     WHERE id=$1`,
    [userId]
  );

  return q.rows[0] || null;
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

    CREATE TABLE IF NOT EXISTS user_sessions (
      session_id UUID PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_user_sessions_user_id
    ON user_sessions(user_id);

    CREATE INDEX IF NOT EXISTS idx_user_sessions_last_seen
    ON user_sessions(last_seen);
  `);

  // Agrega la columna sin borrar usuarios existentes
  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS permissions JSONB
    NOT NULL DEFAULT '{}'::jsonb;
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
        active,
        permissions
      )
      VALUES($1,$2,'admin',TRUE,$3::jsonb)`,
      [
        "admin",
        hash,
        JSON.stringify(allPermissions())
      ]
    );

    console.log("Usuario admin creado correctamente.");
  }

  // Admin siempre tiene todos los permisos
  await pool.query(
    `UPDATE users
     SET permissions=$1::jsonb
     WHERE username='admin'`,
    [JSON.stringify(allPermissions())]
  );

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
  const client = await pool.connect();

  try {
    const username = String(
      req.body?.username || ""
    ).trim();

    const password = String(
      req.body?.password || ""
    );

    const q = await client.query(
      `SELECT
        id,
        username,
        password_hash,
        role,
        active,
        permissions
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

    const permissions =
      u.role === "admin"
        ? allPermissions()
        : normalizePermissions(u.permissions);

    let sessionId = null;

    // ADMIN: acceso ilimitado.
    // USUARIOS NORMALES: máximo 2 sesiones/pestañas activas.
    if (u.role !== "admin") {
      await client.query("BEGIN");

      // Evita que dos inicios simultáneos superen el límite.
      await client.query(
        "SELECT pg_advisory_xact_lock($1)",
        [u.id]
      );

      // Libera sesiones de pestañas/equipos que dejaron de enviar actividad.
      await client.query(
        `DELETE FROM user_sessions
         WHERE user_id=$1
           AND last_seen <= NOW() - INTERVAL '5 minutes'`,
        [u.id]
      );

      const activeSessions = await client.query(
        `SELECT COUNT(*)::int AS total
         FROM user_sessions
         WHERE user_id=$1`,
        [u.id]
      );

      const total = activeSessions.rows[0]?.total || 0;

      if (total >= 2) {
        await client.query("ROLLBACK");

        return res.status(409).json({
          ok: false,
          code: "SESSION_LIMIT",
          error: "Este usuario ya tiene 2 sesiones activas. Cierra una sesión para poder ingresar."
        });
      }

      sessionId = randomUUID();

      await client.query(
        `INSERT INTO user_sessions(
          session_id,
          user_id,
          created_at,
          last_seen
        )
        VALUES($1,$2,NOW(),NOW())`,
        [sessionId, u.id]
      );

      await client.query("COMMIT");
    }

    const token = jwt.sign(
      {
        id: u.id,
        username: u.username,
        role: u.role,
        ...(sessionId ? { sid: sessionId } : {})
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
        role: u.role,
        permissions
      },
      sessionLimit: u.role === "admin" ? null : 2
    });
  } catch (err) {
    try { await client.query("ROLLBACK"); } catch (_) {}
    console.error(err);

    res.status(500).json({
      ok: false,
      error: "Error interno"
    });
  } finally {
    client.release();
  }
});

// ======================================================
// SESIONES ACTIVAS
// ======================================================

// Mantiene viva una pestaña abierta. Los usuarios normales envían
// este pulso periódicamente; el admin queda exento del límite.
app.post("/api/session/heartbeat", auth, async (req, res) => {
  res.json({ ok: true });
});

// Cierra únicamente la sesión/pestaña actual.
app.post("/api/logout", auth, async (req, res) => {
  try {
    if (req.user?.role !== "admin" && req.user?.sid) {
      await pool.query(
        `DELETE FROM user_sessions
         WHERE session_id=$1 AND user_id=$2`,
        [req.user.sid, req.user.id]
      );
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({
      ok: false,
      error: "No se pudo cerrar la sesión"
    });
  }
});

// ======================================================
// DATOS DEL USUARIO ACTUAL
// ======================================================

app.get("/api/me", auth, async (req, res) => {
  try {
    const u = await getCurrentUser(req.user.id);

    if (!u || !u.active) {
      return res.status(401).json({
        ok: false,
        error: "Usuario no disponible"
      });
    }

    res.json({
      ok: true,
      user: {
        id: u.id,
        username: u.username,
        role: u.role,
        active: u.active,
        permissions:
          u.role === "admin"
            ? allPermissions()
            : normalizePermissions(u.permissions)
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
// ======================================================

app.put("/api/state", auth, async (req, res) => {
  try {
    const currentUser =
      await getCurrentUser(req.user.id);

    if (!currentUser || !currentUser.active) {
      return res.status(401).json({
        ok: false,
        error: "Usuario no disponible"
      });
    }

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

    /*
      El frontend será el encargado de impedir
      las acciones que el usuario no tenga permitidas.

      El backend mantiene la autenticación y guarda
      el estado compartido.
    */

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
          permissions,
          created_at
         FROM users
         ORDER BY id`
      );

      const users = q.rows.map((u) => ({
        ...u,
        permissions:
          u.role === "admin"
            ? allPermissions()
            : normalizePermissions(u.permissions)
      }));

      res.json({
        ok: true,
        users
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

      const permissions =
        role === "admin"
          ? allPermissions()
          : normalizePermissions(
              req.body?.permissions
            );

      await pool.query(
        `INSERT INTO users(
          username,
          password_hash,
          role,
          active,
          permissions
        )
        VALUES($1,$2,$3,TRUE,$4::jsonb)`,
        [
          username,
          hash,
          role,
          JSON.stringify(permissions)
        ]
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
// CAMBIAR PERMISOS
// SOLO ADMIN
// ======================================================

app.patch(
  "/api/users/:id/permissions",
  auth,
  adminOnly,
  async (req, res) => {
    try {
      const userId = Number(req.params.id);

      if (!Number.isInteger(userId)) {
        return res.status(400).json({
          ok: false,
          error: "Usuario inválido"
        });
      }

      const findUser = await pool.query(
        `SELECT id,username,role
         FROM users
         WHERE id=$1`,
        [userId]
      );

      if (!findUser.rowCount) {
        return res.status(404).json({
          ok: false,
          error: "Usuario no encontrado"
        });
      }

      const target = findUser.rows[0];

      if (
        target.username === "admin" ||
        target.role === "admin"
      ) {
        return res.status(400).json({
          ok: false,
          error:
            "Los permisos del administrador no pueden limitarse"
        });
      }

      const permissions =
        normalizePermissions(
          req.body?.permissions
        );

      await pool.query(
        `UPDATE users
         SET permissions=$1::jsonb
         WHERE id=$2`,
        [
          JSON.stringify(permissions),
          userId
        ]
      );

      res.json({
        ok: true,
        permissions
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

      await pool.query(
        "DELETE FROM user_sessions WHERE user_id=$1",
        [req.params.id]
      );

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
          error:
            "No se puede modificar ese usuario"
        });
      }

      if (!req.body?.active) {
        await pool.query(
          "DELETE FROM user_sessions WHERE user_id=$1",
          [req.params.id]
        );
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
          error:
            "No se puede eliminar ese usuario"
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
