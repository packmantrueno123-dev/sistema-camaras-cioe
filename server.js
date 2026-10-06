const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { randomUUID, createHash } = require("crypto");

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
  diseno_colores: true,
  mascotas_encabezado: true,
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

  // Metadatos de seguridad para sesiones.
  await pool.query(`
    ALTER TABLE user_sessions
      ADD COLUMN IF NOT EXISTS ip_address TEXT,
      ADD COLUMN IF NOT EXISTS user_agent TEXT;
  `);

  // Registro persistente de dispositivos.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_devices (
      device_id UUID PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      device_key TEXT NOT NULL,
      device_name TEXT NOT NULL DEFAULT 'Dispositivo',
      user_agent TEXT,
      first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, device_key)
    );
    CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
  `);
  await pool.query(`
    ALTER TABLE user_sessions
      ADD COLUMN IF NOT EXISTS device_id UUID REFERENCES user_devices(device_id) ON DELETE SET NULL;
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

function getClientIp(req) {
  const forwarded=String(req.headers["x-forwarded-for"]||"").split(",")[0].trim();
  const raw=forwarded||req.socket?.remoteAddress||"";
  return raw.replace(/^::ffff:/,"")||"No disponible";
}

const providerCache = new Map();

function isPublicIpForLookup(ip){
  ip=String(ip||"").trim();
  if(!ip || ip==="No disponible") return false;
  if(ip==="::1" || ip==="127.0.0.1") return false;
  if(/^10\./.test(ip) || /^192\.168\./.test(ip)) return false;
  const m=ip.match(/^172\.(\d+)\./);
  if(m && Number(m[1])>=16 && Number(m[1])<=31) return false;
  return true;
}

async function getNetworkProvider(ip){
  ip=String(ip||"").trim();
  if(!isPublicIpForLookup(ip)) return "No disponible";

  const cached=providerCache.get(ip);
  if(cached && cached.expires>Date.now()) return cached.value;

  try{
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),2500);
    const response=await fetch(
      `https://ipwho.is/${encodeURIComponent(ip)}?fields=success,connection`,
      {signal:controller.signal}
    );
    clearTimeout(timer);

    if(!response.ok) throw new Error(`HTTP ${response.status}`);
    const data=await response.json();

    const provider=String(
      data?.connection?.isp ||
      data?.connection?.org ||
      "No disponible"
    ).trim() || "No disponible";

    providerCache.set(ip,{value:provider,expires:Date.now()+6*60*60*1000});
    return provider;
  }catch(err){
    console.warn("No se pudo consultar proveedor para",ip,err?.message||err);
    providerCache.set(ip,{value:"No disponible",expires:Date.now()+10*60*1000});
    return "No disponible";
  }
}

function deviceInfoFromUA(ua){
  ua=String(ua||"");
  let device="PC";
  if(/iPhone/i.test(ua)) device="iPhone";
  else if(/iPad/i.test(ua)) device="iPad";
  else if(/Android/i.test(ua)&&/Mobile/i.test(ua)) device="Android";
  else if(/Android/i.test(ua)) device="Tablet Android";
  else if(/Macintosh|Mac OS X/i.test(ua)) device="Mac";
  else if(/Windows/i.test(ua)) device="PC Windows";
  let browser="Navegador web";
  if(/Edg\//i.test(ua))browser="Microsoft Edge";
  else if(/OPR\//i.test(ua))browser="Opera";
  else if(/Firefox\//i.test(ua))browser="Mozilla Firefox";
  else if(/Chrome\//i.test(ua))browser="Google Chrome";
  else if(/Safari\//i.test(ua))browser="Safari";
  return {device,browser,name:`${device} — ${browser}`};
}
function makeDeviceKey(ua){
  return createHash("sha256").update(String(ua||"desconocido")).digest("hex");
}

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
      const loginUA=String(req.headers["user-agent"]||"").slice(0,500);
      const deviceKey=makeDeviceKey(loginUA);
      const deviceMeta=deviceInfoFromUA(loginUA);
      const deviceRow=await client.query(
        `INSERT INTO user_devices(device_id,user_id,device_key,device_name,user_agent,first_seen,last_seen)
         VALUES($1,$2,$3,$4,$5,NOW(),NOW())
         ON CONFLICT(user_id,device_key)
         DO UPDATE SET device_name=EXCLUDED.device_name,user_agent=EXCLUDED.user_agent,last_seen=NOW()
         RETURNING device_id`,
        [randomUUID(),u.id,deviceKey,deviceMeta.name,loginUA]
      );
      const deviceId=deviceRow.rows[0].device_id;
      await client.query(
        `INSERT INTO user_sessions(session_id,user_id,created_at,last_seen,ip_address,user_agent,device_id)
         VALUES($1,$2,NOW(),NOW(),$3,$4,$5)`,
        [sessionId,u.id,getClientIp(req),loginUA,deviceId]
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
      await pool.query(`DELETE FROM user_sessions WHERE last_seen <= NOW() - INTERVAL '5 minutes'`);
      const q=await pool.query(
        `SELECT u.id,u.username,u.role,u.active,u.permissions,u.created_at,
          CASE WHEN u.role='admin' THEN NULL ELSE COUNT(s.session_id)::int END AS active_sessions
         FROM users u LEFT JOIN user_sessions s
         ON s.user_id=u.id AND s.last_seen > NOW() - INTERVAL '5 minutes'
         GROUP BY u.id ORDER BY u.id`
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
// SESIONES ACTIVAS - SOLO ADMIN
// ======================================================
app.get("/api/users/:id/sessions",auth,adminOnly,async(req,res)=>{
 try{
  const userId=Number(req.params.id);
  if(!Number.isInteger(userId))return res.status(400).json({ok:false,error:"Usuario inválido"});
  const target=await pool.query(`SELECT id,username,role FROM users WHERE id=$1`,[userId]);
  if(!target.rowCount)return res.status(404).json({ok:false,error:"Usuario no encontrado"});
  await pool.query(`DELETE FROM user_sessions WHERE user_id=$1 AND last_seen <= NOW() - INTERVAL '5 minutes'`,[userId]);
  const q=await pool.query(`SELECT session_id,device_id,created_at,last_seen,COALESCE(ip_address,'No disponible') ip_address,COALESCE(user_agent,'') user_agent FROM user_sessions WHERE user_id=$1 AND last_seen > NOW() - INTERVAL '5 minutes' ORDER BY created_at DESC`,[userId]);
  const sessions=await Promise.all(q.rows.map(async s=>({
    ...s,
    provider:await getNetworkProvider(s.ip_address)
  })));
  res.json({ok:true,username:target.rows[0].username,limit:target.rows[0].role==="admin"?null:2,sessions});
 }catch(err){console.error(err);res.status(500).json({ok:false,error:"No se pudieron consultar las sesiones"});}
});
app.get("/api/users/:id/devices",auth,adminOnly,async(req,res)=>{
 try{
  const userId=Number(req.params.id);
  if(!Number.isInteger(userId))return res.status(400).json({ok:false,error:"Usuario inválido"});
  const q=await pool.query(`SELECT d.device_id,d.device_name,d.user_agent,d.first_seen,d.last_seen,COUNT(s.session_id)::int active_sessions FROM user_devices d LEFT JOIN user_sessions s ON s.device_id=d.device_id AND s.last_seen>NOW()-INTERVAL '5 minutes' WHERE d.user_id=$1 GROUP BY d.device_id ORDER BY d.last_seen DESC`,[userId]);
  res.json({ok:true,devices:q.rows});
 }catch(err){console.error(err);res.status(500).json({ok:false,error:"No se pudieron consultar los dispositivos"});}
});
app.delete("/api/users/:id/devices/:deviceId",auth,adminOnly,async(req,res)=>{
 const client=await pool.connect();
 try{
  const userId=Number(req.params.id),deviceId=String(req.params.deviceId||"");
  await client.query("BEGIN");
  await client.query(`DELETE FROM user_sessions WHERE user_id=$1 AND device_id=$2`,[userId,deviceId]);
  const q=await client.query(`DELETE FROM user_devices WHERE user_id=$1 AND device_id=$2 RETURNING device_id`,[userId,deviceId]);
  if(!q.rowCount){await client.query("ROLLBACK");return res.status(404).json({ok:false,error:"Dispositivo no encontrado"});}
  await client.query("COMMIT");res.json({ok:true});
 }catch(err){try{await client.query("ROLLBACK")}catch(_){}console.error(err);res.status(500).json({ok:false,error:"No se pudo revocar el dispositivo"});}
 finally{client.release();}
});
app.delete("/api/users/:id/sessions/:sessionId",auth,adminOnly,async(req,res)=>{
 try{
  const q=await pool.query(`DELETE FROM user_sessions WHERE user_id=$1 AND session_id=$2 RETURNING session_id`,[req.params.id,req.params.sessionId]);
  if(!q.rowCount)return res.status(404).json({ok:false,error:"La sesión ya no está activa"});
  res.json({ok:true});
 }catch(err){console.error(err);res.status(500).json({ok:false,error:"No se pudo cerrar la sesión"});}
});
app.delete("/api/users/:id/sessions",auth,adminOnly,async(req,res)=>{
 try{
  const userId=Number(req.params.id);
  if(!Number.isInteger(userId))return res.status(400).json({ok:false,error:"Usuario inválido"});
  const target=await pool.query(`SELECT id,username,role FROM users WHERE id=$1`,[userId]);
  if(!target.rowCount)return res.status(404).json({ok:false,error:"Usuario no encontrado"});
  if(target.rows[0].role==="admin")return res.status(400).json({ok:false,error:"No se puede cerrar masivamente la sesión del administrador desde aquí"});
  const q=await pool.query(`DELETE FROM user_sessions WHERE user_id=$1 RETURNING session_id`,[userId]);
  res.json({ok:true,closed:q.rowCount});
 }catch(err){console.error(err);res.status(500).json({ok:false,error:"No se pudieron cerrar todas las sesiones"});}
});

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
