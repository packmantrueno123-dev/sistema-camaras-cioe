'use strict';
// JJAE SECURITY - Supabase Storage + Postgres. Revisar y probar antes de uso real.
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const session = require('express-session');
const crypto = require('node:crypto');
const path = require('node:path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OWNER_PASSWORD = process.env.OWNER_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const BUCKET = 'jjae-security-files';
if (!OWNER_PASSWORD || !SESSION_SECRET || SESSION_SECRET.length < 32 || !SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  console.error('Faltan OWNER_PASSWORD, SESSION_SECRET (32+), SUPABASE_URL o SUPABASE_SECRET_KEY');
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_SECRET_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});
// IMPORTANTE: mantener el mismo OWNER_PASSWORD para descifrar archivos previos.
const KEY = crypto.scryptSync(OWNER_PASSWORD, crypto.createHash('sha256').update('jjae-vault-key-v1').digest(), 32);
const safe = s => String(s || '').replace(/[\x00-\x1f]/g, '').trim().slice(0, 180);
const validName = s => typeof s === 'string' && safe(s).length > 0;
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const dbError = ({ error, data }) => { if (error) throw error; return data; };
const files = () => supabase.from('jjae_files');
const folders = () => supabase.from('jjae_folders');
const getAllFiles = async () => dbError(await files().select('*').order('created', { ascending: false }).limit(1000));
const getAllFolders = async () => dbError(await folders().select('*').limit(1000));
const folderNames = async () => {
  const [f, r] = await Promise.all([getAllFolders(), getAllFiles()]);
  return [...new Set([...f.map(x => x.name), ...r.filter(x => !x.deleted_at).map(x => x.folder || 'Archivos')])].sort((a,b) => a.localeCompare(b,'es'));
};
const findFile = async (id, deleted = false) => {
  const { data, error } = await files().select('*').eq('id', id).limit(1).maybeSingle();
  if (error) throw error;
  return data && Boolean(data.deleted_at) === deleted ? data : null;
};
const toPublic = r => ({ id:r.id, name:r.name, folder:r.folder, size:r.size, created:r.created, favorite:!!r.favorite, locked:true });
const filePath = id => `${id}.bin`;
const decrypt = b => {
  if (b.length < 29) throw new Error('Archivo cifrado inválido');
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, b.subarray(0,12));
  decipher.setAuthTag(b.subarray(12,28));
  return Buffer.concat([decipher.update(b.subarray(28)), decipher.final()]);
};

app.disable('x-powered-by');
app.set('trust proxy', 1); // Render utiliza un proxy HTTPS.
app.use(express.json({ limit: '10kb' }));
app.use(session({
  name:'jjae.sid', secret:SESSION_SECRET, resave:false, saveUninitialized:false,
  cookie:{ httpOnly:true, sameSite:'strict', secure:process.env.NODE_ENV==='production', maxAge:2*60*60*1000 },
}));
app.get('/', (req,res) => res.sendFile(path.join(__dirname,'index.html')));
const auth = (req,res,next) => req.session.owner ? next() : res.status(401).json({error:'Inicia sesión primero'});
// Limitación básica en memoria: para producción con múltiples instancias usar almacén compartido.
const attempts = new Map();
app.post('/api/login', (req,res) => {
  const ip = req.ip;
  const now = Date.now();
  const state = attempts.get(ip) || { count:0, until:now+15*60*1000 };
  if (now > state.until) { state.count=0; state.until=now+15*60*1000; }
  if (state.count >= 8) return res.status(429).json({error:'Demasiados intentos. Intenta más tarde'});
  const a=Buffer.from(String(req.body?.password || ''));
  const b=Buffer.from(OWNER_PASSWORD);
  if (a.length !== b.length || !crypto.timingSafeEqual(a,b)) {
    state.count++; attempts.set(ip,state);
    return res.status(401).json({error:'Contraseña incorrecta'});
  }
  attempts.delete(ip);
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'Error de sesión'});
    req.session.owner=true;
    req.session.save(err2 => err2 ? res.status(500).json({error:'Error de sesión'}) : res.json({ok:true}));
  });
});
app.post('/api/logout', auth, (req,res) => req.session.destroy(() => {res.clearCookie('jjae.sid');res.json({ok:true});}));
app.get('/api/me', (req,res) => res.json({authenticated:!!req.session.owner}));
app.get('/api/files', auth, asyncRoute(async(req,res) => res.json((await getAllFiles()).filter(r=>!r.deleted_at).map(toPublic))));
app.get('/api/folders', auth, asyncRoute(async(req,res) => res.json(await folderNames())));
app.get('/api/folder-favorites', auth, asyncRoute(async(req,res) => {
  const all = await getAllFolders(); const names = await folderNames();
  res.json(all.filter(f=>f.favorite && names.includes(f.name)).map(f=>f.name));
}));
app.patch('/api/folder-favorites', auth, asyncRoute(async(req,res) => {
  const name=safe(req.body?.name), favorite=req.body?.favorite;
  if (typeof favorite !== 'boolean') return res.status(400).json({error:'Estado inválido'});
  if (!(await folderNames()).includes(name)) return res.status(404).json({error:'Carpeta no encontrada'});
  dbError(await folders().upsert({name,favorite}, {onConflict:'name'}));
  res.json({ok:true,favorite});
}));
app.post('/api/folders', auth, asyncRoute(async(req,res) => {
  const name=safe(req.body?.name);
  if (!validName(req.body?.name)) return res.status(400).json({error:'Nombre inválido'});
  if ((await folderNames()).includes(name)) return res.status(409).json({error:'Ya existe esa carpeta'});
  dbError(await folders().insert({name,favorite:false}));res.status(201).json({name});
}));
app.patch('/api/folders', auth, asyncRoute(async(req,res) => {
  const from=safe(req.body?.from), to=safe(req.body?.to);
  if (!validName(to) || !(await folderNames()).includes(from)) return res.status(400).json({error:'Carpeta inválida'});
  if (from !== to && (await folderNames()).includes(to)) return res.status(409).json({error:'Ya existe esa carpeta'});
  if (from !== to) {
    const f=dbError(await folders().select('*').eq('name',from).maybeSingle());
    dbError(await folders().upsert({name:to,favorite:!!f?.favorite},{onConflict:'name'}));
    dbError(await files().update({folder:to}).eq('folder',from));
    if (f) dbError(await folders().delete().eq('name',from));
  }
  res.json({ok:true});
}));
app.delete('/api/folders', auth, asyncRoute(async(req,res) => {
  const name=safe(req.body?.name);
  if (!(await folderNames()).includes(name)) return res.status(404).json({error:'Carpeta no encontrada'});
  const now=new Date().toISOString();
  const changed=dbError(await files().update({deleted_at:now}).eq('folder',name).is('deleted_at',null).select('id'));
  dbError(await folders().delete().eq('name',name));
  res.json({ok:true,movedToTrash:changed.length});
}));
app.get('/api/storage', auth, asyncRoute(async(req,res) => {
  const all=await getAllFiles();
  res.json({vaultBytes:all.reduce((s,r)=>s+Number(r.size||0)+28,0),diskTotalBytes:null,diskFreeBytes:null});
}));
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:15*1024*1024,files:1}});
app.post('/api/files', auth, upload.single('file'), asyncRoute(async(req,res) => {
  if (!req.file) return res.status(400).json({error:'Selecciona un archivo'});
  const id=crypto.randomUUID(), iv=crypto.randomBytes(12), cipher=crypto.createCipheriv('aes-256-gcm',KEY,iv);
  const encrypted=Buffer.concat([cipher.update(req.file.buffer),cipher.final()]);
  const blob=Buffer.concat([iv,cipher.getAuthTag(),encrypted]);
  const {error:uploadError}=await supabase.storage.from(BUCKET).upload(filePath(id),blob,{contentType:'application/octet-stream',upsert:false});
  if (uploadError) throw uploadError;
  const row={id,name:safe(req.body.name||req.file.originalname)||'Archivo',folder:safe(req.body.folder||'Archivos')||'Archivos',size:req.file.size,created:new Date().toISOString(),favorite:false};
  try { dbError(await files().insert(row)); }
  catch(e) { await supabase.storage.from(BUCKET).remove([filePath(id)]); throw e; }
  res.status(201).json(toPublic(row));
}));
app.get('/api/files/:id/download', auth, asyncRoute(async(req,res) => {
  const r=await findFile(req.params.id);
  if (!r) return res.status(404).json({error:'No encontrado'});
  const {data,error}=await supabase.storage.from(BUCKET).download(filePath(r.id));
  if (error) throw error;
  const plaintext=decrypt(Buffer.from(await data.arrayBuffer()));
  res.setHeader('Content-Type','application/octet-stream');
  res.setHeader('Content-Disposition',`attachment; filename*=UTF-8''${encodeURIComponent(r.name)}`);
  res.send(plaintext);
}));
app.patch('/api/files/:id', auth, asyncRoute(async(req,res) => {
  const r=await findFile(req.params.id);
  if (!r) return res.status(404).json({error:'No encontrado'});
  const changes={};
  if (req.body?.name !== undefined) {if(!validName(req.body.name))return res.status(400).json({error:'Nombre inválido'});changes.name=safe(req.body.name);}
  if (req.body?.folder !== undefined) {if(!validName(req.body.folder))return res.status(400).json({error:'Carpeta inválida'});changes.folder=safe(req.body.folder);}
  if (req.body?.favorite !== undefined) changes.favorite=!!req.body.favorite;
  if (Object.keys(changes).length) dbError(await files().update(changes).eq('id',r.id));
  res.json({ok:true});
}));
app.get('/api/trash', auth, asyncRoute(async(req,res) => res.json((await getAllFiles()).filter(r=>r.deleted_at).map(r=>({id:r.id,name:r.name,folder:r.folder,size:r.size,created:r.created,deletedAt:r.deleted_at})))));
app.delete('/api/files/:id', auth, asyncRoute(async(req,res) => {
  const r=await findFile(req.params.id);
  if (!r) return res.status(404).json({error:'No encontrado'});
  dbError(await files().update({deleted_at:new Date().toISOString()}).eq('id',r.id));res.json({ok:true});
}));
app.post('/api/trash/:id/restore', auth, asyncRoute(async(req,res) => {
  const r=await findFile(req.params.id,true);
  if (!r) return res.status(404).json({error:'No encontrado'});
  const {data,error}=await supabase.storage.from(BUCKET).info(filePath(r.id));
  if (error || !data) return res.status(409).json({error:'Falta el archivo cifrado'});
  dbError(await files().update({deleted_at:null}).eq('id',r.id));res.json({ok:true});
}));
app.delete('/api/trash/:id', auth, asyncRoute(async(req,res) => {
  const r=await findFile(req.params.id,true);
  if (!r) return res.status(404).json({error:'No encontrado'});
  const {error}=await supabase.storage.from(BUCKET).remove([filePath(r.id)]);
  if (error) throw error;
  dbError(await files().delete().eq('id',r.id));res.json({ok:true});
}));
app.use((err,req,res,next) => {
  console.error('Error:',err.message);
  res.status(err.code==='LIMIT_FILE_SIZE'?413:500).json({error:err.code==='LIMIT_FILE_SIZE'?'Máximo 15 MB por archivo':'No se pudo completar la operación'});
});
app.listen(PORT,'0.0.0.0',()=>console.log(`JJAE SECURITY escuchando en puerto ${PORT}`));
