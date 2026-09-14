const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me-gen-visual";
const ROOT = path.join(__dirname, "..");
const PUBLIC = path.join(ROOT, "public");
const DATA = path.join(ROOT, "data");
fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, "genvisual.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'reader',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS works(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('novel','comic')),
  author TEXT NOT NULL,
  description TEXT NOT NULL,
  price INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'published',
  cover TEXT NOT NULL,
  accent TEXT NOT NULL DEFAULT '#d94b3d',
  tags TEXT NOT NULL DEFAULT '[]',
  chapters TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS favorites(
  user_id INTEGER NOT NULL,
  work_id INTEGER NOT NULL,
  PRIMARY KEY(user_id, work_id),
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS progress(
  user_id INTEGER NOT NULL,
  work_id INTEGER NOT NULL,
  chapter INTEGER NOT NULL DEFAULT 1,
  position REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, work_id)
);
`);

const seedWorks = [
  {
    slug:"a-quiet-coast", title:"A Quiet Coast", type:"comic", author:"Mira Sen",
    description:"A soft, atmospheric graphic story about a vanished lighthouse and the people who keep returning to the shore.",
    price:49, cover:"cover-coast", accent:"#d77b3d",
    tags:["slice of life","mystery","coastal"], chapters:[
      {title:"The Tide Comes In", kind:"image", pages:["A","B","C"]},
      {title:"The Lightkeeper", kind:"image", pages:["A","B","C"]}
    ]
  },
  {
    slug:"rooms-for-ghosts", title:"Rooms for Ghosts", type:"novel", author:"R. F. Dutta",
    description:"Nine rooms. Nine memories. A hotel that remembers every guest who ever left.",
    price:79, cover:"cover-ghosts", accent:"#7652a6",
    tags:["supernatural","literary","mystery"], chapters:[
      {title:"Room 01", kind:"text", text:"The key had no number. It was simply cold in his palm, as though it had been waiting there for years.\n\nHe climbed the stairs slowly. The hotel was quiet, but not empty."},
      {title:"Room 02", kind:"text", text:"At midnight the wallpaper changed.\n\nNot dramatically. It simply became the wallpaper from the house he had promised himself he would never remember."}
    ]
  },
  {
    slug:"the-last-archive", title:"The Last Archive", type:"novel", author:"Anaya Roy",
    description:"In a city where memories are licensed, one archivist discovers a file that was never meant to exist.",
    price:99, cover:"cover-archive", accent:"#2c7067",
    tags:["sci-fi","thriller","dystopian"], chapters:[
      {title:"Index", kind:"text", text:"Every citizen had an index number. Hers had been erased.\n\nThat was how she knew the archive was afraid."},
      {title:"The Unlisted", kind:"text", text:"There were seven shelves beyond the public catalogue. She had spent twelve years pretending they were only dust."}
    ]
  }
];

const count = db.prepare("SELECT COUNT(*) AS c FROM works").get().c;
if (!count) {
  const insert = db.prepare(`INSERT INTO works(slug,title,type,author,description,price,cover,accent,tags,chapters)
    VALUES(@slug,@title,@type,@author,@description,@price,@cover,@accent,@tags,@chapters)`);
  const tx = db.transaction(() => seedWorks.forEach(w => insert.run({...w,tags:JSON.stringify(w.tags),chapters:JSON.stringify(w.chapters)})));
  tx();
}
if (!db.prepare("SELECT 1 FROM users WHERE email=?").get("demo@genvisual.local")) {
  const hash = bcrypt.hashSync("Demo123!", 12);
  db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)")
    .run("Demo Reader","demo@genvisual.local",hash,"reader");
}

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:["'self'"],
      scriptSrc:["'self'"],
      styleSrc:["'self'","'unsafe-inline'"],
      imgSrc:["'self'","data:"],
      connectSrc:["'self'"],
      fontSrc:["'self'"],
      objectSrc:["'none'"],
      frameAncestors:["'none'"]
    }
  }
}));
app.use(compression());
app.use(express.json({limit:"200kb"}));
app.use(express.urlencoded({extended:false, limit:"100kb"}));
app.use(cookieParser());
app.use(morgan("tiny"));

const hits = new Map();
function rateLimit(req,res,next){
  const key = req.ip + ":" + Math.floor(Date.now()/60000);
  const n = (hits.get(key)||0)+1;
  hits.set(key,n);
  if(n>180) return res.status(429).json({error:"Too many requests. Try again shortly."});
  next();
}
app.use("/api", rateLimit);

function safeUser(user){ return {id:user.id,name:user.name,email:user.email,role:user.role}; }
function sign(user){ return jwt.sign(safeUser(user), JWT_SECRET, {expiresIn:"7d"}); }
function auth(req,res,next){
  try{
    const token=req.cookies.gv_token;
    if(!token) return res.status(401).json({error:"Sign in required"});
    req.user=jwt.verify(token,JWT_SECRET);
    next();
  }catch(e){ return res.status(401).json({error:"Session expired"}); }
}
function optionalAuth(req,res,next){
  try{ req.user=req.cookies.gv_token ? jwt.verify(req.cookies.gv_token,JWT_SECRET) : null; }
  catch(e){ req.user=null; }
  next();
}

app.get("/api/health",(req,res)=>res.json({ok:true,service:"gen/visual",time:new Date().toISOString()}));

app.post("/api/auth/register", async (req,res)=>{
  const name=String(req.body.name||"").trim();
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  if(name.length<2 || !/^\S+@\S+\.\S+$/.test(email) || password.length<8)
    return res.status(400).json({error:"Use a name, valid email and password of at least 8 characters."});
  if(db.prepare("SELECT id FROM users WHERE email=?").get(email))
    return res.status(409).json({error:"An account with this email already exists."});
  const hash=await bcrypt.hash(password,12);
  const info=db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
  const user=db.prepare("SELECT * FROM users WHERE id=?").get(info.lastInsertRowid);
  res.cookie("gv_token",sign(user),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});
  res.json({user:safeUser(user)});
});

app.post("/api/auth/login", async (req,res)=>{
  const email=String(req.body.email||"").trim().toLowerCase();
  const password=String(req.body.password||"");
  const user=db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if(!user || !(await bcrypt.compare(password,user.password_hash)))
    return res.status(401).json({error:"Email or password is incorrect."});
  res.cookie("gv_token",sign(user),{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:604800000});
  res.json({user:safeUser(user)});
});
app.post("/api/auth/logout",(req,res)=>{res.clearCookie("gv_token");res.json({ok:true})});
app.get("/api/auth/me",optionalAuth,(req,res)=>res.json({user:req.user||null}));

app.get("/api/works",optionalAuth,(req,res)=>{
  const q=String(req.query.q||"").trim();
  const type=String(req.query.type||"").trim();
  let sql="SELECT * FROM works WHERE status='published'";
  const args=[];
  if(type==="novel"||type==="comic"){sql+=" AND type=?";args.push(type)}
  if(q){sql+=" AND (title LIKE ? OR author LIKE ? OR tags LIKE ?)";const x="%"+q+"%";args.push(x,x,x)}
  sql+=" ORDER BY id DESC";
  const rows=db.prepare(sql).all(...args).map(formatWork);
  res.json({works:rows});
});
app.get("/api/works/:slug",(req,res)=>{
  const row=db.prepare("SELECT * FROM works WHERE slug=?").get(req.params.slug);
  if(!row) return res.status(404).json({error:"Work not found"});
  res.json({work:formatWork(row)});
});
function formatWork(w){
  return {...w,tags:JSON.parse(w.tags||"[]"),chapters:JSON.parse(w.chapters||"[]")};
}

app.post("/api/favorites/:id",auth,(req,res)=>{
  const id=Number(req.params.id);
  const exists=db.prepare("SELECT 1 FROM favorites WHERE user_id=? AND work_id=?").get(req.user.id,id);
  if(exists) db.prepare("DELETE FROM favorites WHERE user_id=? AND work_id=?").run(req.user.id,id);
  else db.prepare("INSERT INTO favorites(user_id,work_id) VALUES(?,?)").run(req.user.id,id);
  res.json({favorite:!exists});
});
app.get("/api/favorites",auth,(req,res)=>{
  const rows=db.prepare(`SELECT w.* FROM works w JOIN favorites f ON f.work_id=w.id WHERE f.user_id=? ORDER BY f.rowid DESC`).all(req.user.id);
  res.json({works:rows.map(formatWork)});
});
app.get("/api/progress/:id",auth,(req,res)=>{
  const p=db.prepare("SELECT chapter,position FROM progress WHERE user_id=? AND work_id=?").get(req.user.id,Number(req.params.id));
  res.json({progress:p||{chapter:1,position:0}});
});
app.post("/api/progress/:id",auth,(req,res)=>{
  const workId=Number(req.params.id), chapter=Math.max(1,Number(req.body.chapter)||1), position=Math.max(0,Math.min(1,Number(req.body.position)||0));
  db.prepare(`INSERT INTO progress(user_id,work_id,chapter,position) VALUES(?,?,?,?,)
  ON CONFLICT(user_id,work_id) DO UPDATE SET chapter=excluded.chapter,position=excluded.position,updated_at=CURRENT_TIMESTAMP`
  .replace("VALUES(?,?,?,?,)","VALUES(?,?,?,?)")).run(req.user.id,workId,chapter,position);
  res.json({ok:true});
});

app.get("/api/creator/works",auth,(req,res)=>{
  if(!["creator","admin"].includes(req.user.role)) return res.json({works:[]});
  res.json({works:db.prepare("SELECT * FROM works ORDER BY id DESC").all().map(formatWork)});
});
app.post("/api/creator/works",auth,(req,res)=>{
  if(!["creator","admin"].includes(req.user.role)) return res.status(403).json({error:"Creator access required. Ask an administrator to enable creator access."});
  const b=req.body;
  const title=String(b.title||"").trim(), author=String(b.author||req.user.name).trim();
  const type=b.type==="comic"?"comic":"novel";
  if(title.length<2) return res.status(400).json({error:"Title is required."});
  const slug=(title.toLowerCase().replace(/[^a-z0-9]+/g,"-").replace(/^-|-$/g,"")||crypto.randomUUID()).slice(0,70);
  try{
    const info=db.prepare(`INSERT INTO works(slug,title,type,author,description,price,cover,accent,tags,chapters,status)
      VALUES(?,?,?,?,?,?,?,?,?,?,?)`).run(slug,title,type,author,String(b.description||""),Math.max(0,Number(b.price)||0),
      String(b.cover||"cover-archive"),String(b.accent||"#d94b3d"),JSON.stringify(b.tags||[]),JSON.stringify(b.chapters||[]),"draft");
    res.status(201).json({work:formatWork(db.prepare("SELECT * FROM works WHERE id=?").get(info.lastInsertRowid))});
  }catch(e){res.status(409).json({error:"A work with that title already exists."})}
});

app.use(express.static(PUBLIC,{extensions:["html"]}));
app.get("*",(req,res)=>res.sendFile(path.join(PUBLIC,"index.html")));

app.listen(PORT,()=>console.log(`GEN/VISUAL running on http://localhost:${PORT}`));
