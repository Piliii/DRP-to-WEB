require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const crypto = require('crypto');
const { Client, GatewayIntentBits, ActivityType } = require('discord.js');
const { WebSocketServer } = require('ws');

const {
  PORT = 6969,
  SESSION_SECRET = 'dev-only-session-secret',
  DISCORD_TOKEN,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI = 'http://localhost:6969/oauth/callback',
  LOG_FILE = 'updates.json',
  LOG_ENCRYPTION_KEY,
} = process.env;

if (!DISCORD_TOKEN || !CLIENT_ID || !CLIENT_SECRET) {
  console.error('[FATAL] Missing DISCORD_TOKEN, CLIENT_ID, or CLIENT_SECRET in env');
  process.exit(1);
}

let encKey = null;
if (LOG_ENCRYPTION_KEY) {
  try {
    const buf = LOG_ENCRYPTION_KEY.match(/^[A-Fa-f0-9]+$/)
      ? Buffer.from(LOG_ENCRYPTION_KEY, 'hex')
      : Buffer.from(LOG_ENCRYPTION_KEY, 'base64');
    if (buf.length !== 32) throw new Error('Key must be 32 bytes for AES-256-GCM');
    encKey = buf;
    console.log('[log] updates.json encryption: ENABLED (AES-256-GCM)');
  } catch (e) {
    console.warn('[warn] LOG_ENCRYPTION_KEY invalid. Falling back to plaintext logs:', e.message);
  }
} else {
  console.log('[log] updates.json encryption: DISABLED (plaintext)');
}

function encryptLine(text) {
  if (!encKey) return text;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const enc = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString('base64'), tag.toString('base64'), enc.toString('base64')].join('.');
}

function decryptLine(serialized) {
  if (!encKey) return serialized;
  const [ivB64, tagB64, dataB64] = String(serialized).split('.');
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildPresences,
    GatewayIntentBits.GuildMembers,
  ],
});

let lastActivity = {};
let currentStatus = {};

const fallbackImages = {
  'generic': 'https://cdn-icons-png.flaticon.com/512/3048/3048425.png',
};

function resolveAssetUrl(applicationId, assetKey, size = 512) {
  if (!assetKey) return null;
  if (assetKey.startsWith('spotify:')) return `https://i.scdn.co/image/${assetKey.replace('spotify:', '')}`;
  if (assetKey.startsWith('https://')) return assetKey;
  if (applicationId) return `https://cdn.discordapp.com/app-assets/${applicationId}/${assetKey}.png?size=${size}`;
  return null;
}

function getImageFallbacks(applicationId, assetKey) {
  if (!assetKey) return [];
  const base = `https://cdn.discordapp.com/app-assets/${applicationId}/${assetKey}`;
  return [
    `${base}.png?size=512`,
    `${base}.webp?size=512`,
    `${base}.jpg?size=512`,
    fallbackImages[applicationId] || fallbackImages['generic'],
  ].filter(Boolean);
}

function activityToPojo(a) {
  const largeImage = a.assets?.large_image || a.assets?.largeImage || null;
  const smallImage = a.assets?.small_image || a.assets?.smallImage || null;

  if (a.type === ActivityType.Custom || a.name === 'Custom Status') {
    return {
      name: a.name,
      type: a.type,
      details: a.details || null,
      state: a.state || null,
      applicationId: null,
      largeImage: null,
      smallImage: null,
      imageUrl: null,
      smallImageUrl: null,
      imageUrlFallbacks: [],
      smallImageUrlFallbacks: [],
      emoji: a.emoji || null,
    };
  }

  const imageUrl = resolveAssetUrl(a.applicationId, largeImage);
  const smallImageUrl = resolveAssetUrl(a.applicationId, smallImage);
  const imageUrlFallbacks = getImageFallbacks(a.applicationId, largeImage);
  const smallImageUrlFallbacks = getImageFallbacks(a.applicationId, smallImage);

  return {
    name: a.name,
    type: a.type,
    details: a.details || null,
    state: a.state || null,
    applicationId: a.applicationId || null,
    largeImage,
    smallImage,
    imageUrl: imageUrl || fallbackImages[a.applicationId] || fallbackImages['generic'],
    smallImageUrl: smallImageUrl || fallbackImages[a.applicationId] || fallbackImages['generic'],
    imageUrlFallbacks,
    smallImageUrlFallbacks,
    emoji: a.emoji || null,
  };
}

function presenceToPojo(presence) {
  const user = presence.user ?? presence.member?.user;
  if (!user) return null;

  const userId = user.id;
  const username = user.username;
  const avatarURL = user.displayAvatarURL({ size: 128, dynamic: true });
  const activities = presence.activities?.map(activityToPojo) || [];
  const status = presence.status || 'offline';
  const lastSeen = presence.clientStatus?.web ? Date.now() : currentStatus[userId]?.lastSeen || null;

  return { username, activities, status, lastSeen, avatarURL };
}

client.once('clientReady', async () => {
  console.log(`Logged in as ${client.user.tag}!`);
  for (const [, guild] of client.guilds.cache) {
    try {
      await guild.members.fetch();
      guild.members.cache.forEach(member => {
        if (member.presence) {
          currentStatus[member.id] = presenceToPojo(member.presence);
        }
      });
    } catch {}
  }
});

client.on('presenceUpdate', (oldPresence, newPresence) => {
  if (!newPresence) return;
  const userId = newPresence.userId;
  const pojo = presenceToPojo(newPresence);
  if (!pojo) return;

  const key = JSON.stringify(pojo.activities);
  if (lastActivity[userId] === key) return;
  lastActivity[userId] = key;
  currentStatus[userId] = pojo;

  const logEntry = JSON.stringify({ timestamp: Date.now(), userId, ...pojo }) + '\n';
  fs.appendFile(LOG_FILE, encryptLine(logEntry), err => { if (err) console.error('Log write error:', err); });

  wss.clients.forEach(ws => {
    if (ws.readyState === ws.OPEN && ws.userId === userId) {
      ws.send(JSON.stringify({ userId, ...pojo }));
    }
  });
});

const app = express();
app.set('trust proxy', 1);
const sessionParser = session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 24 * 3600 * 1000 }
});
app.use(helmet({ contentSecurityPolicy: false }));
app.use(sessionParser);

const authLimiter = rateLimit({ windowMs: 60*1000, max: 20 });
const apiLimiter = rateLimit({ windowMs: 10*1000, max: 30 });
app.use('/login', authLimiter);
app.use('/oauth/callback', authLimiter);
app.use('/api/', apiLimiter);

function genState() { return crypto.randomBytes(16).toString('hex'); }
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next(); }

const server = app.listen(PORT, ()=>console.log(`Listening on http://localhost:${PORT}`));
const wss = new WebSocketServer({ noServer: true });
server.on('upgrade', (req,socket,head)=>{
  sessionParser(req, {}, ()=>{
    if(!req.session.user){ socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); socket.destroy(); return; }
    wss.handleUpgrade(req,socket,head, ws=>{ ws.userId = req.session.user.id; wss.emit('connection', ws, req); });
  });
});

wss.on('connection', ws => {
  if(currentStatus[ws.userId]) ws.send(JSON.stringify({ userId: ws.userId, ...currentStatus[ws.userId] }));
});

app.get('/', (req,res)=>{ if(req.session.user) return res.redirect('/panel'); res.type('html').send(`<html><head><title>Presence Portal</title></head><body style="font-family:system-ui;max-width:720px;margin:40px auto;"><h1>Welcome</h1><p>Login with Discord to view your rich presence data.</p><a href="/login" style="padding:10px 16px;border:1px solid #ccc;border-radius:10px;text-decoration:none;">Login with Discord</a></body></html>`); });

app.get('/login', (req,res)=>{
  const state = genState();
  req.session.oauthState = state;
  const params = new URLSearchParams({ client_id: CLIENT_ID, redirect_uri: REDIRECT_URI, response_type: 'code', scope: 'identify', state, prompt:'none' });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get('/oauth/callback', async(req,res)=>{
  try{
    const { code, state } = req.query;
    if(!code || !state || state!==req.session.oauthState) return res.redirect('/');
    delete req.session.oauthState;
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type:'authorization_code', code, redirect_uri: REDIRECT_URI, scope:'identify' })
    });
    const tokenData = await tokenRes.json();
    if(!tokenRes.ok || !tokenData.access_token) return res.redirect('/');
    const userRes = await fetch('https://discord.com/api/users/@me', { headers:{ Authorization:`${tokenData.token_type} ${tokenData.access_token}` }});
    const user = await userRes.json();
    if(!user?.id) return res.redirect('/');
    req.session.user = { id:user.id, username:user.username, avatar:user.avatar };
    res.redirect('/panel');
  }catch(e){ console.error('OAuth callback error:', e); res.redirect('/'); }
});

app.get('/logout', (req,res)=>{ req.session.destroy(()=>res.clearCookie('sid').redirect('/')); });

app.get('/panel', requireAuth, (req,res)=>{
  const { username, id, avatar } = req.session.user;
  const avatarURL = `https://cdn.discordapp.com/avatars/${id}/${avatar}.png?size=128`;
  res.type('html').send(`
<html><head><title>${username}'s Panel</title></head>
<body style="font-family:system-ui;max-width:900px;margin:40px auto;">
<h1>Hi, ${username}</h1>
<img src="${avatarURL}" style="width:128px;height:128px;border-radius:50%;margin-bottom:16px;" />
<a href="/logout">Logout</a>
<p>Your latest rich presence:</p>
<div id="activities"></div>
<script>
const ws=new WebSocket((location.protocol==='https:'?'wss://':'ws://')+location.host);
ws.onmessage=event=>{
  const data=JSON.parse(event.data);
  if(!data.activities)return;
  const container=document.getElementById('activities');
  container.innerHTML='';
  data.activities.forEach(act=>{
    const div=document.createElement('div');
    div.style.cssText='border:1px solid #ccc;border-radius:12px;margin-bottom:10px;padding:10px;display:flex;align-items:center;background-color:#f5f5f5;';
    if(act.type===4||act.name==='Custom Status'){
      const span=document.createElement('span'); 
      span.style.cssText='font-size:48px;margin-right:10px;width:64px;height:64px;display:flex;align-items:center;justify-content:center;';
      if(act.emoji?.id){ const img=document.createElement('img'); img.src=\`https://cdn.discordapp.com/emojis/\${act.emoji.id}.\${act.emoji.animated?'gif':'png'}\`; img.style.width=img.style.height='48px'; span.appendChild(img); }
      else if(act.emoji?.name) span.textContent=act.emoji.name;
      else{ span.style.backgroundColor='#7289da'; span.style.borderRadius='50%'; span.style.color='white'; span.style.fontSize='24px'; span.style.fontWeight='bold'; span.textContent='💭'; }
      div.appendChild(span);
    } else if(act.imageUrl||act.imageUrlFallbacks?.length>0){
      const img=document.createElement('img'); img.style.cssText='width:64px;height:64px;margin-right:10px;border-radius:6px;';
      let urls=[act.imageUrl,...act.imageUrlFallbacks]; let idx=0;
      function loadNext(){ if(idx>=urls.length){ img.replaceWith(document.createElement('div')); return; } img.onload=()=>{}; img.onerror=()=>{ idx++; loadNext(); }; img.src=urls[idx]; }
      loadNext(); div.appendChild(img);
    }
    const content=document.createElement('div');
    content.innerHTML='<strong>'+act.name+'</strong>'+ (act.details?' — '+act.details:'')+ (act.state?' — '+act.state:'');
    div.appendChild(content);
    container.appendChild(div);
  });
};
</script>
</body></html>
  `);
});

client.login(DISCORD_TOKEN);