require('dotenv').config();
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
const path = require('path');
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
  WEBHOOK_URL,
  DATA_RETENTION_DAYS = '90',
  AUTO_CLEANUP_INTERVAL = '24', // hours
} = process.env;

if (!DISCORD_TOKEN || !CLIENT_ID || !CLIENT_SECRET) {
  console.error('[FATAL] Missing DISCORD_TOKEN, CLIENT_ID, or CLIENT_SECRET in env');
  process.exit(1);
}

// Encryption setup
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
  try {
    const [ivB64, tagB64, dataB64] = String(serialized).split('.');
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch (e) {
    console.warn('[warn] Failed to decrypt log line:', e.message);
    return null;
  }
}

// Data storage
const DATA_DIR = './data';
const SETTINGS_FILE = path.join(DATA_DIR, 'user_settings.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'activity_sessions.json');
const STATUS_HISTORY_FILE = path.join(DATA_DIR, 'status_history.json');

// Ensure data directory exists
if (!fsSync.existsSync(DATA_DIR)) {
  fsSync.mkdirSync(DATA_DIR, { recursive: true });
}

// User settings storage
let userSettings = {};
let activitySessions = {}; // Track active sessions
let statusHistory = {}; // Track status changes
let currentStatus = {};
let lastActivity = {};

// Load persisted data
async function loadData() {
  try {
    if (fsSync.existsSync(SETTINGS_FILE)) {
      const data = await fs.readFile(SETTINGS_FILE, 'utf8');
      userSettings = JSON.parse(data);
    }
    if (fsSync.existsSync(SESSIONS_FILE)) {
      const data = await fs.readFile(SESSIONS_FILE, 'utf8');
      activitySessions = JSON.parse(data);
    }
    if (fsSync.existsSync(STATUS_HISTORY_FILE)) {
      const data = await fs.readFile(STATUS_HISTORY_FILE, 'utf8');
      statusHistory = JSON.parse(data);
    }
  } catch (error) {
    console.warn('[warn] Error loading persisted data:', error.message);
  }
}

// Save data functions
async function saveUserSettings() {
  try {
    await fs.writeFile(SETTINGS_FILE, JSON.stringify(userSettings, null, 2));
  } catch (error) {
    console.error('[error] Failed to save user settings:', error.message);
  }
}

async function saveActivitySessions() {
  try {
    await fs.writeFile(SESSIONS_FILE, JSON.stringify(activitySessions, null, 2));
  } catch (error) {
    console.error('[error] Failed to save activity sessions:', error.message);
  }
}

async function saveStatusHistory() {
  try {
    await fs.writeFile(STATUS_HISTORY_FILE, JSON.stringify(statusHistory, null, 2));
  } catch (error) {
    console.error('[error] Failed to save status history:', error.message);
  }
}

// Default user settings
function getDefaultSettings(userId) {
  return {
    theme: 'dark',
    dashboardLayout: 'grid',
    privateMode: false,
    blacklistedApps: [],
    webhookEnabled: false,
    notificationSettings: {
      newActivity: false,
      statusChange: false,
      dailySummary: false
    },
    dataRetention: parseInt(DATA_RETENTION_DAYS),
    createdAt: Date.now()
  };
}

// Get user settings
function getUserSettings(userId) {
  if (!userSettings[userId]) {
    userSettings[userId] = getDefaultSettings(userId);
    saveUserSettings();
  }
  return userSettings[userId];
}

// Activity tracking functions
function startActivitySession(userId, activityName) {
  if (!activitySessions[userId]) activitySessions[userId] = {};
  if (!activitySessions[userId][activityName]) {
    activitySessions[userId][activityName] = {
      startTime: Date.now(),
      totalTime: 0,
      sessionCount: 0
    };
  } else {
    activitySessions[userId][activityName].startTime = Date.now();
  }
}

function endActivitySession(userId, activityName) {
  if (activitySessions[userId]?.[activityName]?.startTime) {
    const session = activitySessions[userId][activityName];
    const sessionDuration = Date.now() - session.startTime;
    session.totalTime += sessionDuration;
    session.sessionCount += 1;
    session.startTime = null;
    saveActivitySessions();
  }
}

function trackStatusChange(userId, oldStatus, newStatus) {
  if (!statusHistory[userId]) statusHistory[userId] = [];
  
  const change = {
    timestamp: Date.now(),
    fromStatus: oldStatus,
    toStatus: newStatus
  };
  
  statusHistory[userId].push(change);
  
  // Keep only recent history (last 1000 entries per user)
  if (statusHistory[userId].length > 1000) {
    statusHistory[userId] = statusHistory[userId].slice(-1000);
  }
  
  saveStatusHistory();
}

// Discord webhook notification
async function sendWebhookNotification(userId, type, data) {
  if (!WEBHOOK_URL) return;
  
  const settings = getUserSettings(userId);
  if (!settings.webhookEnabled || !settings.notificationSettings[type]) return;

  try {
    const user = currentStatus[userId];
    const embed = {
      title: `Activity Update - ${user?.username || 'Unknown User'}`,
      color: type === 'newActivity' ? 0x00ff00 : type === 'statusChange' ? 0xff9900 : 0x0099ff,
      timestamp: new Date().toISOString(),
      fields: []
    };

    if (type === 'newActivity') {
      embed.fields.push({
        name: 'New Activity',
        value: data.activityName,
        inline: true
      });
    } else if (type === 'statusChange') {
      embed.fields.push({
        name: 'Status Change',
        value: `${data.from} → ${data.to}`,
        inline: true
      });
    }

    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ embeds: [embed] })
    });
  } catch (error) {
    console.warn('[warn] Failed to send webhook notification:', error.message);
  }
}

// Data cleanup function
async function cleanupOldData() {
  const cutoffDate = Date.now() - (parseInt(DATA_RETENTION_DAYS) * 24 * 60 * 60 * 1000);
  
  try {
    // Clean up status history
    for (const userId in statusHistory) {
      statusHistory[userId] = statusHistory[userId].filter(entry => entry.timestamp > cutoffDate);
    }
    await saveStatusHistory();

    // Clean up log file
    if (fsSync.existsSync(LOG_FILE)) {
      const logData = await fs.readFile(LOG_FILE, 'utf8');
      const lines = logData.split('\n').filter(line => line.trim());
      const cleanLines = [];

      for (const line of lines) {
        try {
          const decrypted = decryptLine(line);
          if (decrypted) {
            const entry = JSON.parse(decrypted);
            if (entry.timestamp > cutoffDate) {
              cleanLines.push(line);
            }
          }
        } catch (e) {
          // Keep lines we can't parse
          cleanLines.push(line);
        }
      }

      await fs.writeFile(LOG_FILE, cleanLines.join('\n') + '\n');
    }

    console.log(`[cleanup] Cleaned data older than ${DATA_RETENTION_DAYS} days`);
  } catch (error) {
    console.error('[error] Data cleanup failed:', error.message);
  }
}

// Auto cleanup scheduler
setInterval(cleanupOldData, parseInt(AUTO_CLEANUP_INTERVAL) * 60 * 60 * 1000);

// Discord client setup
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildPresences,
    GatewayIntentBits.GuildMembers,
  ],
});

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
  await loadData();
  
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
  const settings = getUserSettings(userId);
  
  // Skip if in private mode
  if (settings.privateMode) return;
  
  const pojo = presenceToPojo(newPresence);
  if (!pojo) return;

  const oldStatus = currentStatus[userId]?.status;
  const newStatus = pojo.status;

  // Track status changes
  if (oldStatus && oldStatus !== newStatus) {
    trackStatusChange(userId, oldStatus, newStatus);
    sendWebhookNotification(userId, 'statusChange', { from: oldStatus, to: newStatus });
  }

  // Handle activity tracking
  const oldActivities = currentStatus[userId]?.activities || [];
  const newActivities = pojo.activities || [];

  // End sessions for activities that stopped
  for (const oldActivity of oldActivities) {
    if (!settings.blacklistedApps.includes(oldActivity.name)) {
      const stillActive = newActivities.some(a => a.name === oldActivity.name);
      if (!stillActive) {
        endActivitySession(userId, oldActivity.name);
      }
    }
  }

  // Start sessions for new activities
  for (const newActivity of newActivities) {
    if (!settings.blacklistedApps.includes(newActivity.name)) {
      const wasActive = oldActivities.some(a => a.name === newActivity.name);
      if (!wasActive) {
        startActivitySession(userId, newActivity.name);
        sendWebhookNotification(userId, 'newActivity', { activityName: newActivity.name });
      }
    }
  }

  // Filter out blacklisted activities
  pojo.activities = pojo.activities.filter(a => !settings.blacklistedApps.includes(a.name));

  const key = JSON.stringify(pojo.activities);
  if (lastActivity[userId] === key) return;
  lastActivity[userId] = key;
  currentStatus[userId] = pojo;

  const logEntry = JSON.stringify({ timestamp: Date.now(), userId, ...pojo }) + '\n';
  fsSync.appendFile(LOG_FILE, encryptLine(logEntry), err => { 
    if (err) console.error('Log write error:', err); 
  });

  wss.clients.forEach(ws => {
    if (ws.readyState === ws.OPEN && ws.userId === userId) {
      ws.send(JSON.stringify({ userId, ...pojo }));
    }
  });
});

// Express app setup
const app = express();
app.set('trust proxy', 1);
const sessionParser = session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    httpOnly: true, 
    sameSite: 'lax', 
    secure: process.env.NODE_ENV === 'production', 
    maxAge: 7 * 24 * 3600 * 1000 
  }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(sessionParser);
app.use(express.json());

const authLimiter = rateLimit({ windowMs: 60*1000, max: 20 });
const apiLimiter = rateLimit({ windowMs: 10*1000, max: 30 });
app.use('/login', authLimiter);
app.use('/oauth/callback', authLimiter);
app.use('/api/', apiLimiter);

function genState() { return crypto.randomBytes(16).toString('hex'); }
function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login'); next(); }

// WebSocket setup
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

// Routes
app.get('/', (req,res)=>{ 
  if(req.session.user) return res.redirect('/panel'); 
  res.type('html').send(`
    <html>
      <head>
        <title>Presence Portal</title>
        <style>
          body { font-family: system-ui; max-width: 720px; margin: 40px auto; background: #1a1a1a; color: #fff; }
          .btn { padding: 10px 16px; border: 1px solid #444; border-radius: 10px; text-decoration: none; background: #333; color: #fff; display: inline-block; }
          .btn:hover { background: #444; }
        </style>
      </head>
      <body>
        <h1>Welcome to Presence Portal</h1>
        <p>Login with Discord to view your rich presence data and analytics.</p>
        <a href="/login" class="btn">Login with Discord</a>
      </body>
    </html>
  `); 
});

app.get('/login', (req,res)=>{
  const state = genState();
  req.session.oauthState = state;
  const params = new URLSearchParams({ 
    client_id: CLIENT_ID, 
    redirect_uri: REDIRECT_URI, 
    response_type: 'code', 
    scope: 'identify', 
    state, 
    prompt:'none' 
  });
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
      body:new URLSearchParams({ 
        client_id: CLIENT_ID, 
        client_secret: CLIENT_SECRET, 
        grant_type:'authorization_code', 
        code, 
        redirect_uri: REDIRECT_URI, 
        scope:'identify' 
      })
    });
    
    const tokenData = await tokenRes.json();
    if(!tokenRes.ok || !tokenData.access_token) return res.redirect('/');
    
    const userRes = await fetch('https://discord.com/api/users/@me', { 
      headers:{ Authorization:`${tokenData.token_type} ${tokenData.access_token}` }
    });
    
    const user = await userRes.json();
    if(!user?.id) return res.redirect('/');
    
    req.session.user = { id:user.id, username:user.username, avatar:user.avatar };
    res.redirect('/panel');
  }catch(e){ 
    console.error('OAuth callback error:', e); 
    res.redirect('/'); 
  }
});

app.get('/logout', (req,res)=>{ 
  req.session.destroy(()=>res.clearCookie('sid').redirect('/')); 
});

// API Routes
app.get('/api/settings', requireAuth, (req, res) => {
  const settings = getUserSettings(req.session.user.id);
  res.json(settings);
});

app.post('/api/settings', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const updates = req.body;
  
  if (!userSettings[userId]) {
    userSettings[userId] = getDefaultSettings(userId);
  }
  
  // Update settings
  Object.assign(userSettings[userId], updates);
  await saveUserSettings();
  
  res.json({ success: true });
});

app.get('/api/stats/:period', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const period = req.params.period; // 'day', 'week', 'month'
  
  const now = Date.now();
  let cutoff;
  
  switch(period) {
    case 'day': cutoff = now - (24 * 60 * 60 * 1000); break;
    case 'week': cutoff = now - (7 * 24 * 60 * 60 * 1000); break;
    case 'month': cutoff = now - (30 * 24 * 60 * 60 * 1000); break;
    default: cutoff = now - (24 * 60 * 60 * 1000);
  }
  
  const sessions = activitySessions[userId] || {};
  const stats = {};
  
  for (const [activityName, data] of Object.entries(sessions)) {
    let totalTime = data.totalTime || 0;
    
    // Add current session time if active
    if (data.startTime && data.startTime > cutoff) {
      totalTime += Math.min(now - data.startTime, now - cutoff);
    }
    
    if (totalTime > 0) {
      stats[activityName] = {
        totalTime,
        sessionCount: data.sessionCount || 0,
        averageSession: data.sessionCount ? totalTime / data.sessionCount : 0
      };
    }
  }
  
  // Sort by total time
  const sortedStats = Object.entries(stats)
    .sort(([,a], [,b]) => b.totalTime - a.totalTime)
    .reduce((obj, [key, value]) => {
      obj[key] = value;
      return obj;
    }, {});
  
  res.json(sortedStats);
});

app.get('/api/status-history', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const history = statusHistory[userId] || [];
  
  // Optionally filter by time range
  const { from, to } = req.query;
  let filtered = history;
  
  if (from) {
    filtered = filtered.filter(entry => entry.timestamp >= parseInt(from));
  }
  if (to) {
    filtered = filtered.filter(entry => entry.timestamp <= parseInt(to));
  }
  
  res.json(filtered);
});

app.get('/api/export/:format', requireAuth, async (req, res) => {
  const userId = req.session.user.id;
  const format = req.params.format; // 'json' or 'csv'
  
  const data = {
    user: req.session.user,
    settings: getUserSettings(userId),
    activitySessions: activitySessions[userId] || {},
    statusHistory: statusHistory[userId] || [],
    currentStatus: currentStatus[userId] || null,
    exportedAt: new Date().toISOString()
  };
  
  if (format === 'csv') {
    // Convert to CSV format
    let csv = 'Activity,Total Time (ms),Session Count,Average Session (ms)\n';
    
    for (const [activity, stats] of Object.entries(data.activitySessions)) {
      csv += `"${activity}",${stats.totalTime},${stats.sessionCount},${stats.totalTime / (stats.sessionCount || 1)}\n`;
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="discord-presence-${userId}-${Date.now()}.csv"`);
    res.send(csv);
  } else {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="discord-presence-${userId}-${Date.now()}.json"`);
    res.json(data);
  }
});

// Main panel route with enhanced UI
app.get('/panel', requireAuth, (req,res)=>{
  const { username, id, avatar } = req.session.user;
  const avatarURL = `https://cdn.discordapp.com/avatars/${id}/${avatar}.png?size=128`;
  const settings = getUserSettings(id);
  
  res.type('html').send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${username}'s Presence Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        :root {
            --bg-primary: ${settings.theme === 'dark' ? '#1a1a1a' : '#ffffff'};
            --bg-secondary: ${settings.theme === 'dark' ? '#2d2d2d' : '#f5f5f5'};
            --bg-tertiary: ${settings.theme === 'dark' ? '#3a3a3a' : '#e0e0e0'};
            --text-primary: ${settings.theme === 'dark' ? '#ffffff' : '#000000'};
            --text-secondary: ${settings.theme === 'dark' ? '#b0b0b0' : '#666666'};
            --accent: #5865f2;
            --border: ${settings.theme === 'dark' ? '#444444' : '#ddd'};
            --success: #00d4aa;
            --warning: #faa61a;
            --danger: #ed4245;
        }
        
        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
        }
        
        .header {
            background: var(--bg-secondary);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }
        
        .user-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }
        
        .user-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border: 2px solid var(--accent);
        }
        
        .user-details h1 {
            font-size: 1.5rem;
            margin-bottom: 0.25rem;
        }
        
        .user-details p {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .header-actions {
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }
        
        .btn {
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            text-decoration: none;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.2s;
            white-space: nowrap;
        }
        
        .btn:hover { 
            background: var(--bg-tertiary); 
            transform: translateY(-1px);
        }
        
        .btn-primary {
            background: var(--accent);
            border-color: var(--accent);
            color: white;
        }
        
        .btn-success { 
            background: var(--success); 
            border-color: var(--success);
            color: white;
        }
        
        .btn-danger { 
            background: var(--danger); 
            border-color: var(--danger);
            color: white;
        }
        
        .toggle-switch {
            position: relative;
            width: 50px;
            height: 24px;
            background: var(--border);
            border-radius: 12px;
            cursor: pointer;
            transition: background 0.3s;
        }
        
        .toggle-switch.active { background: var(--accent); }
        
        .toggle-switch::after {
            content: '';
            position: absolute;
            top: 2px;
            left: 2px;
            width: 20px;
            height: 20px;
            background: white;
            border-radius: 50%;
            transition: transform 0.3s;
        }
        
        .toggle-switch.active::after {
            transform: translateX(26px);
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
            margin-bottom: 2rem;
        }
        
        .dashboard-list {
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }
        
        .card {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            transition: all 0.3s;
        }
        
        .card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .card h2 {
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        
        .card h3 {
            margin-bottom: 0.5rem;
            color: var(--accent);
        }
        
        .activity-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: var(--bg-primary);
            border-radius: 8px;
            margin-bottom: 0.5rem;
            transition: all 0.2s;
        }
        
        .activity-item:hover {
            background: var(--bg-tertiary);
        }
        
        .activity-image {
            width: 64px;
            height: 64px;
            border-radius: 8px;
            flex-shrink: 0;
        }
        
        .activity-info {
            flex: 1;
        }
        
        .activity-name {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }
        
        .activity-details {
            color: var(--text-secondary);
            font-size: 0.9rem;
        }
        
        .activity-time {
            text-align: right;
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
        
        .stats-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem;
            background: var(--bg-primary);
            border-radius: 8px;
            margin-bottom: 0.5rem;
        }
        
        .stats-rank {
            background: var(--accent);
            color: white;
            width: 24px;
            height: 24px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            font-weight: bold;
            margin-right: 0.75rem;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
        }
        
        .modal.show { display: flex; align-items: center; justify-content: center; }
        
        .modal-content {
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 2rem;
            max-width: 500px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }
        
        .form-group {
            margin-bottom: 1rem;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }
        
        .form-group input, .form-group select, .form-group textarea {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-primary);
            color: var(--text-primary);
            font-size: 0.9rem;
        }
        
        .search-box {
            width: 100%;
            padding: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: var(--bg-secondary);
            color: var(--text-primary);
            margin-bottom: 1rem;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 0.5rem;
        }
        
        .status-online { background: var(--success); }
        .status-idle { background: var(--warning); }
        .status-dnd { background: var(--danger); }
        .status-offline { background: var(--text-secondary); }
        
        .time-display {
            font-family: 'Courier New', monospace;
            font-weight: bold;
        }
        
        .progress-bar {
            width: 100%;
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            overflow: hidden;
            margin: 0.5rem 0;
        }
        
        .progress-fill {
            height: 100%;
            background: var(--accent);
            transition: width 0.3s;
        }
        
        @media (max-width: 768px) {
            .header {
                padding: 1rem;
                flex-direction: column;
                text-align: center;
            }
            
            .container { padding: 1rem; }
            
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .header-actions {
                justify-content: center;
            }
        }
        
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--border);
            border-radius: 50%;
            border-top-color: var(--accent);
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .notification {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 1rem 1.5rem;
            border-radius: 8px;
            color: white;
            font-weight: 600;
            z-index: 2000;
            transform: translateX(100%);
            transition: transform 0.3s;
        }
        
        .notification.show {
            transform: translateX(0);
        }
        
        .notification.success { background: var(--success); }
        .notification.error { background: var(--danger); }
        .notification.info { background: var(--accent); }
    </style>
</head>
<body>
    <header class="header">
        <div class="user-info">
            <img src="${avatarURL}" alt="${username}" class="user-avatar">
            <div class="user-details">
                <h1>${username}</h1>
                <p>Discord Presence Portal</p>
            </div>
        </div>
        <div class="header-actions">
            <div class="toggle-switch ${settings.privateMode ? 'active' : ''}" id="privateMode" title="Private Mode">
                <span style="font-size: 0.8rem; position: absolute; left: ${settings.privateMode ? '-60px' : '55px'}; top: 2px; white-space: nowrap;">
                    ${settings.privateMode ? 'Private' : 'Tracking'}
                </span>
            </div>
            <button class="btn" onclick="openSettings()">Settings</button>
            <button class="btn btn-primary" onclick="exportData('json')">Export JSON</button>
            <button class="btn btn-success" onclick="exportData('csv')">Export CSV</button>
            <a href="/logout" class="btn btn-danger">Logout</a>
        </div>
    </header>

    <div class="container">
        <input type="text" class="search-box" id="searchBox" placeholder="Search activities..." oninput="filterActivities()">
        
        <div class="dashboard-${settings.dashboardLayout}" id="dashboard">
            <div class="card fade-in">
                <h2>🎮 Current Activities</h2>
                <div id="activities">
                    <div class="loading"></div>
                </div>
            </div>
            
            <div class="card fade-in">
                <h2>📊 Today's Stats</h2>
                <div id="dailyStats">
                    <div class="loading"></div>
                </div>
            </div>
            
            <div class="card fade-in">
                <h2>🏆 Weekly Rankings</h2>
                <div id="weeklyRankings">
                    <div class="loading"></div>
                </div>
            </div>
            
            <div class="card fade-in">
                <h2>📈 Status History</h2>
                <div id="statusHistory">
                    <div class="loading"></div>
                </div>
            </div>
        </div>
    </div>

    <!-- Settings Modal -->
    <div class="modal" id="settingsModal">
        <div class="modal-content">
            <h2>Settings</h2>
            <form id="settingsForm">
                <div class="form-group">
                    <label>Theme</label>
                    <select name="theme">
                        <option value="dark" ${settings.theme === 'dark' ? 'selected' : ''}>Dark</option>
                        <option value="light" ${settings.theme === 'light' ? 'selected' : ''}>Light</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Dashboard Layout</label>
                    <select name="dashboardLayout">
                        <option value="grid" ${settings.dashboardLayout === 'grid' ? 'selected' : ''}>Grid</option>
                        <option value="list" ${settings.dashboardLayout === 'list' ? 'selected' : ''}>List</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label>Blacklisted Apps (one per line)</label>
                    <textarea name="blacklistedApps" rows="4" placeholder="Enter app names to ignore...">${settings.blacklistedApps.join('\\n')}</textarea>
                </div>
                
                <div class="form-group">
                    <label>Data Retention (days)</label>
                    <input type="number" name="dataRetention" value="${settings.dataRetention}" min="1" max="365">
                </div>
                
                <h3>Webhook Notifications</h3>
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="webhookEnabled" ${settings.webhookEnabled ? 'checked' : ''}>
                        Enable Discord Webhooks
                    </label>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="notifyNewActivity" ${settings.notificationSettings.newActivity ? 'checked' : ''}>
                        New Activity Notifications
                    </label>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="notifyStatusChange" ${settings.notificationSettings.statusChange ? 'checked' : ''}>
                        Status Change Notifications
                    </label>
                </div>
                
                <div class="form-group">
                    <label>
                        <input type="checkbox" name="notifyDailySummary" ${settings.notificationSettings.dailySummary ? 'checked' : ''}>
                        Daily Summary Notifications
                    </label>
                </div>
                
                <div style="display: flex; gap: 1rem; margin-top: 2rem;">
                    <button type="submit" class="btn btn-primary">Save Settings</button>
                    <button type="button" class="btn" onclick="closeSettings()">Cancel</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        let currentActivities = [];
        let statsData = {};
        let searchTerm = '';
        
        const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host);
        
        ws.onmessage = event => {
            const data = JSON.parse(event.data);
            if (data.activities !== undefined) {
                currentActivities = data.activities;
                updateActivitiesDisplay();
            }
        };
        
        ws.onopen = () => {
            console.log('WebSocket connected');
            loadAllData();
        };
        
        ws.onerror = error => {
            console.error('WebSocket error:', error);
            showNotification('Connection error', 'error');
        };
        
        async function loadAllData() {
            try {
                await Promise.all([
                    loadStats('day'),
                    loadStats('week'), 
                    loadStatusHistory()
                ]);
            } catch (error) {
                console.error('Error loading data:', error);
                showNotification('Failed to load data', 'error');
            }
        }
        
        async function loadStats(period) {
            try {
                const response = await fetch(\`/api/stats/\${period}\`);
                const data = await response.json();
                
                if (period === 'day') {
                    updateDailyStats(data);
                } else if (period === 'week') {
                    updateWeeklyRankings(data);
                }
            } catch (error) {
                console.error(\`Error loading \${period} stats:\`, error);
            }
        }
        
        async function loadStatusHistory() {
            try {
                const response = await fetch('/api/status-history');
                const data = await response.json();
                updateStatusHistory(data);
            } catch (error) {
                console.error('Error loading status history:', error);
            }
        }
        
        function updateActivitiesDisplay() {
            const container = document.getElementById('activities');
            
            if (!currentActivities || currentActivities.length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 2rem;">No current activities</p>';
                return;
            }
            
            const filteredActivities = currentActivities.filter(activity => 
                !searchTerm || activity.name.toLowerCase().includes(searchTerm.toLowerCase())
            );
            
            container.innerHTML = filteredActivities.map(activity => {
                if (activity.type === 4 || activity.name === 'Custom Status') {
                    return \`
                        <div class="activity-item">
                            <div style="font-size: 48px; width: 64px; height: 64px; display: flex; align-items: center; justify-content: center; background: var(--bg-tertiary); border-radius: 8px;">
                                \${activity.emoji?.id ? 
                                    \`<img src="https://cdn.discordapp.com/emojis/\${activity.emoji.id}.\${activity.emoji.animated ? 'gif' : 'png'}" style="width: 48px; height: 48px;">\` :
                                    activity.emoji?.name || '💭'
                                }
                            </div>
                            <div class="activity-info">
                                <div class="activity-name">Custom Status</div>
                                <div class="activity-details">\${activity.state || activity.details || 'Custom status'}</div>
                            </div>
                        </div>
                    \`;
                } else {
                    return \`
                        <div class="activity-item">
                            <img src="\${activity.imageUrl || '/default-activity.png'}" 
                                 class="activity-image" 
                                 onerror="this.src='https://cdn-icons-png.flaticon.com/512/3048/3048425.png'">
                            <div class="activity-info">
                                <div class="activity-name">\${activity.name}</div>
                                <div class="activity-details">
                                    \${activity.details || ''}\${activity.details && activity.state ? ' — ' : ''}\${activity.state || ''}
                                </div>
                            </div>
                        </div>
                    \`;
                }
            }).join('');
        }
        
        function updateDailyStats(data) {
            const container = document.getElementById('dailyStats');
            
            if (Object.keys(data).length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No activity today</p>';
                return;
            }
            
            const totalTime = Object.values(data).reduce((sum, stat) => sum + stat.totalTime, 0);
            
            container.innerHTML = \`
                <div style="text-align: center; margin-bottom: 1rem;">
                    <div style="font-size: 2rem; font-weight: bold; color: var(--accent);">\${formatTime(totalTime)}</div>
                    <div style="color: var(--text-secondary);">Total active time today</div>
                </div>
                \${Object.entries(data).slice(0, 5).map(([name, stats]) => \`
                    <div class="stats-item">
                        <div style="display: flex; align-items: center; flex: 1;">
                            <span style="font-weight: 600;">\${name}</span>
                        </div>
                        <div class="activity-time">
                            <div class="time-display">\${formatTime(stats.totalTime)}</div>
                            <div style="font-size: 0.7rem; opacity: 0.7;">\${stats.sessionCount} sessions</div>
                        </div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: \${(stats.totalTime / totalTime * 100)}%"></div>
                    </div>
                \`).join('')}
            \`;
        }
        
        function updateWeeklyRankings(data) {
            const container = document.getElementById('weeklyRankings');
            
            if (Object.keys(data).length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No activity this week</p>';
                return;
            }
            
            container.innerHTML = Object.entries(data)
                .slice(0, 10)
                .map(([name, stats], index) => \`
                    <div class="stats-item">
                        <div style="display: flex; align-items: center; flex: 1;">
                            <div class="stats-rank">\${index + 1}</div>
                            <span style="font-weight: 600;">\${name}</span>
                        </div>
                        <div class="activity-time">
                            <div class="time-display">\${formatTime(stats.totalTime)}</div>
                            <div style="font-size: 0.7rem; opacity: 0.7;">\${stats.sessionCount} sessions</div>
                        </div>
                    </div>
                \`).join('');
        }
        
        function updateStatusHistory(data) {
            const container = document.getElementById('statusHistory');
            
            if (data.length === 0) {
                container.innerHTML = '<p style="color: var(--text-secondary); text-align: center;">No status changes recorded</p>';
                return;
            }
            
            // Show last 10 status changes
            const recent = data.slice(-10).reverse();
            
            container.innerHTML = recent.map(change => \`
                <div class="stats-item">
                    <div style="display: flex; align-items: center; flex: 1;">
                        <span class="status-indicator status-\${change.toStatus}"></span>
                        <span>\${change.fromStatus} → \${change.toStatus}</span>
                    </div>
                    <div style="text-align: right; font-size: 0.8rem; color: var(--text-secondary);">
                        \${new Date(change.timestamp).toLocaleString()}
                    </div>
                </div>
            \`).join('');
        }
        
        function formatTime(ms) {
            if (ms < 60000) return Math.floor(ms / 1000) + 's';
            if (ms < 3600000) return Math.floor(ms / 60000) + 'm ' + Math.floor((ms % 60000) / 1000) + 's';
            const hours = Math.floor(ms / 3600000);
            const minutes = Math.floor((ms % 3600000) / 60000);
            return hours + 'h ' + minutes + 'm';
        }
        
        function filterActivities() {
            searchTerm = document.getElementById('searchBox').value;
            updateActivitiesDisplay();
        }
        
        // Private mode toggle
        document.getElementById('privateMode').addEventListener('click', async () => {
            const toggle = document.getElementById('privateMode');
            const isActive = toggle.classList.contains('active');
            
            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ privateMode: !isActive })
                });
                
                if (response.ok) {
                    toggle.classList.toggle('active');
                    const text = toggle.querySelector('span');
                    if (!isActive) {
                        text.textContent = 'Private';
                        text.style.left = '-60px';
                        showNotification('Private mode enabled', 'info');
                    } else {
                        text.textContent = 'Tracking';
                        text.style.left = '55px';
                        showNotification('Tracking resumed', 'success');
                    }
                }
            } catch (error) {
                console.error('Error toggling private mode:', error);
                showNotification('Failed to toggle private mode', 'error');
            }
        });
        
        // Settings modal
        function openSettings() {
            document.getElementById('settingsModal').classList.add('show');
        }
        
        function closeSettings() {
            document.getElementById('settingsModal').classList.remove('show');
        }
        
        document.getElementById('settingsForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const settings = {
                theme: formData.get('theme'),
                dashboardLayout: formData.get('dashboardLayout'),
                blacklistedApps: formData.get('blacklistedApps').split('\\n').filter(app => app.trim()),
                dataRetention: parseInt(formData.get('dataRetention')),
                webhookEnabled: formData.has('webhookEnabled'),
                notificationSettings: {
                    newActivity: formData.has('notifyNewActivity'),
                    statusChange: formData.has('notifyStatusChange'),
                    dailySummary: formData.has('notifyDailySummary')
                }
            };
            
            try {
                const response = await fetch('/api/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
                
                if (response.ok) {
                    showNotification('Settings saved successfully', 'success');
                    closeSettings();
                    
                    // Reload page if theme changed
                    if (settings.theme !== '${settings.theme}' || settings.dashboardLayout !== '${settings.dashboardLayout}') {
                        setTimeout(() => location.reload(), 1000);
                    }
                } else {
                    showNotification('Failed to save settings', 'error');
                }
            } catch (error) {
                console.error('Error saving settings:', error);
                showNotification('Failed to save settings', 'error');
            }
        });
        
        // Export functions
        async function exportData(format) {
            try {
                const response = await fetch(\`/api/export/\${format}\`);
                const blob = await response.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = response.headers.get('Content-Disposition').split('filename=')[1].replace(/"/g, '');
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                showNotification(\`Data exported as \${format.toUpperCase()}\`, 'success');
            } catch (error) {
                console.error('Export error:', error);
                showNotification('Export failed', 'error');
            }
        }
        
        function showNotification(message, type = 'info') {
            const notification = document.createElement('div');
            notification.className = \`notification \${type}\`;
            notification.textContent = message;
            document.body.appendChild(notification);
            
            setTimeout(() => notification.classList.add('show'), 100);
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => document.body.removeChild(notification), 300);
            }, 3000);
        }
        
        // Close modal when clicking outside
        document.getElementById('settingsModal').addEventListener('click', (e) => {
            if (e.target === e.currentTarget) {
                closeSettings();
            }
        });
        
        // Auto-refresh data every 30 seconds
        setInterval(loadAllData, 30000);
    </script>
</body>
</html>
  `);
});

client.login(DISCORD_TOKEN);