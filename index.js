require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');
<<<<<<< Updated upstream
const fs = require('fs');
const express = require('express');
=======
const { WebSocketServer } = require('ws');

const {
  PORT = 6969,
  SESSION_SECRET = 'dev-only-session-secret',
  DISCORD_TOKEN,
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI = 'http://localhost:6969/oauth/callback',
  ADMIN_IDS = '',
  LOG_FILE = 'updates.json',
  LOG_ENCRYPTION_KEY,
} = process.env;

if (!DISCORD_TOKEN || !CLIENT_ID || !CLIENT_SECRET) {
  console.error('[FATAL] Missing DISCORD_TOKEN, CLIENT_ID, or CLIENT_SECRET in env');
  process.exit(1);
}

// Encryption for logs (optional)
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
    console.warn('[warn] LOG_ENCRYPTION_KEY invalid. Falling back to plaintext logs. Reason:', e.message);
  }
} else {
  console.log('[log] updates.json encryption: DISABLED (plaintext)');
}

function encryptLine(plaintext) {
  if (!encKey) return plaintext;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
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
  const dec = Buffer.concat([decipher.update(data), decipher.final()]);
  return dec.toString('utf8');
}
>>>>>>> Stashed changes

// Discord client
const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildPresences,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent
  ]
});

let lastActivity = {};
let currentStatus = {};
<<<<<<< Updated upstream
const LOG_FILE = 'updates.json';
index.js
client.once('ready', async () => {
  console.log(`Logged in as ${client.user.tag}!`);

  for (const [guildId, guild] of client.guilds.cache) {
    await guild.members.fetch();

    guild.members.cache.forEach(member => {
      if (!member.presence) return;

      const userId = member.id;
      const username = member.user.username;

      const activities = member.presence.activities.map(a => ({
        name: a.name,
        type: a.type,
        details: a.details || null,
        state: a.state || null
      }));

      if (activities.length === 0) return;

      const unixTimestamp = Math.floor(Date.now() / 1000);

      currentStatus[userId] = {
        username,
        timestamp: unixTimestamp,
        activities
      };
    });
=======

function activityToPojo(a) {
  return {
    name: a.name,
    type: a.type,
    details: a.details || null,
    state: a.state || null,
    applicationId: a.applicationId || null,
    largeImage: a.assets?.largeImage || null,
    smallImage: a.assets?.smallImage || null,
  };
}

function formatActivities(activities) {
  if (!activities || activities.length === 0) return 'No current activity';
  return activities
    .map(a => `${a.name} (${a.type})${a.details ? ' — ' + a.details : ''}${a.state ? ' — ' + a.state : ''}`)
    .join('; ');
}

// Populate current status immediately
client.once('ready', async () => {
  console.log(`Logged in as ${client.user.tag}!`);
  for (const [, guild] of client.guilds.cache) {
    try {
      await guild.members.fetch();
      guild.members.cache.forEach(member => {
        if (!member.presence) return;
        const userId = member.id;
        const username = member.user.username;
        const activities = member.presence.activities.map(activityToPojo);
        if (activities.length === 0) return;
        const unixTimestamp = Math.floor(Date.now() / 1000);
        currentStatus[userId] = { username, timestamp: unixTimestamp, activities };
      });
    } catch (e) {
      console.warn(`[guild:${guild.id}] fetch members failed:`, e.message);
    }
>>>>>>> Stashed changes
  }
  console.log('Current status populated for all cached members.');
});

// Update on presence changes
client.on('presenceUpdate', (oldPresence, newPresence) => {
  if (!newPresence) return;

  const userId = newPresence.userId;
  const username = newPresence.user.username;

  const activities = newPresence.activities.map(a => ({
    name: a.name,
    type: a.type,
    details: a.details || null,
    state: a.state || null
  }));

  if (activities.length === 0) return;

  const key = JSON.stringify(activities);
  if (lastActivity[userId] === key) return;
  lastActivity[userId] = key;

  const unixTimestamp = Math.floor(Date.now() / 1000);

  currentStatus[userId] = {
    username,
    timestamp: unixTimestamp,
    activities
  };

  const logEntry = {
    timestamp: unixTimestamp,
    userId,
    username,
    activities
  };

  fs.appendFile(LOG_FILE, JSON.stringify(logEntry) + '\n', (err) => {
    if (err) console.error('Error writing log:', err);
  });

  // Send live update to all WebSocket clients
  wss.clients.forEach(ws => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify({ userId, activities: currentStatus[userId].activities }));
  });
});

// Express setup
const app = express();
<<<<<<< Updated upstream
const PORT = process.env.PORT;

app.use((req, res, next) => {
  if (req.ip !== '::1' && req.ip !== '127.0.0.1') {
    return res.status(403).send('Forbidden');
=======
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(session({
  name: 'sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
}));

const authLimiter = rateLimit({ windowMs: 60 * 1000, max: 20 });
const apiLimiter = rateLimit({ windowMs: 10 * 1000, max: 30 });
app.use('/login', authLimiter);
app.use('/oauth/callback', authLimiter);
app.use('/api/', apiLimiter);

function genState() { return crypto.randomBytes(16).toString('hex'); }
function requireAuth(req, res, next) { if (!req.session.user) return res.redirect('/login'); next(); }

// WebSocket server
const server = app.listen(PORT, () => console.log(`Web + API listening on http://localhost:${PORT}`));
const wss = new WebSocketServer({ server });

// Send current status immediately on connect
wss.on('connection', ws => {
  Object.entries(currentStatus).forEach(([userId, data]) => {
    ws.send(JSON.stringify({ userId, activities: data.activities }));
  });
});

// OAuth & panel routes (same as before)
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/panel');
  res.type('html').send(`<html><head><title>Presence Portal</title></head>
    <body style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
      <h1>Welcome</h1>
      <p>Login with Discord to view your rich presence data captured by the bot in shared servers.</p>
      <a href="/login" style="display:inline-block;padding:10px 16px;border:1px solid #ccc;border-radius:10px;text-decoration:none;">Login with Discord</a>
    </body></html>`);
});

app.get('/login', (req, res) => {
  const state = genState();
  req.session.oauthState = state;
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'identify',
    state,
    prompt: 'none',
  });
  res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`);
});

app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state || state !== req.session.oauthState) return res.redirect('/');
    delete req.session.oauthState;

    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        scope: 'identify',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenRes.ok || !tokenData.access_token) {
      console.error('OAuth token error:', tokenData);
      return res.redirect('/');
    }

    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `${tokenData.token_type} ${tokenData.access_token}` },
    });
    const user = await userRes.json();
    if (!user || !user.id) return res.redirect('/');

    req.session.user = { id: user.id, username: user.username, avatar: user.avatar };
    res.redirect('/panel');
  } catch (e) {
    console.error('OAuth callback error:', e);
    res.redirect('/');
>>>>>>> Stashed changes
  }
  next();
});

<<<<<<< Updated upstream
app.get('/status', (req, res) => {
  const { userId } = req.query;

  function formatActivities(activities) {
    if (!activities || activities.length === 0) return 'No current activity';
    return activities
      .map(a => `${a.name} (${a.type})${a.details ? ' — ' + a.details : ''}${a.state ? ' — ' + a.state : ''}`)
      .join('; ');
  }

  if (userId) {
    const userData = currentStatus[userId];
    if (!userData) {
      return res.status(404).json({ error: 'User not found or no activity yet.' });
    }
    return res.json({
      username: userData.username,
      timestamp: userData.timestamp,
      activities: userData.activities,
      formattedActivities: formatActivities(userData.activities)
    });
  }

  const allUsers = {};
  for (const id in currentStatus) {
    const user = currentStatus[id];
    allUsers[id] = {
      username: user.username,
      timestamp: user.timestamp,
      activities: user.activities,
      formattedActivities: formatActivities(user.activities)
    };
  }

  res.json(allUsers);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Local API running at http://127.0.0.1:${PORT}/status`);
});

client.login(process.env.DISCORD_TOKEN);
=======
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.clearCookie('sid').redirect('/'));
});

app.get('/panel', requireAuth, (req, res) => {
  const { username } = req.session.user;
  res.type('html').send(`
    <html>
      <head><title>${username}'s Panel</title></head>
      <body style="font-family: system-ui; max-width: 900px; margin: 40px auto;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;">
          <h1>Hi, ${username}</h1>
          <a href="/logout">Logout</a>
        </div>
        <p>Your latest rich presence <a href="https://discord.gg/ex9efuvHCV">(if the bot shares a server with you)</a>:</p>
        <div id="activities"></div>
        <script>
          const ws = new WebSocket('ws://' + location.host);
          ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (!data.activities) return;
            const container = document.getElementById('activities');
            container.innerHTML = '';
            data.activities.forEach(act => {
              const div = document.createElement('div');
              div.style.border = '1px solid #ccc';
              div.style.borderRadius = '12px';
              div.style.marginBottom = '10px';
              div.style.padding = '10px';
              div.style.display = 'flex';
              div.style.alignItems = 'center';
              div.style.backgroundColor = '#f5f5f5';

              // VSCode & Discord app icons
              if (act.largeImage && act.applicationId && !act.largeImage.startsWith('spotify:')) {
                const img = document.createElement('img');
                img.src = 'https://cdn.discordapp.com/app-assets/' + act.applicationId + '/' + act.largeImage + '.png';
                img.style.width = '64px';
                img.style.height = '64px';
                img.style.marginRight = '10px';
                div.appendChild(img);
              }

              // Spotify album covers
              if (act.largeImage && act.largeImage.startsWith('spotify:')) {
                const img = document.createElement('img');
                img.src = 'https://i.scdn.co/image/' + act.largeImage.replace('spotify:', '');
                img.style.width = '64px';
                img.style.height = '64px';
                img.style.marginRight = '10px';
                div.appendChild(img);
              }

              const content = document.createElement('div');
              content.innerHTML = '<strong>' + act.name + '</strong>' +
                                  (act.details ? ' — ' + act.details : '') +
                                  (act.state ? ' — ' + act.state : '');
              div.appendChild(content);
              container.appendChild(div);
            });
          };
        </script>
      </body>
    </html>
  `);
});

client.login(DISCORD_TOKEN);
>>>>>>> Stashed changes
