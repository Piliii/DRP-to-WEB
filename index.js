require('dotenv').config();
const { Client, GatewayIntentBits } = require('discord.js');
const fs = require('fs');
const express = require('express');

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
const LOG_FILE = 'updates.json';

client.once('ready', () => {
  console.log(`Logged in as ${client.user.tag}!`);
});

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
});

const app = express();
const PORT = process.env.PORT;

app.use((req, res, next) => {
  if (req.ip !== '::1' && req.ip !== '127.0.0.1') {
    return res.status(403).send('Forbidden');
  }
  next();
});

app.get('/status', (req, res) => {
  res.json(currentStatus);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Local API running at http://127.0.0.1:${PORT}/status`);
});

client.login(process.env.DISCORD_TOKEN);