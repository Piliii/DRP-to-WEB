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
  }

  console.log('Current status populated for all cached members.');
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
