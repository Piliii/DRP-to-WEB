# Discord Presence to WEB

This project logs Discord user activities and provides a local-only API to fetch the latest status of users.
It also provides a dedicated Web page per user to display their status in a visually appealing way.

---

## Features
- Logs user presence updates (activities like Spotify, games, etc.) in memory
- Provides a local API (http://127.0.0.1:PORT/status) for current user statuses
- Supports querying a specific user using ?userId=USER_ID
- Timestamps in Discord format <t:UNIX_TIMESTAMP> for easy display
- Dedicated user page to display username and activities in a styled interface
- Prevents external access for security (only accessible locally)

---

## Requirements
- Node.js (v16+)
- Discord Bot Token
- A guild with members whose presences you want to track

---

## Installation
Clone the repository and install dependencies:

npm install

---

## Environment Variables
Create a .env file in the root directory with the following:

DISCORD_TOKEN=your_discord_bot_token
PORT=3000

- DISCORD_TOKEN → Your Discord bot token
- PORT → The port for the local API (e.g., 3000)

---

## Running the Bot
Start the bot:

node index.js

---

## Local API
Once running, the API is available at:

http://127.0.0.1:PORT/status

Optional query parameter:
- ?userId=USER_ID → returns only the specified user’s status
- If no parameter is provided, returns all users

Example API responses:

All users:

{
  "123456789012345678": {
    "username": "JohnDoe",
    "timestamp": 1692630295,
    "activities": [ ... ],
    "formattedActivities": "Spotify (Listening) — Song Name"
  }
}

Specific user:

{
  "username": "JohnDoe",
  "timestamp": 1692630295,
  "activities": [ ... ],
  "formattedActivities": "Spotify (Listening) — Song Name"
}

---

## Security
- The API only listens on 127.0.0.1 and rejects all external requests.
- Use a local reverse proxy (e.g., Nginx) if you want additional security or dashboard integration.

---

## Notes
- Presence updates may not trigger if users were already online before the bot starts; the bot fetches all members on startup to populate the initial status.
- The system keeps status in memory only; no logs are written to disk unless modified.
