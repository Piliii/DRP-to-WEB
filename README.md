# Discord Rich Presence Portal

A secure Discord bot that tracks user activities and provides a web-based dashboard for viewing your own rich presence data in real-time. Features Discord OAuth authentication, encrypted logging, and live WebSocket updates.

---

## Features

- **OAuth Authentication**: Secure Discord login to view only your own presence data
- **Real-time Updates**: WebSocket connection for live activity monitoring
- **Rich Activity Display**: Beautiful rendering of Discord activities including:
  - Custom status with emoji support
  - Game/application activities with images
  - Spotify and other rich presence data
- **Encrypted Logging**: Optional AES-256-GCM encryption for activity logs
- **Session Management**: Secure session handling with configurable cookies
- **Rate Limiting**: Built-in protection against abuse
- **Security Headers**: Helmet.js integration for enhanced security

---

## Requirements

- Node.js (v16+)
- Discord Bot Token
- Discord Application (for OAuth)
- A guild where the bot can read member presences

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Piliii/DRP-to-WEB
cd discord-presence-portal
```

2. Install dependencies:
```bash
npm install
```

3. Set up your Discord Application:
   - Go to https://discord.com/developers/applications
   - Create a new application
   - Go to "Bot" section and create a bot, copy the token
   - Go to "OAuth2" section and note your Client ID and Client Secret
   - Add redirect URI: `http://localhost:6969/oauth/callback` (or your custom port)

---

## Environment Variables

Create a `.env` file in the root directory:

```env
# Required
DISCORD_TOKEN=your_discord_bot_token
CLIENT_ID=your_discord_client_id
CLIENT_SECRET=your_discord_client_secret

# Optional
PORT=6969
SESSION_SECRET=your-random-session-secret
REDIRECT_URI=http://localhost:6969/oauth/callback
LOG_FILE=updates.json
LOG_ENCRYPTION_KEY=your-32-byte-hex-or-base64-key
```

### Environment Variable Details:

- **DISCORD_TOKEN**: Your Discord bot token (required)
- **CLIENT_ID**: Your Discord application's client ID (required)  
- **CLIENT_SECRET**: Your Discord application's client secret (required)
- **PORT**: Server port (default: 6969)
- **SESSION_SECRET**: Secret for session encryption (recommended for production)
- **REDIRECT_URI**: OAuth callback URL (must match Discord app settings)
- **LOG_FILE**: File to store activity logs (default: updates.json)
- **LOG_ENCRYPTION_KEY**: 32-byte key for encrypting logs (hex or base64 format)

---

## Running the Application

Start the server:
```bash
node index.js
```

Then visit `http://localhost:6969` (or your configured port) to begin.

---

## Usage

1. **Login**: Visit the home page and click "Login with Discord"
2. **Authorize**: Complete the Discord OAuth flow
3. **Dashboard**: View your real-time rich presence activities
4. **Real-time Updates**: Activities update automatically via WebSocket

---

## Security Features

- **OAuth-only Access**: Users can only view their own presence data
- **Session Management**: Secure HTTP-only cookies with configurable settings
- **Rate Limiting**: 
  - Authentication endpoints: 20 requests per minute
  - API endpoints: 30 requests per 10 seconds
- **Security Headers**: Helmet.js protection against common vulnerabilities
- **Encrypted Logging**: Optional AES-256-GCM encryption for stored logs
- **WebSocket Authentication**: Session-based WebSocket access control

---

## API Endpoints

- `GET /` - Home page (redirects to panel if logged in)
- `GET /login` - Initiates Discord OAuth flow
- `GET /oauth/callback` - Handles OAuth callback
- `GET /panel` - User dashboard (requires authentication)
- `GET /logout` - Destroys session and logs out
- `WebSocket /` - Real-time activity updates (requires authentication)

---

## Activity Types Supported

- **Custom Status**: With emoji support and custom text
- **Games & Applications**: With rich presence images and details
- **Spotify**: Album artwork and track information
- **Generic Activities**: Fallback handling for any Discord activity

---

## Logging

Activity updates are logged to `updates.json` (or your configured file) with:
- Timestamps
- User ID
- Complete activity data
- Optional AES-256-GCM encryption

Log entries are appended in real-time and can be encrypted for privacy.

---

## Development Notes

- The bot fetches all guild members on startup to populate initial presence data
- WebSocket connections are tied to user sessions for security
- Image URLs include fallback handling for Discord CDN assets
- Custom status emojis support both Unicode and Discord custom emojis
- Rate limiting is configured for production safety

---

## Production Deployment

For production use:
1. Set `NODE_ENV=production`
2. Use a strong `SESSION_SECRET`
3. Enable log encryption with `LOG_ENCRYPTION_KEY`
4. Configure proper HTTPS and reverse proxy
5. Update `REDIRECT_URI` to match your domain
6. Consider database storage instead of JSON logs for scalability

---

## Troubleshooting

- **"Missing CLIENT_ID" error**: Ensure all required environment variables are set
- **OAuth fails**: Check redirect URI matches Discord app settings exactly
- **No presence data**: Ensure bot has necessary permissions in target guilds
- **WebSocket connection fails**: Check session authentication and browser console

---

## License

- MIT License