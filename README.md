# Discord Rich Presence To WEB

A comprehensive Discord bot and web application that tracks user activities and provides advanced analytics, insights, and visualizations of your digital presence. Features real-time tracking, AI-powered insights, privacy controls, and beautiful data visualizations. [Discord Server](https://discord.com/invite/uVUw4wKtNc)

---

## ✨ Key Features

### 🎮 **Activity Tracking & Analytics**
- **Real-time Activity Monitoring**: Live tracking of Discord rich presence data
- **Time Tracking**: Automatic session duration tracking for all activities
- **Smart Session Management**: Detects activity starts/stops with precision
- **Historical Data**: Complete activity history with timestamps and durations
- **Usage Statistics**: Daily, weekly, and monthly analytics with trend analysis

### 📊 **Advanced Dashboard**
- **Interactive UI**: Modern, responsive dashboard with real-time updates
- **Dual Themes**: Beautiful dark and light mode with instant switching
- **Customizable Layouts**: Grid or list view options for different preferences  
- **Smart Search & Filtering**: Real-time activity filtering with advanced search
- **Live WebSocket Updates**: Instant activity updates without page refresh

### 🏆 **Rankings & Statistics**
- **Activity Rankings**: Most played games and apps with detailed metrics
- **Time Visualizations**: Progress bars and time displays with session counts
- **Status Timeline**: Complete history of online/offline/away status changes
- **Usage Patterns**: Detailed breakdowns of daily and weekly usage

### 🔒 **Privacy & Control**
- **Private Mode**: One-click toggle to pause all tracking temporarily
- **Activity Blacklist**: Ignore specific apps or games from tracking
- **Data Retention**: Configurable automatic cleanup of old data
- **Encrypted Storage**: Optional AES-256-GCM encryption for all logs
- **User-Controlled Settings**: Granular privacy controls per user

### 🔗 **Integrations & Notifications**
- **Discord Webhooks**: Customizable notifications for activity changes
- **Notification Types**: New activities, status changes, and daily summaries
- **Smart Alerts**: Configurable webhook notifications with rich embeds
- **Export Functionality**: Full data export in JSON and CSV formats

### 🛡️ **Security & Performance**
- **OAuth Authentication**: Secure Discord login with session management
- **Rate Limiting**: Protection against abuse with configurable limits
- **Security Headers**: Helmet.js integration for enhanced security
- **Auto Cleanup**: Scheduled data purging based on retention policies
- **Error Handling**: Comprehensive error tracking and graceful degradation

---

## 🚀 Quick Start

### Prerequisites
- Node.js 16+ 
- Discord Bot Token
- Discord Application (for OAuth)
- Guild with presence permissions

### Installation

1. **Clone & Install**
```bash
git clone https://github.com/Piliii/DRP-to-WEB
cd DRP-to-WEB
npm install
```

2. **Discord Application Setup**
   - Create application at https://discord.com/developers/applications
   - Create bot and copy token
   - Note Client ID and Client Secret
   - Add redirect URI: `http://localhost:6969/oauth/callback`

3. **Environment Configuration**
```bash
cp .env
# Edit .env with your Discord credentials
```

4. **Launch**
```bash
node index.js
```

5. **Access Dashboard**
   - Visit `http://localhost:6969`
   - Login with Discord OAuth
   - Start tracking your activities!

---

## ⚙️ Environment Variables

### Required Configuration
```env
DISCORD_TOKEN=your_discord_bot_token_here
CLIENT_ID=your_discord_client_id
CLIENT_SECRET=your_discord_client_secret
```

### Optional Settings
```env
# Server Configuration
PORT=6969
SESSION_SECRET=your-secure-random-session-secret

# OAuth Settings  
REDIRECT_URI=http://localhost:6969/oauth/callback

# Data & Logging
LOG_FILE=updates.json
LOG_ENCRYPTION_KEY=your-32-byte-hex-or-base64-encryption-key

# Webhooks & Notifications
WEBHOOK_URL=https://discord.com/api/webhooks/your-webhook-url

# Data Management
DATA_RETENTION_DAYS=90
AUTO_CLEANUP_INTERVAL=24
```

### Environment Variable Details

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCORD_TOKEN` | Required | Your Discord bot token |
| `CLIENT_ID` | Required | Discord application client ID |
| `CLIENT_SECRET` | Required | Discord application client secret |
| `PORT` | `6969` | Web server port |
| `SESSION_SECRET` | Generated | Session encryption secret |
| `REDIRECT_URI` | `http://localhost:6969/oauth/callback` | OAuth callback URL |
| `LOG_FILE` | `updates.json` | Activity log file path |
| `LOG_ENCRYPTION_KEY` | None | 32-byte key for log encryption |
| `WEBHOOK_URL` | None | Discord webhook for notifications |
| `DATA_RETENTION_DAYS` | `90` | Days to keep historical data |
| `AUTO_CLEANUP_INTERVAL` | `24` | Hours between cleanup runs |

---

## 🎯 User Guide

### Getting Started
1. **Login**: Use Discord OAuth to securely authenticate
2. **Dashboard**: View your real-time activity dashboard
3. **Customize**: Configure themes, layouts, and privacy settings
4. **Analyze**: Explore your usage patterns and statistics
5. **Export**: Download your data for external analysis

### Dashboard Features

#### **Current Activities Panel**
- Live view of active Discord rich presence
- Custom status support with emoji rendering
- Game/app activities with rich imagery
- Real-time updates via WebSocket connection

#### **Statistics Panels**
- **Today's Stats**: Current day activity breakdown with progress bars
- **Weekly Rankings**: Top 10 most-used applications with session counts
- **Status History**: Timeline of online/offline status changes
- **Search & Filter**: Real-time activity filtering across all panels

#### **Settings & Customization**
- **Theme Toggle**: Instant dark/light mode switching
- **Layout Options**: Grid or list dashboard layouts
- **Privacy Controls**: Private mode and activity blacklisting
- **Notification Settings**: Webhook configuration and preferences
- **Data Management**: Retention policies and cleanup settings

### Privacy Features

#### **Private Mode**
Temporarily pause all activity tracking with one click:
- Toggle in header for instant activation
- All presence updates ignored while active
- No data logged during private sessions
- Visual indicator shows current tracking status

#### **Activity Blacklist**
Exclude specific applications from tracking:
- Add apps to ignore list in settings
- Blacklisted activities won't be logged
- Real-time filtering of presence data
- Retroactive application to existing data

---

## 🔧 API Reference

### Authentication
All API endpoints require valid Discord OAuth session except public routes.

### Endpoints

#### **User Settings**
```http
GET /api/settings
POST /api/settings
```
Retrieve and update user preferences, privacy settings, and configuration.

#### **Activity Statistics**
```http
GET /api/stats/{period}
```
Parameters: `period` = `day` | `week` | `month`

Returns aggregated activity data with time tracking, session counts, and rankings.

#### **Status History**
```http
GET /api/status-history?from={timestamp}&to={timestamp}
```
Retrieve user status change timeline with optional date filtering.

#### **Data Export**
```http
GET /api/export/{format}
```
Parameters: `format` = `json` | `csv`

Download complete user data archive in specified format.

### WebSocket Events

#### **Real-time Updates**
```javascript
// Connection
const ws = new WebSocket('ws://localhost:6969');

// Activity Updates
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Activity update:', data);
};
```

---

## 🛠️ Development

### Architecture Overview
```
├── Data Storage
│   ├── updates.json (encrypted activity logs)
│   ├── data/user_settings.json (user preferences)
│   ├── data/activity_sessions.json (time tracking)
│   └── data/status_history.json (status changes)
├── Authentication (Discord OAuth)
├── WebSocket Server (real-time updates)
└── Express API (REST endpoints)
```

### Key Components

#### **Activity Tracking Engine**
- Discord.js presence event handling
- Session start/stop detection
- Time duration calculations
- Blacklist filtering
- Private mode enforcement (stops logging)

#### **Data Management**
- Encrypted JSON file storage
- Automatic data cleanup
- Configurable retention policies
- Session persistence
- Error recovery

#### **Web Interface**
- Modern responsive design
- Real-time WebSocket updates
- Progressive enhancement
- Accessibility compliance
- Mobile optimization

### Adding New Features

#### **Custom Statistics**
```javascript
// Add new stat calculation
function calculateCustomStat(userId, timeframe) {
  const sessions = activitySessions[userId] || {};
  // Your custom logic here
  return customData;
}

// Add API endpoint
app.get('/api/custom-stats', requireAuth, (req, res) => {
  const stats = calculateCustomStat(req.session.user.id, req.query.timeframe);
  res.json(stats);
});
```

#### **New Dashboard Panels**
```javascript
// Frontend: Add to dashboard
<div class="card">
  <h2>🆕 Custom Panel</h2>
  <div id="customData"></div>
</div>

// Load data
async function loadCustomData() {
  const response = await fetch('/api/custom-stats');
  const data = await response.json();
  updateCustomPanel(data);
}
```

---

## 🔐 Security

### Authentication & Authorization
- **OAuth 2.0**: Secure Discord authentication flow
- **Session Management**: HTTP-only cookies with CSRF protection
- **Rate Limiting**: Configurable request throttling
- **Input Validation**: Comprehensive data sanitization

### Data Protection
- **Encryption**: AES-256-GCM for sensitive logs
- **Local Storage**: No external data transmission
- **Access Control**: Users only see their own data
- **Audit Trails**: Complete action logging

### Privacy Compliance
- **Data Minimization**: Only necessary data collected
- **User Control**: Complete data export and deletion
- **Transparency**: Clear data usage policies
- **Consent Management**: Explicit permission for tracking

---

## 📈 Performance

### Optimization Features
- **Memory Management**: Efficient data structures
- **Background Processing**: Non-blocking data operations
- **Caching**: Smart data caching strategies
- **Cleanup**: Automatic old data purging

### Monitoring
- **Error Tracking**: Comprehensive error logging
- **Performance Metrics**: Response time monitoring  
- **Resource Usage**: Memory and CPU tracking
- **Health Checks**: System status endpoints

---

## 🚀 Production Deployment

### Requirements
- Node.js 16+ production environment
- HTTPS reverse proxy (nginx/Apache)
- Process manager (PM2, systemd)
- Log rotation setup

### Production Checklist
```bash
# Environment
export NODE_ENV=production

# Security
- Set strong SESSION_SECRET
- Enable LOG_ENCRYPTION_KEY  
- Configure HTTPS reverse proxy
- Set up rate limiting
- Enable security headers

# Performance
- Configure process manager
- Set up log rotation
- Enable gzip compression
- Configure monitoring

# Reliability
- Database backups
- Error tracking
- Health monitoring
- Graceful shutdowns
```

### Deployment Example
```bash
# PM2 Process Manager
npm install -g pm2
pm2 start index.js --name "discord-presence"
pm2 startup
pm2 save

# Nginx Configuration
server {
    listen 443 ssl;
    server_name yourdomain.com;
    
    location / {
        proxy_pass http://localhost:6969;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Development Setup
```bash
# Fork and clone
git clone https://github.com/Piliii/DRP-to-WEB
cd DRP-to-WEB

# Install dependencies
npm install

# Set up development environment
cp .env .env.dev
# Configure with test Discord app

# Run development server
npm run dev
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🆘 Support

### Common Issues

#### **"Missing CLIENT_ID" Error**
- Ensure all required environment variables are set
- Check Discord application configuration
- Verify .env file is properly loaded

#### **OAuth Authentication Fails**
- Confirm redirect URI matches Discord app settings exactly
- Check CLIENT_SECRET is correct
- Ensure bot has necessary permissions

#### **No Presence Data**
- Verify bot is in target Discord guilds
- Check bot has "Presence Intent" and "Identity" enabled
- Ensure users have activities to display

#### **WebSocket Connection Issues**
- Check session authentication
- Verify WebSocket support in browser
- Review browser console for errors

### Getting Help

- **Documentation**: Check this README and inline comments
- **Issues**: Create GitHub issue with details
- **Discord**: Join our support server
- **Email**: Contact contacts@ayopili.com

---

**Made with ❤️ by the Pili Inc.**
