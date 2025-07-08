# my-cool.space

A modern, secure subdomain management platform that allows users to create free subdomains with Discord OAuth authentication and automated DNS management through Porkbun.

## Features

- **Discord OAuth Authentication** - Secure login with Discord accounts
- **Free Subdomain Creation** - Users can request subdomains (e.g., `yourname.my-cool.space`)
- **Multiple DNS Record Types** - Support for CNAME and A records
- **Admin Dashboard** - Complete management interface for administrators
- **Rate Limiting** - Built-in protection against abuse
- **User Management** - Admin tools for user oversight and moderation
- **Abuse Reporting** - Community-driven content moderation
- **Data Export/Deletion** - GDPR-compliant user data management
- **Maintenance Mode** - Toggle site maintenance without downtime
- **Real-time Updates** - Live status updates and notifications

## Architecture

### Tech Stack
- **Backend**: Node.js + Express.js
- **Database**: Appwrite (Cloud or Self-hosted)
- **Authentication**: Discord OAuth 2.0
- **DNS Provider**: Porkbun API
- **Frontend**: EJS templating + Tailwind CSS
- **Session Management**: Express-session with secure cookies
- **Security**: Helmet.js, CORS, Rate limiting

### Key Components
- **Authentication System** - Discord OAuth integration
- **Subdomain Request Management** - CRUD operations for subdomain requests
- **DNS Automation** - Automatic DNS record creation/deletion via Porkbun
- **Admin Panel** - Complete administrative interface
- **User Dashboard** - Personal subdomain management
- **Abuse Reporting** - Community moderation system

## Quick Start

### Prerequisites
- Node.js 18+ and npm 8+
- Appwrite instance (cloud or self-hosted)
- Discord Application (for OAuth)
- Porkbun account with API access
- Domain registered with Porkbun

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/my-cool-space/my-cool-dot-space.git
   cd my-cool-dot-space
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env with your actual values
   ```

4. **Build CSS assets**
   ```bash
   npm run build
   ```

5. **Set up Appwrite database**
   ```bash
   # Run the setup script to create required collections
   node scripts/setup-admin-settings.js
   ```

6. **Start the application**
   ```bash
   # Development with auto-reload
   npm run dev

   # Production
   npm start
   ```

## Configuration

### Environment Variables

Create a `.env` file based on `.env.example`:

```bash
# Application
NODE_ENV=development
PORT=3000
SESSION_SECRET=your-secure-session-secret

# Session debugging (for development only)
DISABLE_HTTPS=true  # Set to true if testing locally without HTTPS

# Appwrite
APPWRITE_ENDPOINT=https://cloud.appwrite.io/v1
APPWRITE_PROJECT_ID=your-project-id
APPWRITE_DATABASE_ID=your-database-id
APPWRITE_COLLECTION_ID=your-collection-id
APPWRITE_API_KEY=your-api-key

# Discord OAuth
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
DISCORD_REDIRECT_URI=http://localhost:3000/auth/discord/callback

# Porkbun DNS
PORKBUN_API_KEY=your-porkbun-api-key
PORKBUN_SECRET_KEY=your-porkbun-secret-key
BASE_DOMAIN=your-domain.com

# hCaptcha (Optional - for spam protection)
HCAPTCHA_SITE_KEY=your-hcaptcha-site-key
HCAPTCHA_SECRET_KEY=your-hcaptcha-secret-key
```

### Important Notes

**Session Configuration**: The application uses session-based authentication. If you experience login issues where users are redirected back to the home page after successful Discord OAuth:

1. **For local development**: Set `DISABLE_HTTPS=true` in your `.env` file
2. **For production**: Ensure your application is served over HTTPS
3. **Session storage**: The default memory store is not suitable for production. Consider using Redis or another persistent session store.

**Discord OAuth Redirect URI**: Make sure the redirect URI in your Discord application settings exactly matches the one in your `.env` file.

### Discord OAuth Setup

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Create a new application
3. Go to OAuth2 → General
4. Add redirect URI: `http://localhost:3000/auth/discord/callback` (development)
5. Copy Client ID and Client Secret to your `.env` file

### Porkbun DNS Setup

1. Register your domain with Porkbun
2. Enable API access in your Porkbun account
3. Generate API keys and add them to your `.env` file

### hCaptcha Setup (Optional)

hCaptcha provides spam protection for domain requests and abuse reports:

1. Go to [hCaptcha Dashboard](https://dashboard.hcaptcha.com/)
2. Create a new site
3. Copy the Site Key and Secret Key to your `.env` file
4. If not configured, the system will skip captcha verification (useful for development)

**Note**: Without hCaptcha, forms are more vulnerable to automated spam and abuse.
4. Ensure your domain's nameservers are set to Porkbun's

### Appwrite Setup

1. Create an Appwrite project
2. Create a database
3. Create the following collections:
   - `subdomain-requests` - For storing subdomain requests
   - `admin_settings` - For application configuration
   - `abuse_reports` - For abuse reporting system
   - `deletion_requests` - For GDPR data deletion requests

## Docker Deployment

### Using Docker Compose

```bash
# Copy and edit environment variables
cp .env.example .env

# Development with hot reload
npm run docker:dev

# Production deployment
npm run docker:prod
```

### Manual Docker Commands

```bash
# Build image
npm run docker:build

# Run container
npm run docker:run
```

## Admin Features

### Setting up Admin Users

1. Log in with Discord OAuth
2. Use Appwrite console to add the "admin" label to your user
3. Access admin panel at `/admin`

### Admin Capabilities
- **Subdomain Management** - Approve, deny, or delete subdomain requests
- **User Management** - View users, grant/revoke admin privileges
- **Abuse Reports** - Review and moderate reported content
- **Data Deletion** - Handle GDPR deletion requests
- **System Settings** - Configure application parameters
- **Maintenance Mode** - Toggle maintenance mode

## Security Features

- **Rate Limiting** - Protection against request flooding
- **CSRF Protection** - Cross-site request forgery prevention
- **Secure Headers** - Helmet.js security headers
- **Input Validation** - Comprehensive input sanitization
- **Session Security** - Secure session management
- **DNS Validation** - Strict validation of DNS records

## API Endpoints

### Public Endpoints
- `GET /` - Landing page
- `GET /auth/discord` - Discord OAuth login
- `GET /auth/discord/callback` - OAuth callback
- `POST /api/request-subdomain` - Create subdomain request
- `POST /api/report-abuse` - Submit abuse report

### User Endpoints (Authentication Required)
- `GET /dashboard` - User dashboard
- `GET /api/my-requests` - User's subdomain requests
- `GET /api/user/export-data` - Export user data (GDPR)

### Admin Endpoints (Admin Privileges Required)
- `GET /admin` - Admin dashboard
- `GET /api/admin/requests` - All subdomain requests
- `POST /api/admin/approve/:id` - Approve subdomain request
- `POST /api/admin/deny/:id` - Deny subdomain request
- `DELETE /api/admin/delete/:id` - Delete subdomain request

## Development

### Available Scripts

```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon
npm run build      # Build CSS assets
npm run build:watch # Build CSS with file watching
npm run build:prod # Build minified CSS for production
npm run docker:dev # Start development environment with Docker
npm run docker:prod # Start production environment with Docker
npm audit          # Check for security vulnerabilities
npm audit:fix      # Automatically fix security issues
```

## Troubleshooting

### Common Issues

**1. Session/Login Problems**
If users are redirected to the home page after successful Discord OAuth:

- **Check environment variables**: Ensure `SESSION_SECRET` is set to a secure random string
- **HTTPS configuration**: For production, ensure the app is served over HTTPS. For local development, set `DISABLE_HTTPS=true`
- **Cookie domain**: Verify the domain configuration matches your deployment
- **Session store**: The default memory store doesn't persist across restarts. Use Redis for production.

**2. Discord OAuth Issues**
- **Redirect URI mismatch**: Ensure the redirect URI in your Discord app settings exactly matches your `.env` configuration
- **Client credentials**: Verify `DISCORD_CLIENT_ID` and `DISCORD_CLIENT_SECRET` are correct
- **Scopes**: The application requires `identify` and `email` scopes

**3. DNS/Subdomain Creation Failures**
- **Porkbun API credentials**: Verify your API key and secret are correct and have the necessary permissions
- **Domain configuration**: Ensure your domain's nameservers are set to Porkbun's servers
- **Rate limiting**: Check if you're hitting Porkbun's API rate limits

**4. Database Connection Issues**
- **Appwrite configuration**: Verify all Appwrite environment variables are correct
- **Collection setup**: Ensure all required collections exist in your Appwrite database
- **API key permissions**: Verify your Appwrite API key has the necessary permissions

### Debug Mode

To enable additional debugging output, you can check the server logs for detailed session and authentication information.

**Development Debug Routes** (only available when `NODE_ENV != production`):
- `GET /debug/session` - View current session information and debugging data
- `GET /debug/reset-session` - Emergency session reset (clears current session)

### Session Persistence in Production

**Important**: The default MemoryStore session configuration is not suitable for production as it will leak memory and not scale past a single process. For production deployments, consider using a persistent session store like Redis:

```bash
npm install connect-redis redis
```

Then modify the session configuration in `app.js` to use Redis instead of the default memory store.

## License

**All Rights Reserved**

Copyright (c) 2025 my-cool.space

This software and associated documentation files (the "Software") are proprietary and confidential. No part of this Software may be reproduced, distributed, or transmitted in any form or by any means, including photocopying, recording, or other electronic or mechanical methods, without the prior written permission of the copyright owner, except in the case of brief quotations embodied in critical reviews and certain other noncommercial uses permitted by copyright law.

**Restrictions:**
- You may NOT use, copy, modify, merge, publish, distribute, sublicense, or sell copies of the Software
- You may NOT reverse engineer, decompile, or disassemble the Software
- You may NOT create derivative works based on the Software
- Commercial use is strictly prohibited without explicit written permission
- Redistribution of any part of this Software is strictly prohibited

**Disclaimer:**
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Support

- **Issues**: Report bugs via [GitHub Issues](https://github.com/my-cool-space/my-cool-dot-space/issues)


## Roadmap

- [ ] **Custom DNS Records** - Support for MX, TXT, and other record types
- [ ] **Subdomain Analytics** - Usage statistics and monitoring
- [ ] **API Rate Limiting** - More granular rate limiting options
- [ ] **Multi-domain Support** - Support for multiple base domains
- [ ] **Automated SSL** - Integration with Let's Encrypt
- [ ] **Webhook Notifications** - Real-time notifications for events
- [ ] **Mobile App** - React Native mobile application

## Acknowledgments

- [Appwrite](https://appwrite.io/) - Backend-as-a-Service platform
- [Porkbun](https://porkbun.com/) - Domain registration and DNS management
- [Discord](https://discord.com/) - OAuth authentication provider
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework

---

Made by the my-cool.space team
