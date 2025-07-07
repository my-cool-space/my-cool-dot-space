require('dotenv').config();

const discordConfig = {
  clientId: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  redirectUri: process.env.DISCORD_REDIRECT_URI,
  scopes: ['identify', 'email'],
  
  // Discord OAuth URLs
  authUrl: 'https://discord.com/api/oauth2/authorize',
  tokenUrl: 'https://discord.com/api/oauth2/token',
  userUrl: 'https://discord.com/api/users/@me'
};

// Validate required environment variables
if (!discordConfig.clientId) {
  throw new Error('DISCORD_CLIENT_ID environment variable is required');
}

if (!discordConfig.clientSecret) {
  throw new Error('DISCORD_CLIENT_SECRET environment variable is required');
}

if (!discordConfig.redirectUri) {
  throw new Error('DISCORD_REDIRECT_URI environment variable is required');
}

console.log('Discord config loaded:', {
  clientId: discordConfig.clientId ? 'Set' : 'Missing',
  clientSecret: discordConfig.clientSecret ? 'Set' : 'Missing',
  redirectUri: discordConfig.redirectUri
});

module.exports = discordConfig;
