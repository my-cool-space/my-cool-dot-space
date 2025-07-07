const crypto = require('crypto');
const discordConfig = require('./discord-config');

class DiscordOAuth {
  
  // Generate OAuth URL
  static getAuthUrl(state = null) {
    if (!state) {
      state = crypto.randomBytes(16).toString('hex');
    }
    
    const params = new URLSearchParams({
      client_id: discordConfig.clientId,
      redirect_uri: discordConfig.redirectUri,
      response_type: 'code',
      scope: discordConfig.scopes.join(' '),
      state: state
    });
    
    return `${discordConfig.authUrl}?${params.toString()}`;
  }
  
  // Exchange code for access token
  static async getAccessToken(code) {
    const params = new URLSearchParams({
      client_id: discordConfig.clientId,
      client_secret: discordConfig.clientSecret,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: discordConfig.redirectUri
    });
    
    const response = await fetch(discordConfig.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: params.toString()
    });
    
    if (!response.ok) {
      throw new Error(`Discord token exchange failed: ${response.status}`);
    }
    
    return await response.json();
  }
  
  // Get user info using access token
  static async getUser(accessToken) {
    const response = await fetch(discordConfig.userUrl, {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    });
    
    if (!response.ok) {
      throw new Error(`Discord user fetch failed: ${response.status}`);
    }
    
    return await response.json();
  }
  
  // Complete OAuth flow
  static async completeOAuth(code) {
    try {
      console.log('Exchanging code for token...');
      const tokenData = await this.getAccessToken(code);
      
      console.log('Getting user info...');
      const userData = await this.getUser(tokenData.access_token);
      
      return {
        user: userData,
        token: tokenData
      };
    } catch (error) {
      console.error('Discord OAuth error:', error);
      throw error;
    }
  }
}

module.exports = DiscordOAuth;
