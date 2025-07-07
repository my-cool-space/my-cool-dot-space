// Simple Discord OAuth authentication for my-cool.space
console.log('Discord auth script loaded');

// Make login function globally available
window.loginWithDiscord = function() {
  console.log('Starting Discord OAuth login...');
  window.location.href = '/auth/discord';
};

// Make logout function globally available
window.logoutDiscord = function() {
  console.log('Starting logout...');
  window.location.href = '/auth/logout';
};

// Make authenticated request function
window.makeAuthenticatedRequest = async function(url, options = {}) {
  console.log('Making authenticated request to:', url);
  console.log('Request options:', options);
  
  const response = await fetch(url, {
    ...options,
    credentials: 'include' // Include session cookies
  });
  
  console.log('Response status:', response.status);
  console.log('Response headers:', Object.fromEntries(response.headers.entries()));
  
  if (!response.ok) {
    const errorData = await response.text();
    console.error('Request failed:', {
      status: response.status,
      statusText: response.statusText,
      body: errorData
    });
    
    if (response.status === 401) {
      console.error('Authentication required - redirecting to login');
      alert('Your session has expired. Please log in again.');
      window.location.href = '/';
      return;
    }
    
    // Try to parse as JSON for better error messages
    try {
      const errorJson = JSON.parse(errorData);
      throw new Error(errorJson.error || errorJson.message || `HTTP ${response.status}`);
    } catch (parseError) {
      throw new Error(errorData || `HTTP ${response.status}: ${response.statusText}`);
    }
  }
  
  return response;
};

// Attach to login buttons
document.addEventListener('DOMContentLoaded', () => {
  console.log('Setting up Discord OAuth event listeners...');
  
  // Handle main login button
  const loginBtn = document.getElementById('discord-login-btn');
  if (loginBtn) {
    console.log('Found discord-login-btn, attaching click handler');
    loginBtn.addEventListener('click', window.loginWithDiscord);
  }
  
  // Handle CTA login button
  const ctaBtn = document.getElementById('cta-login-btn');
  if (ctaBtn) {
    console.log('Found cta-login-btn, attaching click handler');
    ctaBtn.addEventListener('click', window.loginWithDiscord);
  }
  
  // Handle logout button
  const logoutBtn = document.querySelector('[onclick="logoutAppwrite()"]');
  if (logoutBtn) {
    console.log('Found logout button, updating to use Discord logout');
    logoutBtn.onclick = window.logoutDiscord;
  }
  
  console.log('Discord OAuth setup complete');
});
