// Appwrite Web SDK authentication for Discord OAuth
import { Client, Account } from "https://cdn.jsdelivr.net/npm/appwrite@13.0.0/+esm";

const client = new Client();
client
  .setEndpoint("https://fra.cloud.appwrite.io/v1")
  .setProject("685c3ec100269a27c206");

const account = new Account(client);

// Store current session for API calls
let currentSession = null;
let currentUser = null;

// Make this function globally available
window.makeAuthenticatedRequest = async function(url, options = {}) {
  console.log('Making authenticated request to:', url);
  
  // Try to get fresh session info
  if (!currentSession || !currentUser) {
    console.log('No cached session, fetching fresh session info...');
    try {
      currentUser = await account.get();
      currentSession = await account.getSession('current');
      console.log('Fresh session obtained:', { userId: currentUser.$id, sessionId: currentSession.$id });
    } catch (error) {
      console.error('Failed to get session info:', error);
      console.error('Error details:', error.message, error.code, error.type);
      throw new Error('Not authenticated - please log in again');
    }
  }
  
  const headers = {
    'Content-Type': 'application/json',
    'X-Appwrite-User-ID': currentUser.$id,
    'X-Appwrite-Session-ID': currentSession.$id,
    ...options.headers
  };
  
  console.log('Making authenticated request to:', url, 'with user:', currentUser.name);
  console.log('Request headers:', headers);
  console.log('Request options:', options);
  
  const response = await fetch(url, {
    ...options,
    headers
  });
  
  console.log('Response status:', response.status, response.statusText);
  console.log('Response headers:', Object.fromEntries(response.headers.entries()));
  
  if (!response.ok && response.status === 401) {
    console.error('Authentication expired (401), clearing cached session');
    // Clear cached session and try once more
    currentSession = null;
    currentUser = null;
    throw new Error('Authentication expired - please refresh and log in again');
  }
  
  if (!response.ok) {
    console.error('Request failed with status:', response.status);
    const errorText = await response.text();
    console.error('Error response body:', errorText);
  }
  
  return response;
};

// Make login function globally available
window.loginWithDiscord = function() {
  console.log('Starting Discord OAuth login...');
  
  // Use the current origin to build redirect URLs - direct to dashboard
  const currentOrigin = window.location.origin;
  const successUrl = currentOrigin + '/dashboard';
  const failureUrl = currentOrigin + '/auth/failure';
  
  console.log('OAuth redirect URLs:', { successUrl, failureUrl });
  
  account.createOAuth2Session(
    'discord',
    successUrl,
    failureUrl
  );
};

// Attach to login buttons
window.addEventListener('DOMContentLoaded', () => {
  console.log('Auth script loaded, setting up event listeners...');
  console.log('Current URL:', window.location.href);
  console.log('Current pathname:', window.location.pathname);
  console.log('Current search params:', window.location.search);
  console.log('Current hash:', window.location.hash);
  console.log('Current origin:', window.location.origin);
  
  // Handle dashboard login button
  const loginBtn = document.getElementById('discord-login-btn');
  if (loginBtn) {
    console.log('Found discord-login-btn, attaching click handler');
    loginBtn.addEventListener('click', window.loginWithDiscord);
  } else {
    console.log('discord-login-btn not found');
  }
  
  // Handle index page CTA button  
  const ctaBtn = document.getElementById('cta-login-btn');
  if (ctaBtn) {
    console.log('Found cta-login-btn, attaching click handler');
    ctaBtn.addEventListener('click', window.loginWithDiscord);
  } else {
    console.log('cta-login-btn not found');
  }

  // Check if user is logged in and get session
  console.log('Starting authentication check...');
  
  // Enhanced OAuth callback detection
  const urlParams = new URLSearchParams(window.location.search);
  const isOAuthCallback = window.location.pathname === '/dashboard' && 
                         (urlParams.get('oauth_callback') === 'true' ||
                          window.location.search.includes('userId') || 
                          window.location.hash.includes('userId') ||
                          window.location.search.includes('sessionId') ||
                          window.location.hash.includes('sessionId') ||
                          window.location.search.includes('session') ||
                          window.location.hash.includes('session') ||
                          window.location.search.includes('user') ||
                          window.location.hash.includes('user') ||
                          // Also check if we're on dashboard without any existing session and came from cross-site
                          (window.location.pathname === '/dashboard' && 
                           !localStorage.getItem('appwrite-session') &&
                           document.referrer.includes('appwrite.io')));
  
  console.log('OAuth callback detection:', {
    isDashboard: window.location.pathname === '/dashboard',
    hasOAuthParam: urlParams.get('oauth_callback') === 'true',
    hasParams: window.location.search || window.location.hash,
    hasSession: !!localStorage.getItem('appwrite-session'),
    referrer: document.referrer,
    isOAuthCallback: isOAuthCallback
  });
  
  if (isOAuthCallback) {
    console.log('OAuth callback detected, waiting 7 seconds before authentication check...');
    // Clean the URL to remove the oauth_callback parameter
    if (urlParams.get('oauth_callback') === 'true') {
      urlParams.delete('oauth_callback');
      const newUrl = window.location.pathname + (urlParams.toString() ? '?' + urlParams.toString() : '');
      window.history.replaceState({}, '', newUrl);
    }
    setTimeout(() => checkAuthStatus(), 7000);
  } else {
    console.log('No OAuth callback detected, checking auth immediately');
    checkAuthStatus();
  }
});

async function checkAuthStatus(retryCount = 0) {
  console.log(`Checking authentication status... (attempt ${retryCount + 1})`);
  
  // Check if we just came from OAuth (URL might have fragments)
  const isOAuthCallback = window.location.pathname === '/dashboard' && 
                         (window.location.search.includes('userId') || 
                          window.location.hash.includes('userId') ||
                          window.location.search.includes('sessionId') ||
                          window.location.hash.includes('sessionId'));
  
  if (isOAuthCallback && retryCount === 0) {
    console.log('Detected OAuth callback, waiting for session to be established...');
    // Wait a bit longer for OAuth session to be properly established
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  
  try {
    console.log('Getting current user...');
    currentUser = await account.get();
    console.log('Getting current session...');
    currentSession = await account.getSession('current');
    
    console.log('User authenticated:', currentUser.name, 'Session ID:', currentSession.$id);
    console.log('Full user object:', currentUser);
    console.log('Full session object:', currentSession);
    
    // Update UI to show user is logged in
    const userNameElements = document.querySelectorAll('.user-name');
    console.log('Found', userNameElements.length, 'user-name elements to update');
    userNameElements.forEach(el => {
      console.log('Updating user-name element with:', currentUser.name);
      el.textContent = currentUser.name;
    });
    document.body.classList.add('logged-in');
    
    // Store session info for backup
    const sessionData = {
      userId: currentUser.$id,
      sessionId: currentSession.$id,
      userName: currentUser.name
    };
    console.log('Storing session data in localStorage:', sessionData);
    localStorage.setItem('appwrite-session', JSON.stringify(sessionData));
    
    // If we're on dashboard page, trigger setup
    if (window.location.pathname === '/dashboard' && typeof checkAuthAndSetupDashboard === 'function') {
      console.log('On dashboard page, triggering setup...');
      setTimeout(() => checkAuthAndSetupDashboard(), 100);
    }
    
  } catch (error) {
    console.log('User not authenticated (this is normal for first-time visitors):', error.message);
    
    // Only log full error details if it's not the expected "guests missing scope" error
    if (!error.message.includes('guests) missing scope')) {
      console.error('Unexpected authentication error:', error);
    } else {
      console.log('User needs to log in with Discord OAuth');
    }
    
    document.body.classList.remove('logged-in');
    localStorage.removeItem('appwrite-session');
    currentUser = null;
    currentSession = null;
    
    // If we're on dashboard without auth, try to retry for OAuth callbacks
    if (window.location.pathname === '/dashboard') {
      if (isOAuthCallback && retryCount < 5) {
        const delay = Math.pow(2, retryCount) * 1500; // Longer delays: 1.5s, 3s, 6s, 12s, 24s
        console.log(`OAuth callback detected but auth failed, retrying in ${delay}ms (attempt ${retryCount + 1}/5)...`);
        setTimeout(() => checkAuthStatus(retryCount + 1), delay);
        return; // Don't redirect immediately
      } else {
        console.log('Not authenticated on dashboard, redirecting to home');
        window.location.href = '/';
      }
    }
  }
}

// Logout handler
window.logoutAppwrite = function() {
  console.log('Starting logout process...');
  account.deleteSession('current').then(() => {
    console.log('Session deleted successfully');
    localStorage.removeItem('appwrite-session');
    currentUser = null;
    currentSession = null;
    window.location.href = '/';
  }).catch(error => {
    console.error('Logout error:', error);
    console.error('Logout error details:', error.message, error.code, error.type);
    // Force logout anyway
    console.log('Forcing logout despite error...');
    localStorage.removeItem('appwrite-session');
    currentUser = null;
    currentSession = null;
    window.location.href = '/';
  });
};
