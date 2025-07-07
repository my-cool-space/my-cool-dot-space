const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const appwriteClient = require('./src/appwrite');
const DiscordOAuth = require('./src/discord-oauth');

const app = express();
const PORT = process.env.PORT || 3000;

// Maintenance mode configuration
let MAINTENANCE_MODE = process.env.MAINTENANCE_MODE === 'true' || false;
// Make it globally accessible
global.MAINTENANCE_MODE = MAINTENANCE_MODE;

// Admin settings with defaults
let ADMIN_SETTINGS = {
  maxSubdomains: 1,
  domainName: 'my-cool.space',
  autoApprove: false,
  maintenanceMode: MAINTENANCE_MODE
};

// Load admin settings from database on startup
async function loadAdminSettings() {
  try {
    console.log('Loading admin settings from database...');
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    const settings = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SETTINGS_COLLECTION_ID || 'admin_settings'
    );
    
    if (settings.documents.length > 0) {
      const settingsDoc = settings.documents[0];
      ADMIN_SETTINGS = {
        maxSubdomains: settingsDoc.max_subdomains || 1,
        domainName: settingsDoc.domain_name || 'my-cool.space',
        autoApprove: settingsDoc.auto_approve || false,
        maintenanceMode: settingsDoc.maintenance_mode !== undefined ? settingsDoc.maintenance_mode : MAINTENANCE_MODE
      };
      global.MAINTENANCE_MODE = ADMIN_SETTINGS.maintenanceMode;
      console.log('✅ Admin settings loaded:', ADMIN_SETTINGS);
    } else {
      console.log('No admin settings found in database, using defaults');
      // Create default settings document
      await saveAdminSettingsToDatabase();
    }
  } catch (error) {
    console.warn('Failed to load admin settings from database:', error.message);
    console.log('Using default admin settings');
  }
}

// Save admin settings to database
async function saveAdminSettingsToDatabase() {
  try {
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    // First try to get existing settings
    const existingSettings = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_SETTINGS_COLLECTION_ID || 'admin_settings'
    );
    
    const settingsData = {
      max_subdomains: ADMIN_SETTINGS.maxSubdomains,
      domain_name: ADMIN_SETTINGS.domainName,
      auto_approve: ADMIN_SETTINGS.autoApprove,
      maintenance_mode: ADMIN_SETTINGS.maintenanceMode,
      updated_at: new Date().toISOString()
    };
    
    if (existingSettings.documents.length > 0) {
      // Update existing settings
      await databases.updateDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_SETTINGS_COLLECTION_ID || 'admin_settings',
        existingSettings.documents[0].$id,
        settingsData
      );
    } else {
      // Create new settings document
      await databases.createDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_SETTINGS_COLLECTION_ID || 'admin_settings',
        'unique()',
        {
          ...settingsData,
          created_at: new Date().toISOString()
        }
      );
    }
    console.log('✅ Admin settings saved to database');
  } catch (error) {
    console.error('Failed to save admin settings to database:', error);
    throw error;
  }
}

// Make it globally accessible
global.ADMIN_SETTINGS = ADMIN_SETTINGS;

// Helper function to check if user is admin
// Helper function to check if user is admin
async function isAdminUser(sessionUser) {
  if (!sessionUser || !sessionUser.id) {
    return false;
  }
  
  // Check Appwrite user labels for "admin" label
  try {
    const { Users } = require('node-appwrite');
    const users = new Users(appwriteClient);
    const appwriteUser = await users.get(sessionUser.id);
    
    // Check if user has "admin" label
    return appwriteUser.labels && appwriteUser.labels.includes('admin');
  } catch (error) {
    console.error('Error checking admin status:', error);
    return false;
  }
}

// Helper function to log user actions
function logUserAction(user, action, details = {}) {
  const timestamp = new Date().toISOString();
  const logEntry = {
    timestamp,
    user: {
      id: user?.id || 'anonymous',
      username: user?.username || 'unknown',
      email: user?.email || 'unknown'
    },
    action,
    details,
    ip: details.ip || 'unknown'
  };
  
  console.log(`📝 [USER ACTION] ${timestamp} | ${user?.username || 'anonymous'} | ${action} |`, JSON.stringify(details, null, 2));
  
  // In production, you might want to store this in a database or external logging service
  return logEntry;
}

// Middleware
app.use(cors());

// Security headers with helmet
const helmet = require('helmet');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      scriptSrcAttr: ["'unsafe-inline'"], // Allow inline event handlers (onclick, etc.)
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'none'"],
      baseUri: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false, // Disable if causing issues with external resources
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  }
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// More restrictive rate limiting for subdomain requests
const subdomainLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // Limit each IP to 5 subdomain requests per hour
  message: 'Too many subdomain requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-this',
  resave: true, // Force session save on each request
  saveUninitialized: true, // Save uninitialized sessions
  rolling: true, // Reset expiration on each request
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Only send cookie over HTTPS
    httpOnly: true, // Prevent JS access to cookies
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
    sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax', // Lax for development
    path: '/',
  },
  name: 'mycoolspace.sid', // Custom session cookie name
  proxy: process.env.NODE_ENV === 'production', // Trust proxy for secure cookies
}));

app.use(express.static(path.join(__dirname, 'public')));

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Enhanced maintenance mode middleware
app.use((req, res, next) => {
  if (global.MAINTENANCE_MODE) {
    // Allow access to static files (CSS, images, etc.)
    if (req.path.startsWith('/public') || req.path.match(/\.(css|js|png|jpg|jpeg|gif|ico|svg)$/)) {
      return next();
    }
    // Allow access to landing page
    if (req.path === '/') {
      return next();
    }
    // Allow access to privacy and terms pages
    if (req.path === '/privacy' || req.path === '/terms') {
      return next();
    }
    // Allow Discord OAuth login and callback
    if (req.path.startsWith('/auth/discord') || req.path === '/auth/callback' || req.path === '/auth/failure' || req.path === '/auth/logout') {
      return next();
    }
    // Allow access to admin-related pages (admins can always access admin panel)
    if (req.path.startsWith('/admin') || req.path.startsWith('/api/admin') || req.path === '/access-denied') {
      return next();
    }
    // Show maintenance page for ALL other pages (including dashboard, even for admins)
    return res.status(503).render('maintenance', { 
      title: 'Maintenance - my-cool.space' 
    });
  }
  next();
});

// Routes
app.get('/', (req, res) => {
  console.log('🏠 [PAGE] Home page visit');
  logUserAction(req.session?.user, 'page_visit', { 
    page: 'home',
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.render('index', { 
    title: 'my-cool.space - Free Subdomains',
    user: req.session.user || null
  });
});

app.get('/dashboard', (req, res) => {
  // Check if user is authenticated
  console.log('🏠 [DASHBOARD] Dashboard access attempt:');
  console.log('🏠 [DASHBOARD] - Session exists:', !!req.session);
  console.log('🏠 [DASHBOARD] - Session ID:', req.sessionID);
  console.log('🏠 [DASHBOARD] - Session user:', req.session?.user?.username || 'none');
  
  if (!req.session.user) {
    console.log('🏠 [DASHBOARD] User not authenticated, redirecting to home');
    logUserAction(null, 'dashboard_access_denied', { 
      reason: 'not_authenticated',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return res.redirect('/?error=not_authenticated');
  }
  
  console.log('🏠 [DASHBOARD] Authenticated user accessing dashboard:', req.session.user.username);
  logUserAction(req.session.user, 'dashboard_access', { 
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.render('dashboard', { 
    title: 'Dashboard - my-cool.space',
    user: req.session.user
  });
});

app.get('/admin', async (req, res) => {
  console.log('👑 [ADMIN] Admin panel access attempt');
  
  // Check if user is logged in
  if (!req.session || !req.session.user) {
    console.log('👑 [ADMIN] Access denied - not logged in');
    logUserAction(null, 'admin_access_denied', { 
      reason: 'not_logged_in',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return res.redirect('/?error=Please log in to access admin panel');
  }

  // Check if user is admin
  const isAdmin = await isAdminUser(req.session.user);
  if (!isAdmin) {
    console.log('👑 [ADMIN] Access denied - not admin:', req.session.user.username);
    logUserAction(req.session.user, 'admin_access_denied', { 
      reason: 'insufficient_privileges',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return res.status(403).render('access-denied', { 
      title: 'Access Denied - my-cool.space',
      error: 'You do not have admin privileges',
      user: req.session.user || null
    });
  }

  console.log('👑 [ADMIN] Admin access granted:', req.session.user.username);
  logUserAction(req.session.user, 'admin_panel_access', { 
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // User is authenticated and is admin
  res.render('admin', { 
    title: 'Admin Panel - my-cool.space',
    user: req.session.user,
    requests: []
  });
});

app.get('/success', (req, res) => {
  res.render('success', { 
    title: 'Success - my-cool.space',
    subdomain: req.query.subdomain
  });
});

app.get('/terms', (req, res) => {
  res.render('terms', { 
    title: 'Terms of Service - my-cool.space'
  });
});

app.get('/privacy', (req, res) => {
  res.render('privacy', { 
    title: 'Privacy Policy - my-cool.space',
    user: req.session.user || null
  });
});

app.get('/report-abuse', (req, res) => {
  console.log('📢 [PAGE] Abuse report page visit');
  logUserAction(req.session?.user, 'page_visit', { 
    page: 'report_abuse',
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.render('report-abuse', { 
    title: 'Report Abuse - my-cool.space',
    user: req.session.user || null
  });
});

app.get('/deletion', (req, res) => {
  console.log('🗑️ [PAGE] Deletion request page visit');
  logUserAction(req.session?.user, 'page_visit', { 
    page: 'deletion_request',
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  res.render('deletion', { 
    title: 'Request Data Deletion - my-cool.space',
    user: req.session.user || null
  });
});

app.get('/account-settings', (req, res) => {
  res.render('account-settings', { 
    title: 'Account Settings - my-cool.space',
    user: req.session.user || null
  });
});

// Debug route for OAuth testing
app.get('/debug-oauth', (req, res) => {
  res.sendFile(path.join(__dirname, 'debug-oauth.html'));
});

// Discord OAuth routes
app.get('/auth/discord', (req, res) => {
  console.log('🔐 [AUTH] Starting Discord OAuth...');
  logUserAction(null, 'oauth_start', { ip: req.ip, userAgent: req.get('User-Agent') });
  
  const authUrl = DiscordOAuth.getAuthUrl();
  console.log('🔐 [AUTH] Redirecting to Discord:', authUrl);
  res.redirect(authUrl);
});

app.get('/auth/discord/callback', async (req, res) => {
  console.log('🔐 [AUTH] === Discord OAuth Callback ===');
  console.log('🔐 [AUTH] Query params:', req.query);
  
  const { code, error, error_description } = req.query;
  
  if (error) {
    console.error('🔐 [AUTH] Discord OAuth error:', error, error_description);
    logUserAction(null, 'oauth_failed', { 
      error, 
      error_description, 
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    return res.redirect('/?error=oauth_failed');
  }
  
  if (!code) {
    console.error('🔐 [AUTH] No authorization code received');
    logUserAction(null, 'oauth_no_code', { ip: req.ip, userAgent: req.get('User-Agent') });
    return res.redirect('/?error=no_code');
  }
  
  try {
    console.log('🔐 [AUTH] Completing OAuth with code:', code.substring(0, 10) + '...');
    const { user, token } = await DiscordOAuth.completeOAuth(code);
    
    console.log('🔐 [AUTH] Discord OAuth successful for user:', user.username);
    logUserAction(user, 'oauth_success', { 
      provider: 'discord',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    // Create or update user in Appwrite
    const { Users } = require('node-appwrite');
    const users = new Users(appwriteClient);
    
    let appwriteUser;
    let isNewUser = false;
    try {
      // Try to get existing user by Discord ID
      appwriteUser = await users.get(user.id);
      console.log('🔐 [AUTH] Found existing Appwrite user:', appwriteUser.name);
      logUserAction(user, 'user_login', { 
        userType: 'existing',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      // Update user info in case it changed
      try {
        appwriteUser = await users.updateName(user.id, user.username);
      } catch (nameError) {
        console.warn('🔐 [AUTH] Failed to update username:', nameError.message);
      }
      
      try {
        appwriteUser = await users.updateEmail(user.id, user.email);
      } catch (emailError) {
        console.warn('🔐 [AUTH] Failed to update email (possibly already exists):', emailError.message);
        // Continue with login even if email update fails
      }

      // Mark user as verified and update last login
      try {
        console.log('🔐 [AUTH] Marking user as verified and updating last login...');
        await users.updateEmailVerification(user.id, true);
        console.log('🔐 [AUTH] User marked as verified');
      } catch (verifyError) {
        console.warn('🔐 [AUTH] Failed to mark user as verified:', verifyError.message);
      }

      // Update user preferences with last login
      try {
        const currentPrefs = appwriteUser.prefs || {};
        await users.updatePrefs(user.id, {
          ...currentPrefs,
          last_login: new Date().toISOString(),
          login_count: (currentPrefs.login_count || 0) + 1,
          discord_username: user.username,
          discord_discriminator: user.discriminator || '0',
          discord_avatar: user.avatar,
          discord_verified: user.verified
        });
        console.log('🔐 [AUTH] Updated user preferences with last login');
      } catch (prefsError) {
        console.warn('🔐 [AUTH] Failed to update user preferences:', prefsError.message);
      }
      
    } catch (userError) {
      if (userError.code === 404) {
        isNewUser = true;
        console.log('🔐 [AUTH] Creating new Appwrite user...');
        logUserAction(user, 'user_registration', { 
          provider: 'discord',
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
        
        // Create new user in Appwrite
        appwriteUser = await users.create(
          user.id, // Use Discord ID as Appwrite user ID
          user.email,
          undefined, // phone (optional)
          undefined, // password (not needed for OAuth)
          user.username // name
        );

        // Mark new user as verified
        try {
          console.log('🔐 [AUTH] Marking new user as verified...');
          await users.updateEmailVerification(user.id, true);
          console.log('🔐 [AUTH] New user marked as verified');
        } catch (verifyError) {
          console.warn('🔐 [AUTH] Failed to mark new user as verified:', verifyError.message);
        }
        
        // Set default user preferences (without admin flag)
        await users.updatePrefs(user.id, {
          discord_username: user.username,
          discord_discriminator: user.discriminator || '0',
          discord_avatar: user.avatar,
          discord_verified: user.verified,
          created_via: 'discord_oauth',
          created_at: new Date().toISOString(),
          first_login: new Date().toISOString(),
          last_login: new Date().toISOString(),
          login_count: 1
        });
        
        console.log('🔐 [AUTH] Created new Appwrite user:', appwriteUser.name);
        logUserAction(user, 'user_created', { 
          appwriteUserId: appwriteUser.$id,
          ip: req.ip,
          userAgent: req.get('User-Agent')
        });
      } else {
        throw userError;
      }
    }
    
    // Store user in session with Appwrite data
    req.session.user = {
      id: user.id,
      username: user.username,
      discriminator: user.discriminator || '0',
      avatar: user.avatar,
      email: user.email,
      verified: user.verified,
      appwriteUser: appwriteUser,
      prefs: appwriteUser.prefs || {}
    };
    
    console.log('🔐 [AUTH] User session created:', {
      username: req.session.user.username,
      email: req.session.user.email,
      isNewUser: isNewUser
    });
    console.log('🔐 [AUTH] Session ID:', req.sessionID);
    
    logUserAction(req.session.user, 'session_created', { 
      sessionId: req.sessionID,
      isNewUser: isNewUser,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    // Force session save before redirect
    req.session.save((err) => {
      if (err) {
        console.error('🔐 [AUTH] Session save error:', err);
        logUserAction(req.session.user, 'session_save_failed', { 
          error: err.message,
          ip: req.ip
        });
        return res.status(500).send('Session save failed');
      }
      console.log('🔐 [AUTH] Session saved successfully, redirecting to dashboard');
      logUserAction(req.session.user, 'login_complete', { 
        redirectTo: '/dashboard',
        ip: req.ip
      });
      res.redirect('/dashboard');
    });
    
  } catch (error) {
    console.error('🔐 [AUTH] Discord OAuth completion error:', error);
    logUserAction(null, 'oauth_completion_failed', { 
      error: error.message,
      stack: error.stack,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    res.redirect('/?error=oauth_completion_failed');
  }
});

// Auth routes - now using Discord OAuth directly
app.get('/auth/callback', (req, res) => {
  // Legacy route - redirect to Discord callback
  res.redirect('/auth/discord/callback');
});

app.get('/auth/failure', (req, res) => {
  res.send('Authentication failed. <a href="/">Go back</a>');
});

app.get('/auth/logout', (req, res) => {
  const user = req.session?.user;
  console.log('🔐 [AUTH] User logging out:', user?.username || 'unknown');
  
  logUserAction(user, 'logout', { 
    sessionId: req.sessionID,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  req.session.destroy((err) => {
    if (err) {
      console.error('🔐 [AUTH] Session destruction error:', err);
      logUserAction(user, 'logout_failed', { 
        error: err.message,
        ip: req.ip
      });
    } else {
      console.log('🔐 [AUTH] Session destroyed successfully');
      logUserAction(user, 'logout_complete', { ip: req.ip });
    }
    res.clearCookie('mycoolspace.sid'); // Clear our custom session cookie name
    res.redirect('/');
  });
});

// API routes
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    appwrite_configured: !!(process.env.APPWRITE_PROJECT_ID && process.env.APPWRITE_DATABASE_ID),
    discord_configured: !!process.env.DISCORD_CLIENT_ID,
    porkbun_configured: !!(process.env.PORKBUN_API_KEY && process.env.PORKBUN_SECRET_KEY),
    timestamp: new Date().toISOString(),
    authenticated: !!(req.session && req.session.user),
    user: req.session?.user || null,
    sessionID: req.sessionID,
    adminSettings: global.ADMIN_SETTINGS
  });
});

app.get('/api/session-check', (req, res) => {
  console.log('=== Session Check ===');
  console.log('Session exists:', !!req.session);
  console.log('Session user:', req.session?.user);
  console.log('Session ID:', req.sessionID);
  console.log('Cookies:', req.headers.cookie);
  
  res.json({
    authenticated: !!(req.session && req.session.user),
    user: req.session?.user || null,
    sessionID: req.sessionID,
    sessionExists: !!req.session,
    hasUser: !!(req.session && req.session.user)
  });
});

// Debug route to test OAuth URL generation
app.get('/api/debug/oauth', async (req, res) => {
  try {
    const { Account } = require('node-appwrite');
    const account = new Account(appwriteClient);
    
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    console.log('Base URL:', baseUrl);
    console.log('Success URL:', `${baseUrl}/dashboard`);
    console.log('Failure URL:', `${baseUrl}/auth/failure`);
    
    const redirectUrl = await account.createOAuth2Token(
      'discord',
      `${baseUrl}/dashboard`,
      `${baseUrl}/auth/failure`
    );
    
    res.json({
      success: true,
      redirectUrl: redirectUrl,
      baseUrl: baseUrl,
      successUrl: `${baseUrl}/dashboard`,
      failureUrl: `${baseUrl}/auth/failure`
    });
  } catch (error) {
    res.json({
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// Abuse report submission endpoint
app.post('/api/report-abuse', async (req, res) => {
  console.log('📢 [ABUSE] === POST /api/report-abuse ===');
  
  try {
    const { reporterEmail, reportedSubdomain, abuseType, description, evidenceUrl } = req.body;
    
    console.log('📢 [ABUSE] Abuse report submission attempt');
    logUserAction(req.session?.user, 'abuse_report_attempt', { 
      reporterEmail,
      reportedSubdomain,
      abuseType,
      hasEvidence: !!evidenceUrl,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    // Input validation
    if (!reporterEmail || !reportedSubdomain || !abuseType || !description) {
      logUserAction(req.session?.user, 'abuse_report_failed', { 
        reason: 'missing_fields',
        provided: { 
          reporterEmail: !!reporterEmail, 
          reportedSubdomain: !!reportedSubdomain, 
          abuseType: !!abuseType, 
          description: !!description 
        },
        ip: req.ip
      });
      return res.status(400).json({ error: 'All required fields must be filled' });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(reporterEmail)) {
      return res.status(400).json({ error: 'Invalid email address format' });
    }
    
    // Validate subdomain format
    const subdomainRegex = /^[a-zA-Z0-9-]+\.my-cool\.space$/;
    if (!subdomainRegex.test(reportedSubdomain)) {
      return res.status(400).json({ error: 'Invalid subdomain format. Must be in format: subdomain.my-cool.space' });
    }
    
    // Validate abuse type
    const validAbuseTypes = ['spam', 'phishing', 'malware', 'illegal_content', 'copyright', 'harassment', 'fake_identity', 'other'];
    if (!validAbuseTypes.includes(abuseType)) {
      return res.status(400).json({ error: 'Invalid abuse type' });
    }
    
    // Validate description length
    if (description.length < 10 || description.length > 2000) {
      return res.status(400).json({ error: 'Description must be between 10 and 2000 characters' });
    }
    
    // Validate evidence URL if provided
    if (evidenceUrl) {
      try {
        new URL(evidenceUrl);
      } catch {
        return res.status(400).json({ error: 'Invalid evidence URL format' });
      }
    }
    
    console.log('Creating abuse report in database...');
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    // Create abuse report
    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_ABUSE_COLLECTION_ID,
      'unique()',
      {
        reporter_email: reporterEmail,
        reported_subdomain: reportedSubdomain,
        abuse_type: abuseType,
        description: description,
        evidence_url: evidenceUrl || '',
        status: 'pending',
        created_at: new Date().toISOString()
      }
    );
    
    console.log('📢 [ABUSE] Abuse report created successfully:', document.$id);
    logUserAction(req.session?.user, 'abuse_report_created', { 
      reportId: document.$id,
      reporterEmail,
      reportedSubdomain,
      abuseType,
      hasEvidence: !!evidenceUrl,
      ip: req.ip
    });
    
    res.json({ 
      success: true, 
      reportId: document.$id,
      message: 'Abuse report submitted successfully. We will review it and take appropriate action.'
    });
    
  } catch (error) {
    console.error('📢 [ABUSE] Submit abuse report error:', error);
    logUserAction(req.session?.user, 'abuse_report_failed', { 
      reason: 'unexpected_error',
      error: error.message,
      ip: req.ip
    });
    res.status(500).json({ error: 'Failed to submit abuse report. Please try again later.' });
  }
});

// Admin API endpoints for subdomain requests
app.get('/api/admin/requests', async (req, res) => {
  console.log('=== GET /api/admin/requests ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      [
        Query.orderDesc('created_at'),
        Query.limit(100)
      ]
    );

    console.log(`Found ${response.documents.length} subdomain requests`);
    res.json({ success: true, requests: response.documents });

  } catch (error) {
    console.error('Get subdomain requests error:', error);
    res.status(500).json({ error: 'Failed to load subdomain requests' });
  }
});

// Admin API endpoints for abuse reports
app.get('/api/admin/abuse-reports', async (req, res) => {
  console.log('=== GET /api/admin/abuse-reports ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_ABUSE_COLLECTION_ID,
      [
        Query.orderDesc('created_at'),
        Query.limit(100)
      ]
    );

    console.log(`Found ${response.documents.length} abuse reports`);
    res.json({ success: true, reports: response.documents });

  } catch (error) {
    console.error('Get abuse reports error:', error);
    res.status(500).json({ error: 'Failed to load abuse reports' });
  }
});

app.post('/api/admin/abuse-reports/:id/resolve', async (req, res) => {
  console.log('=== POST /api/admin/abuse-reports/:id/resolve ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const reportId = req.params.id;
    const { notes } = req.body;

    if (!reportId) {
      return res.status(400).json({ error: 'Report ID is required' });
    }

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Update the abuse report
    const updatedDocument = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_ABUSE_COLLECTION_ID,
      reportId,
      {
        status: 'resolved',
        admin_notes: notes || '',
        resolved_by: req.session.user.username || req.session.user.global_name || 'Admin',
        updated_at: new Date().toISOString()
      }
    );

    console.log('Abuse report resolved:', reportId);
    res.json({ success: true, report: updatedDocument });

  } catch (error) {
    console.error('Resolve abuse report error:', error);
    res.status(500).json({ error: 'Failed to resolve abuse report' });
  }
});

app.post('/api/admin/abuse-reports/:id/dismiss', async (req, res) => {
  console.log('=== POST /api/admin/abuse-reports/:id/dismiss ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const reportId = req.params.id;
    const { notes } = req.body;

    if (!reportId) {
      return res.status(400).json({ error: 'Report ID is required' });
    }

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Update the abuse report
    const updatedDocument = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_ABUSE_COLLECTION_ID,
      reportId,
      {
        status: 'dismissed',
        admin_notes: notes || '',
        resolved_by: req.session.user.username || req.session.user.global_name || 'Admin',
        updated_at: new Date().toISOString()
      }
    );

    console.log('Abuse report dismissed:', reportId);
    res.json({ success: true, report: updatedDocument });

  } catch (error) {
    console.error('Dismiss abuse report error:', error);
    res.status(500).json({ error: 'Failed to dismiss abuse report' });
  }
});

// User management endpoints
app.get('/api/admin/users', async (req, res) => {
  console.log('=== GET /api/admin/users ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { search } = req.query;
    console.log('📊 Search query:', search);
    
    const { Users } = require('node-appwrite');
    const { Databases, Query } = require('node-appwrite');
    
    const users = new Users(appwriteClient);
    const databases = new Databases(appwriteClient);

    // Get all users from Appwrite
    console.log('📊 Fetching all users from Appwrite...');
    let allUsers;
    try {
      // Try different approaches to list users
      console.log('📊 Attempting users.list() with no parameters...');
      allUsers = await users.list();
      console.log('📊 users.list() result:', { total: allUsers.total, users: allUsers.users?.length });
      
      if (allUsers.total === 0 || !allUsers.users || allUsers.users.length === 0) {
        console.log('📊 No users found with users.list(), trying with queries...');
        const { Query } = require('node-appwrite');
        allUsers = await users.list([Query.limit(100)]);
        console.log('📊 users.list() with Query.limit(100):', { total: allUsers.total, users: allUsers.users?.length });
      }
      
      if (allUsers.total === 0 || !allUsers.users || allUsers.users.length === 0) {
        console.log('📊 Still no users found, checking if current user exists individually...');
        try {
          const currentUser = await users.get(req.session.user.id);
          console.log('📊 Current user exists individually:', currentUser.name);
          // Create a mock response with the current user
          allUsers = {
            total: 1,
            users: [currentUser]
          };
        } catch (userError) {
          console.error('📊 Error getting current user:', userError);
          allUsers = { total: 0, users: [] };
        }
      }
    } catch (error) {
      console.error('📊 Error listing users:', error);
      allUsers = { total: 0, users: [] };
    }
    
    // Get subdomain requests to count subdomains per user and enable search
    console.log('📊 Fetching subdomain requests for user stats and search...');
    const subdomainRequests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID
    );

    // Create a map of subdomain counts per user and collect subdomain info
    const subdomainCounts = new Map();
    const lastActivity = new Map();
    const userSubdomains = new Map(); // Map user_id to array of subdomains
    
    subdomainRequests.documents.forEach(req => {
      const userId = req.user_id;
      subdomainCounts.set(userId, (subdomainCounts.get(userId) || 0) + 1);
      
      // Store subdomain info for search
      if (!userSubdomains.has(userId)) {
        userSubdomains.set(userId, []);
      }
      userSubdomains.get(userId).push({
        subdomain: req.subdomain,
        status: req.status,
        created_at: req.created_at
      });
      
      const reqDate = new Date(req.created_at);
      if (!lastActivity.has(userId) || reqDate > lastActivity.get(userId)) {
        lastActivity.set(userId, reqDate);
      }
    });

    // Transform Appwrite users to our format
    let usersData = (allUsers.users || []).map(user => {
      const subdomainCount = subdomainCounts.get(user.$id) || 0;
      const userLastActivity = lastActivity.get(user.$id);
      const userSubs = userSubdomains.get(user.$id) || [];
      
      return {
        id: user.$id,
        username: user.name || user.email?.split('@')[0] || 'Unknown',
        email: user.email || 'Not available',
        status: user.status ? 'active' : 'inactive', // Appwrite user status
        subdomainCount: subdomainCount,
        subdomains: userSubs,
        lastActive: userLastActivity ? userLastActivity.toISOString() : user.$createdAt,
        createdAt: user.$createdAt,
        verified: user.emailVerification || false,
        labels: user.labels || [],
        isAdmin: user.labels && user.labels.includes('admin')
      };
    });

    // Apply search filter if provided
    if (search && search.trim()) {
      const searchTerm = search.trim().toLowerCase();
      console.log('📊 Applying search filter for:', searchTerm);
      
      usersData = usersData.filter(user => {
        // Search in username
        if (user.username.toLowerCase().includes(searchTerm)) {
          return true;
        }
        
        // Search in email
        if (user.email.toLowerCase().includes(searchTerm)) {
          return true;
        }
        
        // Search in user ID (Discord ID)
        if (user.id.toLowerCase().includes(searchTerm)) {
          return true;
        }
        
        // Search in subdomains
        if (user.subdomains.some(sub => sub.subdomain.toLowerCase().includes(searchTerm))) {
          return true;
        }
        
        return false;
      });
      
      console.log(`📊 Search filtered ${usersData.length} users`);
    }

    console.log(`📊 Found ${allUsers.total || 0} total users in Appwrite`);
    console.log(`📊 ${usersData.filter(u => u.subdomainCount > 0).length} users have subdomain requests`);
    
    res.json({ 
      success: true, 
      users: usersData,
      total: usersData.length,
      totalInDatabase: allUsers.total || 0,
      isFiltered: !!(search && search.trim()),
      searchTerm: search || null,
      stats: {
        totalUsers: allUsers.total || 0, // Total in database
        filteredUsers: usersData.length,   // After search filter
        activeUsers: usersData.filter(u => u.status === 'active').length,
        usersWithSubdomains: usersData.filter(u => u.subdomainCount > 0).length,
        adminUsers: usersData.filter(u => u.isAdmin).length
      }
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to load users: ' + error.message });
  }
});

// Debug endpoint for troubleshooting user listing
app.get('/api/admin/debug-users', async (req, res) => {
  console.log('=== GET /api/admin/debug-users ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { Users } = require('node-appwrite');
    const users = new Users(appwriteClient);

    console.log('🔍 DEBUG: Testing different user listing methods...');
    
    let debugInfo = {
      currentUser: null,
      listMethods: {},
      error: null
    };

    // Test getting current user
    try {
      debugInfo.currentUser = await users.get(req.session.user.id);
      console.log('🔍 DEBUG: Current user found:', debugInfo.currentUser.name);
    } catch (error) {
      debugInfo.currentUser = { error: error.message };
      console.log('🔍 DEBUG: Current user error:', error.message);
    }

    // Test users.list() with no parameters
    try {
      const list1 = await users.list();
      debugInfo.listMethods.noParams = {
        total: list1.total,
        usersCount: list1.users ? list1.users.length : 0,
        success: true
      };
      console.log('🔍 DEBUG: users.list() no params:', debugInfo.listMethods.noParams);
    } catch (error) {
      debugInfo.listMethods.noParams = { error: error.message, success: false };
      console.log('🔍 DEBUG: users.list() no params error:', error.message);
    }

    // Test users.list() with queries
    try {
      const { Query } = require('node-appwrite');
      const list2 = await users.list([Query.limit(100)]);
      debugInfo.listMethods.withQuery = {
        total: list2.total,
        usersCount: list2.users ? list2.users.length : 0,
        success: true
      };
      console.log('🔍 DEBUG: users.list() with Query:', debugInfo.listMethods.withQuery);
    } catch (error) {
      debugInfo.listMethods.withQuery = { error: error.message, success: false };
      console.log('🔍 DEBUG: users.list() with Query error:', error.message);
    }

    // Test users.list() with different parameters
    try {
      const list3 = await users.list([], 100);
      debugInfo.listMethods.oldStyle = {
        total: list3.total,
        usersCount: list3.users ? list3.users.length : 0,
        success: true
      };
      console.log('🔍 DEBUG: users.list([], 100):', debugInfo.listMethods.oldStyle);
    } catch (error) {
      debugInfo.listMethods.oldStyle = { error: error.message, success: false };
      console.log('🔍 DEBUG: users.list([], 100) error:', error.message);
    }

    res.json({
      success: true,
      debug: debugInfo,
      appwriteClient: {
        configured: !!appwriteClient,
        endpoint: process.env.APPWRITE_ENDPOINT || 'not set',
        projectId: process.env.APPWRITE_PROJECT_ID || 'not set'
      }
    });

  } catch (error) {
    console.error('🔍 DEBUG: General error:', error);
    res.status(500).json({ 
      success: false,
      error: error.message,
      stack: error.stack
    });
  }
});

// Search users by subdomain endpoint
app.get('/api/admin/search-user-by-subdomain/:subdomain', async (req, res) => {
  console.log('=== GET /api/admin/search-user-by-subdomain ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const subdomain = req.params.subdomain.toLowerCase();
    console.log('🔍 Searching for user by subdomain:', subdomain);
    
    const { Databases, Query } = require('node-appwrite');
    const { Users } = require('node-appwrite');
    
    const databases = new Databases(appwriteClient);
    const users = new Users(appwriteClient);

    // Find subdomain request
    const subdomainRequests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      [
        Query.equal('subdomain', subdomain)
      ]
    );

    if (subdomainRequests.documents.length === 0) {
      return res.json({ 
        success: true, 
        found: false,
        message: `No subdomain request found for "${subdomain}"` 
      });
    }

    const request = subdomainRequests.documents[0];
    const userId = request.user_id;

    // Get user details
    let user = null;
    try {
      user = await users.get(userId);
    } catch (error) {
      console.warn('User not found in Appwrite:', userId);
    }

    res.json({ 
      success: true, 
      found: true,
      subdomain: subdomain,
      request: {
        id: request.$id,
        subdomain: request.subdomain,
        target_url: request.target_url,
        status: request.status,
        created_at: request.created_at,
        discord_tag: request.discord_tag
      },
      user: user ? {
        id: user.$id,
        username: user.name,
        email: user.email,
        verified: user.emailVerification,
        labels: user.labels,
        isAdmin: user.labels && user.labels.includes('admin')
      } : null
    });

  } catch (error) {
    console.error('Search user by subdomain error:', error);
    res.status(500).json({ error: 'Failed to search for user: ' + error.message });
  }
});

app.post('/api/admin/users/:id/suspend', async (req, res) => {
  console.log('=== POST /api/admin/users/:id/suspend ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const userId = req.params.id;
    const { reason } = req.body;

    // For now, we'll just return success since we don't have a user suspension system in place
    // In a real implementation, you'd update a user status table
    console.log(`Suspended user ${userId} for reason: ${reason}`);
    res.json({ success: true, message: 'User suspended successfully' });

  } catch (error) {
    console.error('Suspend user error:', error);
    res.status(500).json({ error: 'Failed to suspend user' });
  }
});

app.post('/api/admin/users/:id/make-admin', async (req, res) => {
  console.log('=== POST /api/admin/users/:id/make-admin ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const userId = req.params.id;
    const { Users } = require('node-appwrite');
    const users = new Users(appwriteClient);

    // Get current user
    const user = await users.get(userId);
    
    // Check if user is already admin
    if (user.labels && user.labels.includes('admin')) {
      return res.status(400).json({ error: 'User is already an admin' });
    }

    // Add admin label
    const updatedLabels = [...(user.labels || []), 'admin'];
    await users.updateLabels(userId, updatedLabels);

    console.log(`Made user ${userId} an admin by ${req.session.user.username}`);
    logUserAction(req.session.user, 'admin_privileges_granted', { 
      targetUserId: userId,
      targetUsername: user.name,
      ip: req.ip
    });

    res.json({ success: true, message: 'User has been made admin successfully' });

  } catch (error) {
    console.error('Make admin error:', error);
    res.status(500).json({ error: 'Failed to make user admin: ' + error.message });
  }
});

app.post('/api/admin/users/:id/remove-admin', async (req, res) => {
  console.log('=== POST /api/admin/users/:id/remove-admin ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const userId = req.params.id;
    
    // Prevent self-removal of admin privileges
    if (userId === req.session.user.id) {
      return res.status(400).json({ error: 'You cannot remove your own admin privileges' });
    }

    const { Users } = require('node-appwrite');
    const users = new Users(appwriteClient);

    // Get current user
    const user = await users.get(userId);
    
    // Check if user is admin
    if (!user.labels || !user.labels.includes('admin')) {
      return res.status(400).json({ error: 'User is not an admin' });
    }

    // Remove admin label
    const updatedLabels = user.labels.filter(label => label !== 'admin');
    await users.updateLabels(userId, updatedLabels);

    console.log(`Removed admin privileges from user ${userId} by ${req.session.user.username}`);
    logUserAction(req.session.user, 'admin_privileges_revoked', { 
      targetUserId: userId,
      targetUsername: user.name,
      ip: req.ip
    });

    res.json({ success: true, message: 'Admin privileges removed successfully' });

  } catch (error) {
    console.error('Remove admin error:', error);
    res.status(500).json({ error: 'Failed to remove admin privileges: ' + error.message });
  }
});

// Data deletion request endpoints
app.post('/api/request-deletion', async (req, res) => {
  console.log('=== POST /api/request-deletion ===');
  
  try {
    const { email, reason } = req.body;
    
    // Input validation
    if (!email || !reason) {
      return res.status(400).json({ error: 'Email and reason are required' });
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: 'Invalid email address format' });
    }
    
    // Validate reason length
    if (reason.length < 10 || reason.length > 1000) {
      return res.status(400).json({ error: 'Reason must be between 10 and 1000 characters' });
    }
    
    console.log('Creating deletion request in database...');
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    // Create deletion request
    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      'unique()',
      {
        email: email,
        reason: reason,
        status: 'pending',
        user_id: req.session?.user?.id || null,
        created_at: new Date().toISOString()
      }
    );
    
    console.log('Deletion request created successfully:', document.$id);
    
    res.json({ 
      success: true, 
      requestId: document.$id,
      message: 'Data deletion request submitted successfully. An admin will review it shortly.'
    });
    
  } catch (error) {
    console.error('Submit deletion request error:', error);
    res.status(500).json({ error: 'Failed to submit deletion request. Please try again later.' });
  }
});

app.get('/api/admin/deletion-requests', async (req, res) => {
  console.log('=== GET /api/admin/deletion-requests ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      [
        Query.orderDesc('created_at'),
        Query.limit(100)
      ]
    );

    console.log(`Found ${response.documents.length} deletion requests`);
    res.json({ success: true, requests: response.documents });

  } catch (error) {
    console.error('Get deletion requests error:', error);
    res.status(500).json({ error: 'Failed to load deletion requests' });
  }
});

app.post('/api/admin/deletion-requests/:id/approve', async (req, res) => {
  console.log('=== POST /api/admin/deletion-requests/:id/approve ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const requestId = req.params.id;
    
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Update the deletion request status
    const updatedDocument = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      requestId,
      {
        status: 'approved',
        approved_by: req.session.user.username || 'Admin',
        approved_at: new Date().toISOString()
      }
    );

    console.log('Deletion request approved:', requestId);
    res.json({ success: true, request: updatedDocument });

  } catch (error) {
    console.error('Approve deletion request error:', error);
    res.status(500).json({ error: 'Failed to approve deletion request' });
  }
});

app.post('/api/admin/deletion-requests/:id/deny', async (req, res) => {
  console.log('=== POST /api/admin/deletion-requests/:id/deny ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const requestId = req.params.id;
    const { reason } = req.body;
    
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Update the deletion request status
    const updatedDocument = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      requestId,
      {
        status: 'denied',
        denied_by: req.session.user.username || 'Admin',
        denied_at: new Date().toISOString(),
        denial_reason: reason || ''
      }
    );

    console.log('Deletion request denied:', requestId);
    res.json({ success: true, request: updatedDocument });

  } catch (error) {
    console.error('Deny deletion request error:', error);
    res.status(500).json({ error: 'Failed to deny deletion request' });
  }
});

// Admin settings endpoint
app.post('/api/admin/save-settings', async (req, res) => {
  console.log('=== POST /api/admin/save-settings ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { domainName, maxSubdomains, autoApprove } = req.body;
    
    // Validate input
    if (!domainName || !maxSubdomains) {
      return res.status(400).json({ error: 'Domain name and max subdomains are required' });
    }
    
    if (maxSubdomains < 1 || maxSubdomains > 100) {
      return res.status(400).json({ error: 'Max subdomains must be between 1 and 100' });
    }
    
    // Update global settings
    global.ADMIN_SETTINGS.domainName = domainName;
    global.ADMIN_SETTINGS.maxSubdomains = parseInt(maxSubdomains);
    global.ADMIN_SETTINGS.autoApprove = autoApprove === true || autoApprove === 'true';
    
    console.log('Saving settings:', global.ADMIN_SETTINGS);
    
    // Save to database
    await saveAdminSettingsToDatabase();
    
    res.json({ 
      success: true, 
      message: 'Settings saved successfully',
      settings: global.ADMIN_SETTINGS
    });

  } catch (error) {
    console.error('Save settings error:', error);
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Get admin settings endpoint
app.get('/api/admin/settings', async (req, res) => {
  console.log('=== GET /api/admin/settings ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    res.json({ 
      success: true, 
      settings: global.ADMIN_SETTINGS
    });
  } catch (error) {
    console.error('Get settings error:', error);
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

// Maintenance mode toggle endpoint
app.post('/api/admin/toggle-maintenance', async (req, res) => {
  console.log('=== POST /api/admin/toggle-maintenance ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    const { enabled } = req.body;
    
    // Toggle maintenance mode
    global.MAINTENANCE_MODE = enabled === true || enabled === 'true';
    global.ADMIN_SETTINGS.maintenanceMode = global.MAINTENANCE_MODE;
    
    console.log('Maintenance mode toggled:', {
      enabled: global.MAINTENANCE_MODE,
      by: req.session.user.username
    });
    
    // Save to database
    await saveAdminSettingsToDatabase();
    
    res.json({ 
      success: true, 
      message: `Maintenance mode ${global.MAINTENANCE_MODE ? 'enabled' : 'disabled'}`,
      maintenanceMode: global.MAINTENANCE_MODE
    });

  } catch (error) {
    console.error('Toggle maintenance error:', error);
    res.status(500).json({ error: 'Failed to toggle maintenance mode' });
  }
});

// Get maintenance status endpoint
app.get('/api/admin/maintenance-status', async (req, res) => {
  console.log('=== GET /api/admin/maintenance-status ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!(await isAdminUser(req.session.user))) {
    return res.status(403).json({ error: 'Admin access required' });
  }

  try {
    res.json({ 
      success: true, 
      maintenanceMode: global.MAINTENANCE_MODE || false
    });
  } catch (error) {
    console.error('Get maintenance status error:', error);
    res.status(500).json({ error: 'Failed to get maintenance status' });
  }
});

// User account data export endpoint
app.get('/api/user/export-data', async (req, res) => {
  console.log('=== GET /api/user/export-data ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    // Get all user's subdomain requests
    const userRequests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID
    );
    
    const userData = userRequests.documents.filter(doc => doc.user_id === req.session.user.id);
    
    const exportData = {
      user: {
        id: req.session.user.id,
        username: req.session.user.username,
        email: req.session.user.email
      },
      subdomainRequests: userData,
      exportedAt: new Date().toISOString()
    };

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="my-cool-space-data.json"');
    res.json(exportData);

  } catch (error) {
    console.error('Export data error:', error);
    res.status(500).json({ error: 'Failed to export data' });
  }
});

app.post('/api/user/cancel-deletion-request/:id', async (req, res) => {
  console.log('=== POST /api/user/cancel-deletion-request ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const requestId = req.params.id;
    
    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get the deletion request to verify ownership
    const deletionRequest = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      requestId
    );

    // Check if the user owns this request or if it matches their email
    if (deletionRequest.user_id !== req.session.user.id && 
        deletionRequest.email !== req.session.user.email) {
      return res.status(403).json({ error: 'You can only cancel your own deletion requests' });
    }

    // Check if the request is in pending status
    if (deletionRequest.status !== 'pending') {
      return res.status(400).json({ error: 'Only pending deletion requests can be cancelled' });
    }

    // Update the deletion request to cancelled status
    const updatedDocument = await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      requestId,
      {
        status: 'cancelled',
        cancelled_at: new Date().toISOString(),
        cancelled_by_user: true
      }
    );

    console.log('Deletion request cancelled:', requestId);
    res.json({ success: true, request: updatedDocument });

  } catch (error) {
    console.error('Cancel deletion request error:', error);
    res.status(500).json({ error: 'Failed to cancel deletion request' });
  }
});

app.get('/api/user/deletion-requests', async (req, res) => {
  console.log('=== GET /api/user/deletion-requests ===');
  
  if (!req.session.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get user's deletion requests (by email or user_id)
    const response = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_DELETION_COLLECTION_ID || 'deletion_requests',
      [
        Query.equal('email', req.session.user.email || ''),
        Query.orderDesc('created_at')
      ]
    );

    console.log(`Found ${response.documents.length} deletion requests for user`);
    res.json({ success: true, requests: response.documents });

  } catch (error) {
    console.error('Get user deletion requests error:', error);
    res.status(500).json({ error: 'Failed to load deletion requests' });
  }
});

app.post('/api/request-subdomain', subdomainLimiter, async (req, res) => {
  console.log('🌐 [SUBDOMAIN] === POST /api/request-subdomain ===');
  
  try {
    // Check if user is authenticated
    if (!req.session || !req.session.user) {
      console.error('🌐 [SUBDOMAIN] Authentication failed: no user in session');
      logUserAction(null, 'subdomain_request_denied', { 
        reason: 'not_authenticated',
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(401).json({ 
        error: 'Not authenticated - please log in'
      });
    }
    
    const { subdomain, targetUrl, recordType } = req.body;
    console.log('🌐 [SUBDOMAIN] Parsed request data:', { subdomain, targetUrl, recordType });
    
    logUserAction(req.session.user, 'subdomain_request_attempt', { 
      subdomain,
      targetUrl,
      recordType,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
    
    // Input validation
    if (!subdomain || !targetUrl) {
      logUserAction(req.session.user, 'subdomain_request_failed', { 
        reason: 'missing_fields',
        provided: { subdomain: !!subdomain, targetUrl: !!targetUrl },
        ip: req.ip
      });
      return res.status(400).json({ error: 'Subdomain and target URL are required' });
    }
    
    // Validate subdomain format (RFC 1123 compliant)
    const subdomainRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
    if (!subdomainRegex.test(subdomain)) {
      logUserAction(req.session.user, 'subdomain_request_failed', { 
        reason: 'invalid_subdomain_format',
        subdomain,
        ip: req.ip
      });
      return res.status(400).json({ 
        error: 'Invalid subdomain format. Must contain only letters, numbers, and hyphens. Cannot start or end with a hyphen.' 
      });
    }
    
    // Check subdomain length
    if (subdomain.length < 3 || subdomain.length > 63) {
      logUserAction(req.session.user, 'subdomain_request_failed', { 
        reason: 'invalid_subdomain_length',
        subdomain,
        length: subdomain.length,
        ip: req.ip
      });
      return res.status(400).json({ 
        error: 'Subdomain must be between 3 and 63 characters long' 
      });
    }
    
    // Validate target URL format
    try {
      let urlToValidate = targetUrl;
      
      // If it's an A record, validate as IP
      if (recordType === 'a') {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(targetUrl)) {
          logUserAction(req.session.user, 'subdomain_request_failed', { 
            reason: 'invalid_ip_format',
            targetUrl,
            recordType,
            ip: req.ip
          });
          return res.status(400).json({ error: 'Invalid IP address format for A record' });
        }
      } else {
        // For CNAME records, validate as domain
        if (targetUrl.startsWith('http://') || targetUrl.startsWith('https://')) {
          urlToValidate = new URL(targetUrl).hostname;
        } else {
          urlToValidate = targetUrl;
        }
        
        // Validate domain format
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        if (!domainRegex.test(urlToValidate)) {
          logUserAction(req.session.user, 'subdomain_request_failed', { 
            reason: 'invalid_domain_format',
            targetUrl,
            urlToValidate,
            recordType,
            ip: req.ip
          });
          return res.status(400).json({ error: 'Invalid domain format for CNAME record' });
        }
      }
    } catch (error) {
      logUserAction(req.session.user, 'subdomain_request_failed', { 
        reason: 'url_validation_error',
        targetUrl,
        error: error.message,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Invalid target format' });
    }
    
    // Validate record type
    const validRecordTypes = ['cname', 'a'];
    if (recordType && !validRecordTypes.includes(recordType)) {
      logUserAction(req.session.user, 'subdomain_request_failed', { 
        reason: 'invalid_record_type',
        recordType,
        validTypes: validRecordTypes,
        ip: req.ip
      });
      return res.status(400).json({ error: 'Invalid record type. Must be: cname or a' });
    }
    
    const user = req.session.user;
    console.log('🌐 [SUBDOMAIN] Authenticated user:', user.username);
    
    console.log('🌐 [SUBDOMAIN] Setting up Appwrite clients...');
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    // Check if user already has reached the limit (dynamic limit from admin settings)
    console.log('🌐 [SUBDOMAIN] Checking existing subdomains for user:', user.id);
    console.log('🌐 [SUBDOMAIN] Current subdomain limit:', global.ADMIN_SETTINGS.maxSubdomains);
    try {
      const existingRequests = await databases.listDocuments(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_COLLECTION_ID,
        [
          Query.equal('user_id', user.id),
          Query.equal('status', ['approved', 'pending'])
        ]
      );
      
      console.log('🌐 [SUBDOMAIN] Found existing requests:', existingRequests.total);
      
      if (existingRequests.total >= global.ADMIN_SETTINGS.maxSubdomains) {
        console.log('🌐 [SUBDOMAIN] User has reached subdomain limit');
        logUserAction(user, 'subdomain_request_failed', { 
          reason: 'limit_reached',
          currentCount: existingRequests.total,
          maxAllowed: global.ADMIN_SETTINGS.maxSubdomains,
          ip: req.ip
        });
        return res.status(400).json({ 
          error: `You have reached your limit of ${global.ADMIN_SETTINGS.maxSubdomains} subdomain${global.ADMIN_SETTINGS.maxSubdomains > 1 ? 's' : ''} per account. Each user is allowed ${global.ADMIN_SETTINGS.maxSubdomains} subdomain${global.ADMIN_SETTINGS.maxSubdomains > 1 ? 's' : ''}.`,
          code: 'SUBDOMAIN_LIMIT_REACHED'
        });
      }
    } catch (error) {
      console.error('🌐 [SUBDOMAIN] Error checking existing subdomains:', error);
      logUserAction(user, 'subdomain_request_failed', { 
        reason: 'database_check_error',
        error: error.message,
        ip: req.ip
      });
      return res.status(500).json({ error: 'Failed to check existing subdomains' });
    }
    
    // Create subdomain request using session user data
    const prefixedTargetUrl = recordType ? `[${recordType}]${targetUrl}` : targetUrl;
    console.log('🌐 [SUBDOMAIN] Creating document with prefixed URL:', prefixedTargetUrl);
    
    console.log('🌐 [SUBDOMAIN] Creating document in database...');
    const document = await databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      'unique()',
      {
        user_id: user.id,
        discord_tag: user.username + '#' + user.discriminator,
        subdomain: subdomain,
        target_url: prefixedTargetUrl,
        status: 'pending',
        created_at: new Date().toISOString()
      }
    );
    
    console.log('🌐 [SUBDOMAIN] Document created successfully:', document.$id);
    logUserAction(user, 'subdomain_request_created', { 
      requestId: document.$id,
      subdomain,
      targetUrl: prefixedTargetUrl,
      recordType,
      status: 'pending',
      ip: req.ip
    });
    
    res.json({ success: true, document });
  } catch (error) {
    console.error('🌐 [SUBDOMAIN] Request subdomain error:', error);
    console.error('🌐 [SUBDOMAIN] Error details:', error.message, error.code, error.type);
    logUserAction(req.session?.user, 'subdomain_request_failed', { 
      reason: 'unexpected_error',
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/approve/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate ID parameter
    if (!id || typeof id !== 'string' || id.length < 10) {
      return res.status(400).json({ error: 'Invalid request ID' });
    }
    
    console.log('👑 [ADMIN] === APPROVAL REQUEST ===');
    console.log('👑 [ADMIN] Request ID:', id);
    console.log('👑 [ADMIN] Admin user:', req.session?.user?.username);
    
    // Check if user is logged in with Discord OAuth
    if (!req.session || !req.session.user) {
      console.log('👑 [ADMIN] ❌ Not authenticated');
      logUserAction(null, 'admin_approve_denied', { 
        reason: 'not_authenticated',
        requestId: id,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check admin status
    if (!(await isAdminUser(req.session.user))) {
      console.log('👑 [ADMIN] ❌ Access denied - not admin');
      logUserAction(req.session.user, 'admin_approve_denied', { 
        reason: 'insufficient_privileges',
        requestId: id,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    logUserAction(req.session.user, 'admin_approve_attempt', { 
      requestId: id,
      ip: req.ip
    });

    const { Databases, Functions } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    const functions = new Functions(appwriteClient);

    // Get the request
    const document = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id
    );

    // Extract record type and clean target URL
    let recordType = 'cname'; // Default to CNAME instead of redirect
    let targetUrl = document.target_url;
    
    if (targetUrl.startsWith('[') && targetUrl.includes(']')) {
      const match = targetUrl.match(/^\[([^\]]+)\](.+)$/);
      if (match) {
        recordType = match[1];
        targetUrl = match[2];
      }
    }

    console.log('Creating DNS record with Porkbun API...');
    
    // Check if Porkbun API keys are configured
    if (!process.env.PORKBUN_API_KEY || !process.env.PORKBUN_SECRET_KEY) {
      console.error('❌ Porkbun API keys not configured');
      return res.status(500).json({ error: 'DNS API not configured. Please set PORKBUN_API_KEY and PORKBUN_SECRET_KEY environment variables.' });
    }
    
    console.log('✅ Porkbun API keys loaded:');
    console.log('- API Key:', process.env.PORKBUN_API_KEY.substring(0, 10) + '...');
    console.log('- Secret Key:', process.env.PORKBUN_SECRET_KEY.substring(0, 10) + '...');
    console.log('Subdomain:', document.subdomain);
    console.log('Record Type:', recordType);
    console.log('Target URL:', targetUrl);

    // Determine Porkbun record type and content
    let porkbunRecordType, porkbunContent;
    
    switch (recordType) {      
      case 'cname':
        porkbunRecordType = 'CNAME';
        porkbunContent = targetUrl.replace(/^https?:\/\//, '').replace(/\/$/, ''); // Remove protocol and trailing slash
        break;
        
      case 'a':
        porkbunRecordType = 'A';
        // Better IP validation for A records
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(targetUrl)) {
          console.error('Invalid IP address format for A record');
          return res.status(400).json({ error: 'Invalid IP address format for A record' });
        }
        porkbunContent = targetUrl;
        break;
        
      default:
        console.error('Invalid record type:', recordType);
        return res.status(400).json({ error: 'Invalid record type. Must be: cname or a' });
    }

    console.log('Porkbun API request:');
    console.log('- Record Type:', porkbunRecordType);
    console.log('- Content:', porkbunContent);
    console.log('- Domain:', process.env.BASE_DOMAIN || 'my-cool.space');

    // Call Porkbun API directly
    const porkbunResponse = await fetch(`https://api.porkbun.com/api/json/v3/dns/create/${process.env.BASE_DOMAIN || 'my-cool.space'}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secretapikey: process.env.PORKBUN_SECRET_KEY,
        apikey: process.env.PORKBUN_API_KEY,
        name: document.subdomain,
        type: porkbunRecordType,
        content: porkbunContent,
        ttl: 300 // 5 minutes TTL for faster propagation
      })
    });

    // Check if response is valid
    if (!porkbunResponse.ok) {
      console.error('❌ Porkbun API HTTP error:', porkbunResponse.status, porkbunResponse.statusText);
      return res.status(500).json({ error: `DNS API error: ${porkbunResponse.status} ${porkbunResponse.statusText}` });
    }

    let porkbunResult;
    try {
      porkbunResult = await porkbunResponse.json();
    } catch (jsonError) {
      console.error('❌ Invalid JSON response from Porkbun API:', jsonError.message);
      const responseText = await porkbunResponse.text();
      console.error('Response text:', responseText.substring(0, 200));
      return res.status(500).json({ error: 'DNS API returned invalid response. Please check API credentials.' });
    }
    
    console.log('Porkbun API response:', porkbunResult);

    if (porkbunResult.status === 'SUCCESS') {
      console.log(`👑 [ADMIN] ✅ DNS record created successfully for ${document.subdomain}.${process.env.BASE_DOMAIN || 'my-cool.space'}`);
      
      // Update status to approved
      await databases.updateDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_COLLECTION_ID,
        id,
        { status: 'approved' }
      );
      
      logUserAction(req.session.user, 'admin_approve_success', { 
        requestId: id,
        subdomain: document.subdomain,
        targetUrl: document.target_url,
        recordType: porkbunRecordType,
        recordContent: porkbunContent,
        fullDomain: `${document.subdomain}.${process.env.BASE_DOMAIN || 'my-cool.space'}`,
        ip: req.ip
      });
      
      res.json({ 
        success: true, 
        message: `DNS record created for ${document.subdomain}.${process.env.BASE_DOMAIN || 'my-cool.space'}`,
        recordType: porkbunRecordType,
        recordContent: porkbunContent
      });
    } else {
      console.error('👑 [ADMIN] ❌ Porkbun API error:', porkbunResult);
      logUserAction(req.session.user, 'admin_approve_failed', { 
        requestId: id,
        subdomain: document.subdomain,
        reason: 'dns_api_error',
        porkbunError: porkbunResult.message || 'Unknown error',
        ip: req.ip
      });
      res.status(500).json({ error: 'Failed to create DNS record: ' + (porkbunResult.message || 'Unknown error') });
    }
  } catch (error) {
    console.error('👑 [ADMIN] Approve error:', error);
    logUserAction(req.session?.user, 'admin_approve_failed', { 
      requestId: req.params.id,
      reason: 'unexpected_error',
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/deny/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate ID parameter
    if (!id || typeof id !== 'string' || id.length < 10) {
      return res.status(400).json({ error: 'Invalid request ID' });
    }
    
    console.log('👑 [ADMIN] === DENY REQUEST ===');
    console.log('👑 [ADMIN] Request ID:', id);
    console.log('👑 [ADMIN] Admin user:', req.session?.user?.username);
    
    // Check if user is logged in with Discord OAuth
    if (!req.session || !req.session.user) {
      console.log('👑 [ADMIN] ❌ Not authenticated');
      logUserAction(null, 'admin_deny_attempt_denied', { 
        reason: 'not_authenticated',
        requestId: id,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check admin status
    if (!(await isAdminUser(req.session.user))) {
      console.log('👑 [ADMIN] ❌ Access denied - not admin');
      logUserAction(req.session.user, 'admin_deny_attempt_denied', { 
        reason: 'insufficient_privileges',
        requestId: id,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    logUserAction(req.session.user, 'admin_deny_attempt', { 
      requestId: id,
      ip: req.ip
    });

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get the request details for logging
    const document = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id
    );

    // Update status to denied
    await databases.updateDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id,
      { status: 'denied' }
    );
    
    console.log('👑 [ADMIN] ✅ Request denied successfully');
    logUserAction(req.session.user, 'admin_deny_success', { 
      requestId: id,
      subdomain: document.subdomain,
      targetUrl: document.target_url,
      originalUser: document.user_id,
      ip: req.ip
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('👑 [ADMIN] Deny error:', error);
    logUserAction(req.session?.user, 'admin_deny_failed', { 
      requestId: req.params.id,
      reason: 'unexpected_error',
      error: error.message,
      ip: req.ip
    });
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/delete/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate ID parameter
    if (!id || typeof id !== 'string' || id.length < 10) {
      return res.status(400).json({ error: 'Invalid request ID' });
    }
    
    console.log('👑 [ADMIN] === DELETE REQUEST ===');
    console.log('👑 [ADMIN] Request ID:', id);
    console.log('👑 [ADMIN] Admin user:', req.session?.user?.username);
    
    // Check if user is logged in with Discord OAuth
    if (!req.session || !req.session.user) {
      console.log('👑 [ADMIN] ❌ Not authenticated');
      logUserAction(null, 'admin_delete_attempt_denied', { 
        reason: 'not_authenticated',
        requestId: id,
        ip: req.ip
      });
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check admin status
    if (!(await isAdminUser(req.session.user))) {
      console.log('👑 [ADMIN] ❌ Access denied - not admin');
      logUserAction(req.session.user, 'admin_delete_attempt_denied', { 
        reason: 'insufficient_privileges',
        requestId: id,
        ip: req.ip
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    logUserAction(req.session.user, 'admin_delete_attempt', { 
      requestId: id,
      ip: req.ip
    });

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get the request details first (to get subdomain for DNS deletion)
    const document = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id
    );
    
    console.log('👑 [ADMIN] Document to delete:', document.subdomain);
    console.log('👑 [ADMIN] Document status:', document.status);
    
    logUserAction(req.session.user, 'admin_delete_processing', { 
      requestId: id,
      subdomain: document.subdomain,
      status: document.status,
      targetUrl: document.target_url,
      originalUser: document.user_id,
      ip: req.ip
    });

    // If the status is approved, we should also delete the DNS record from Porkbun
    if (document.status === 'approved') {
      console.log('👑 [ADMIN] Attempting to delete DNS record from Porkbun...');
      
      logUserAction(req.session.user, 'admin_delete_dns_attempt', { 
        requestId: id,
        subdomain: document.subdomain,
        ip: req.ip
      });
      
      // Extract record type from target URL to determine what type of DNS record to delete
      let recordType = 'cname'; // Default to CNAME
      let targetUrl = document.target_url;
      
      if (targetUrl.startsWith('[') && targetUrl.includes(']')) {
        const match = targetUrl.match(/^\[([^\]]+)\](.+)$/);
        if (match) {
          recordType = match[1];
          targetUrl = match[2];
        }
      }
      
      // Determine the DNS record type to delete
      let dnsRecordType = 'CNAME';
      if (recordType === 'a') {
        dnsRecordType = 'A';
      }
      
      console.log('Deleting DNS record:', {
        subdomain: document.subdomain,
        recordType: dnsRecordType,
        originalTarget: document.target_url
      });
      
      try {
        // Call Porkbun API to delete DNS record
        const porkbunResponse = await fetch(`https://api.porkbun.com/api/json/v3/dns/deleteByNameType/${process.env.BASE_DOMAIN || 'my-cool.space'}/${document.subdomain}/${dnsRecordType}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            secretapikey: process.env.PORKBUN_SECRET_KEY,
            apikey: process.env.PORKBUN_API_KEY
          })
        });

        // Check if response is valid
        if (!porkbunResponse.ok) {
          console.error('❌ Porkbun delete API HTTP error:', porkbunResponse.status, porkbunResponse.statusText);
        } else {
          let porkbunResult;
          try {
            porkbunResult = await porkbunResponse.json();
            console.log('Porkbun deletion result:', porkbunResult);
          } catch (jsonError) {
            console.error('❌ Invalid JSON response from Porkbun delete API:', jsonError.message);
          }
        }
        
        if (porkbunResult && porkbunResult.status !== 'SUCCESS') {
          console.warn('Failed to delete DNS record:', porkbunResult.message);
          // Continue with database deletion even if DNS deletion fails
        } else if (porkbunResult && porkbunResult.status === 'SUCCESS') {
          console.log('✅ DNS record deleted successfully');
        }
      } catch (dnsError) {
        console.warn('DNS deletion error:', dnsError.message);
        // Continue with database deletion even if DNS deletion fails
      }
    }

    // Delete the document from database
    await databases.deleteDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id
    );
    
    console.log('👑 [ADMIN] ✅ Request deleted successfully');
    logUserAction(req.session.user, 'admin_delete_success', { 
      requestId: id,
      subdomain: document.subdomain,
      wasApproved: document.status === 'approved',
      ip: req.ip
    });
    
    res.json({ success: true, message: 'Request and DNS record deleted successfully' });
  } catch (error) {
    console.error('👑 [ADMIN] Delete error:', error);
    logUserAction(req.session?.user, 'admin_delete_failed', { 
      requestId: req.params.id,
      reason: 'unexpected_error',
      error: error.message,
      ip: req.ip
    });
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/remake/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Validate ID parameter
    if (!id || typeof id !== 'string' || id.length < 10) {
      return res.status(400).json({ error: 'Invalid request ID' });
    }
    
    console.log('=== REMAKE DNS RECORD ===');
    console.log('Request ID:', id);
    
    // Check if user is logged in with Discord OAuth
    if (!req.session || !req.session.user) {
      console.log('❌ Not authenticated');
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check admin status
    if (!(await isAdminUser(req.session.user))) {
      console.log('❌ Access denied - not admin');
      return res.status(403).json({ error: 'Access denied' });
    }

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get the request details
    const document = await databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID,
      id
    );
    
    console.log('Document to remake:', document.subdomain);

    // Only allow remaking for approved requests
    if (document.status !== 'approved') {
      console.log('❌ Cannot remake record - request not approved');
      return res.status(400).json({ error: 'Can only remake DNS records for approved requests' });
    }

    // Extract record type and clean target URL
    let recordType = 'cname'; // Default to CNAME instead of redirect
    let targetUrl = document.target_url;
    
    if (targetUrl.startsWith('[') && targetUrl.includes(']')) {
      const match = targetUrl.match(/^\[([^\]]+)\](.+)$/);
      if (match) {
        recordType = match[1];
        targetUrl = match[2];
      }
    }

    console.log('Remaking DNS record with Porkbun API...');
    
    // Check if Porkbun API keys are configured
    if (!process.env.PORKBUN_API_KEY || !process.env.PORKBUN_SECRET_KEY) {
      console.error('❌ Porkbun API keys not configured');
      return res.status(500).json({ error: 'DNS API not configured. Please set PORKBUN_API_KEY and PORKBUN_SECRET_KEY environment variables.' });
    }
    
    console.log('✅ Porkbun API keys loaded:');
    console.log('- API Key:', process.env.PORKBUN_API_KEY.substring(0, 10) + '...');
    console.log('- Secret Key:', process.env.PORKBUN_SECRET_KEY.substring(0, 10) + '...');
    console.log('Subdomain:', document.subdomain);
    console.log('Record Type:', recordType);
    console.log('Target URL:', targetUrl);

    // First, try to delete any existing record
    try {
      const deleteResponse = await fetch(`https://api.porkbun.com/api/json/v3/dns/deleteByNameType/${process.env.BASE_DOMAIN || 'my-cool.space'}/${document.subdomain}/CNAME`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          secretapikey: process.env.PORKBUN_SECRET_KEY,
          apikey: process.env.PORKBUN_API_KEY
        })
      });
      
      if (!deleteResponse.ok) {
        console.log('❌ Delete API HTTP error:', deleteResponse.status, deleteResponse.statusText);
      } else {
        try {
          const deleteResult = await deleteResponse.json();
          console.log('Existing record deletion result:', deleteResult);
        } catch (jsonError) {
          console.log('❌ Invalid JSON response from delete API:', jsonError.message);
        }
      }
    } catch (deleteError) {
      console.log('No existing record to delete or deletion failed:', deleteError.message);
    }

    // Determine Porkbun record type and content
    let porkbunRecordType, porkbunContent;
    
    switch (recordType) {      
      case 'cname':
        porkbunRecordType = 'CNAME';
        porkbunContent = targetUrl.replace(/^https?:\/\//, '').replace(/\/$/, '');
        break;
        
      case 'a':
        porkbunRecordType = 'A';
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        if (!ipRegex.test(targetUrl)) {
          console.error('Invalid IP address format for A record');
          return res.status(400).json({ error: 'Invalid IP address format for A record' });
        }
        porkbunContent = targetUrl;
        break;
        
      default:
        console.error('Invalid record type:', recordType);
        return res.status(400).json({ error: 'Invalid record type. Must be: cname or a' });
    }

    // Create the new DNS record
    const porkbunResponse = await fetch(`https://api.porkbun.com/api/json/v3/dns/create/${process.env.BASE_DOMAIN || 'my-cool.space'}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        secretapikey: process.env.PORKBUN_SECRET_KEY,
        apikey: process.env.PORKBUN_API_KEY,
        name: document.subdomain,
        type: porkbunRecordType,
        content: porkbunContent,
        ttl: 300
      })
    });

    // Check if response is valid
    if (!porkbunResponse.ok) {
      console.error('❌ Porkbun API HTTP error:', porkbunResponse.status, porkbunResponse.statusText);
      return res.status(500).json({ error: `DNS API error: ${porkbunResponse.status} ${porkbunResponse.statusText}` });
    }

    let porkbunResult;
    try {
      porkbunResult = await porkbunResponse.json();
    } catch (jsonError) {
      console.error('❌ Invalid JSON response from Porkbun API:', jsonError.message);
      const responseText = await porkbunResponse.text();
      console.error('Response text:', responseText.substring(0, 200));
      return res.status(500).json({ error: 'DNS API returned invalid response. Please check API credentials.' });
    }
    
    console.log('Porkbun API remake response:', porkbunResult);

    if (porkbunResult.status === 'SUCCESS') {
      console.log(`✅ DNS record remade successfully for ${document.subdomain}.${process.env.BASE_DOMAIN || 'my-cool.space'}`);
      res.json({ 
        success: true, 
        message: `DNS record remade for ${document.subdomain}.${process.env.BASE_DOMAIN || 'my-cool.space'}`,
        recordType: porkbunRecordType,
        recordContent: porkbunContent
      });
    } else {
      console.error('❌ Porkbun API error:', porkbunResult);
      res.status(500).json({ error: 'Failed to remake DNS record: ' + (porkbunResult.message || 'Unknown error') });
    }
  } catch (error) {
    console.error('Remake error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/admin/requests', async (req, res) => {
  try {
    // Check if user is logged in with Discord OAuth
    if (!req.session || !req.session.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check admin status
    if (!(await isAdminUser(req.session.user))) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const { Databases } = require('node-appwrite');
    const databases = new Databases(appwriteClient);

    // Get all requests
    const requests = await databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID
    );
    
    res.json({ requests: requests.documents });
  } catch (error) {
    console.error('Get requests error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/my-requests', async (req, res) => {
  console.log('=== GET /api/my-requests ===');
  console.log('Session user:', req.session.user);
  
  try {
    // Check if user is authenticated
    if (!req.session.user) {
      console.error('Authentication failed: no user in session');
      return res.status(401).json({ error: 'Not authenticated - please log in' });
    }

    console.log('Setting up Appwrite clients...');
    const { Databases, Query } = require('node-appwrite');
    const databases = new Databases(appwriteClient);
    
    const userId = req.session.user.id;
    console.log('Querying database for user requests, userId:', userId);
    
    try {
      const requests = await databases.listDocuments(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_COLLECTION_ID,
        [Query.equal('user_id', userId)]
      );
      
      console.log('Found', requests.documents.length, 'requests for user');
      res.json({ requests: requests.documents });
    } catch (queryError) {
      console.log('Query failed, attempting fallback query without filters:', queryError.message);
      
      // Fallback: get all documents and filter manually
      const allRequests = await databases.listDocuments(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_COLLECTION_ID
      );
      
      const userRequests = allRequests.documents.filter(doc => doc.user_id === userId);
      console.log('Found', userRequests.length, 'requests for user (via fallback)');
      res.json({ requests: userRequests });
    }
  } catch (error) {
    console.error('Get my requests error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);
  
  // Load admin settings from database
  await loadAdminSettings();
});

module.exports = app;
