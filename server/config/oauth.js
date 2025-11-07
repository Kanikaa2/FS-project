const crypto = require('crypto');

const oauthConfig = {
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL,
    authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenURL: 'https://oauth2.googleapis.com/token',
    userInfoURL: 'https://www.googleapis.com/oauth2/v2/userinfo',
    scope: ['profile', 'email'],
    grantType: 'authorization_code',
  },
  facebook: {
    clientId: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK_URL,
    authorizationURL: 'https://www.facebook.com/v18.0/dialog/oauth',
    tokenURL: 'https://graph.facebook.com/v18.0/oauth/access_token',
    userInfoURL: 'https://graph.facebook.com/me',
    scope: ['email', 'public_profile'],
    grantType: 'authorization_code',
  },
};

// Generate PKCE code verifier and challenge
const generatePKCE = () => {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');
  
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
};

// Generate random state
const generateState = () => {
  return crypto.randomBytes(32).toString('hex');
};

// Generate random nonce
const generateNonce = () => {
  return crypto.randomBytes(16).toString('hex');
};

// Build authorization URL
const buildAuthorizationURL = (provider, state, codeChallenge, redirectPath = '/') => {
  const config = oauthConfig[provider];
  if (!config) {
    throw new Error(`Unknown OAuth provider: ${provider}`);
  }

  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: config.callbackURL,
    response_type: 'code',
    scope: config.scope.join(' '),
    state: JSON.stringify({ state, redirectPath }),
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  if (provider === 'google') {
    params.append('access_type', 'offline');
    params.append('prompt', 'consent');
  }

  return `${config.authorizationURL}?${params.toString()}`;
};

// Validate callback state
const validateState = (receivedState, storedState) => {
  return receivedState === storedState;
};

module.exports = {
  oauthConfig,
  generatePKCE,
  generateState,
  generateNonce,
  buildAuthorizationURL,
  validateState,
};
