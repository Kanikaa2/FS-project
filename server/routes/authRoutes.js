const jwt = require('jsonwebtoken');
const User = require('../models/User'); // your User model
const passport = require('passport');

class AuthController {
  // Generate JWT
  generateJWT(user) {
    return jwt.sign(
      { id: user._id, email: user.email, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
  }

  // Initiate OAuth
  initiateOAuth(req, res, next) {
    const { provider } = req.params;
    if (provider === 'google') {
      passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
    } else if (provider === 'facebook') {
      passport.authenticate('facebook', { scope: ['email'] })(req, res, next);
    } else {
      res.status(400).json({ message: 'Unsupported provider' });
    }
  }

  // OAuth callback
  oauthCallback(req, res, next) {
    const { provider } = req.params;

    if (provider === 'google') {
      passport.authenticate('google', { session: false }, (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'OAuth login failed' });

        // Generate JWT
        const token = this.generateJWT(user);

        // Redirect frontend with token
        const redirectPath = req.query.redirectPath || '/register';
        res.redirect(`${process.env.FRONTEND_URL}${redirectPath}?token=${token}`);
      })(req, res, next);
    } else if (provider === 'facebook') {
      passport.authenticate('facebook', { session: false }, (err, user) => {
        if (err || !user) return res.status(401).json({ message: 'OAuth login failed' });

        const token = this.generateJWT(user);
        const redirectPath = req.query.redirectPath || '/register';
        res.redirect(`${process.env.FRONTEND_URL}${redirectPath}?token=${token}`);
      })(req, res, next);
    } else {
      res.status(400).json({ message: 'Unsupported provider' });
    }
  }

  // Existing methods: register, login, logout, refreshToken, getCurrentUser ...
}

module.exports = new AuthController();
