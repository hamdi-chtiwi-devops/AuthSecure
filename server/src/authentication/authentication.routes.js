const {
    registerController,
    loginController,
    refreshTokenController,
    logoutController
  } = require("./authentication.controller");
const router = require("express").Router();
const passport = require('passport');
const { generateToken, ms } = require("./authentication.service");

// Initialize passport strategies
require('../config/passport-setup'); // Corrected path to passport-setup

const OAUTH_FAILURE_REDIRECT_URL = '/auth/oauth/failure'; // Centralized failure redirect

// Standard auth routes
router.post("/register", registerController);
router.post("/login", loginController);
router.post("/refresh-token", refreshTokenController);
router.post("/logout", logoutController);

// OAuth failure route
router.get('/oauth/failure', (req, res) => {
  res.status(401).json({ message: 'OAuth authentication failed or was cancelled.', ok: false });
});

// Google OAuth Routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'], session: false }));

router.get(
  '/google/callback',
  passport.authenticate('google', { failureRedirect: OAUTH_FAILURE_REDIRECT_URL, session: false }),
  (req, res) => {
    const user = req.user; // User object from passport strategy's done(null, user)
    const token = generateToken({ id: user.idUser, email: user.email }, process.env.TOKEN_COOKIE_EXPIRES_IN || '1d');
    const refreshtoken = generateToken({ id: user.idUser, email: user.email }, process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d');

    res.cookie("jwt", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: ms(process.env.TOKEN_COOKIE_EXPIRES_IN || '1d')
    });
    res.cookie("refreshtoken", refreshtoken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: ms(process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d')
    });
    // Optionally redirect to a frontend URL:
    // res.redirect(process.env.CLIENT_URL + '/oauth-success');
    // Or send user data:
    res.status(200).json({ message: "Google OAuth successful", ok: true, user, token, refreshtoken });
  }
);

// Facebook OAuth Routes
router.get('/facebook', passport.authenticate('facebook', { scope: ['email', 'public_profile'], session: false }));

router.get(
  '/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: OAUTH_FAILURE_REDIRECT_URL, session: false }),
  (req, res) => {
    const user = req.user;
    const token = generateToken({ id: user.idUser, email: user.email }, process.env.TOKEN_COOKIE_EXPIRES_IN || '1d');
    const refreshtoken = generateToken({ id: user.idUser, email: user.email }, process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d');

    res.cookie("jwt", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: ms(process.env.TOKEN_COOKIE_EXPIRES_IN || '1d')
    });
    res.cookie("refreshtoken", refreshtoken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: ms(process.env.REFRESH_TOKEN_COOKIE_EXPIRES_IN || '7d')
    });
    // Optionally redirect:
    // res.redirect(process.env.CLIENT_URL + '/oauth-success');
    // Or send user data:
    res.status(200).json({ message: "Facebook OAuth successful", ok: true, user, token, refreshtoken });
  }
);

module.exports = router;
