const fs = require('fs');
const helmet = require('helmet');
const https = require('https');
const path = require('path');
const express = require('express');
const passport = require('passport');
const { Strategy } = require('passport-google-oauth20');
const cookieSession = require('cookie-session');
require('dotenv').config()

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2
};

const AUTH_OPTIONS = {
  callbackURL: '/auth/google/callback',
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET
}

const verifyCallback = (accessToken, refreshToken, profile, done) => {
  // We will have access to accessToken, refreshToken, profile, done once the OAuth flow is completed inside the passport middleware.
  console.log('Google profile', profile);
  // Any other operations / database operations.
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

// https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize

// Save the session to the cookie.
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Read the session from the cookie.
passport.deserializeUser((id, done) => {
  // User.findById(id).then(user => {
  //   done(null, user);
  // });
  done(null, id);
})

const app = express();

app.use(helmet());

app.use(cookieSession({
  name: 'session',
  maxAge: 24 * 60 * 60 * 1000,
  keys: [ config.COOKIE_KEY_1, config.COOKIE_KEY_2 ]
}))

app.use(passport.initialize()); // so that passport understands the cookieSession and the req.user object, that it set by the cookieSession middleware.
app.use(passport.session()); // it authenticates the session that is being sent to the server. It uses the config.cookie_key 1 and 2 to validate that everything is signed.
// It then sets the req.user property to contain the user's identity.
// In short the passport.session() middleware will allow the deserialize function to be called.

const checkLoggedIn = (req, res, next) => {
  console.log('Current user is: ', req.user);
  const isLoggedIn = req.isAuthenticated() && req.user; // req.isAuthenticated() is populated by passport.
  if(!isLoggedIn)
  return res.status(401).json({
    error: 'You must log in!',
  })
  next();
}

app.get('/auth/google', passport.authenticate('google', {
  scope: ['email', 'profile'],
}));

app.get('/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/failure',
    successRedirect: '/',
    session: true,
  }),
  (req, res) => {
  console.log('Google called us back!');
});

app.get('/auth/logout', (req, res) => {
  req.logout(); // Removes req.user and clears any logged in session. req.logout() is a passport function.
  return res.redirect('/');
});

app.get('/secret', checkLoggedIn, (req, res) => {
  return res.send('Your personal secret value is 42!');
});

app.get('/failure', (req, res) => {
  res.send('Failed to log in!');
})

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

https.createServer({
  key: fs.readFileSync('key.pem'),
  cert: fs.readFileSync('cert.pem'),
}, app).listen(PORT, () => {
  console.log(`Listening on port ${PORT}...`)
})