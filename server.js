require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const refresh = require('passport-oauth2-refresh');
const cookieParser = require('cookie-parser');

const app = express();
const port = 3000;
const lobby = {
    welcome: function(user) {
        var msg = `Welcome to dubbl, ${user.username}!
            ${this.listUsers()}.<br/>
            <a href="${process.env.CALLBALL_BASE_URL}auth/discord">Login again...</a>`;
        return msg;
    },
    listUsers: function() {
        var msg = `Users in lobby:`;
        this.users.forEach(usr => {
            msg += `<br>👋 ${usr.username}`;
        });
        return msg;
    },
    findUserById: function(id, cb) {
        this.users.forEach(usr => {
            if (usr.id === id) {
                cb(null, usr);
            }
        });
    },
    users: []
};

// Middleware to initialize session
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
}));

app.use(cookieParser());

passport.serializeUser((user, done) => {
    lobby["users"].push(user);
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    lobby.findUserById(id, function(err, user) {
        done(err, user);
    });
});

const discordStrat = new DiscordStrategy({
    clientID: '1182353826615926844',
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: `${process.env.CALLBALL_BASE_URL}auth/discord/callback`,
    scope: ['identify email'],
    passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
    req.refreshToken = refreshToken;
    return done(null, profile);
});

passport.use(discordStrat);
refresh.use(discordStrat);

// Middleware to initialize passport
app.use(passport.initialize());
app.use(passport.session());

// Route for initiating Discord authentication
app.get('/auth/discord', (req, res, next) => {
    let options = { failureRedirect: '/login' };
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
        refresh.requestNewAccessToken('discord', refreshToken, function(err, accessToken, refreshToken, profile) {
            if (!err) {
                res.cookie('refreshToken', refreshToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
                    sameSite: 'strict' // Helps to prevent CSRF attacks
                });
                res.req.user = JSON.parse(req.cookies.user);
                return res.redirect('/lobby'); // Add return statement
            } else {
                passport.authenticate('discord', options)(req, res, next);
                return; // Add return statement
            }
        });
    } else {
        passport.authenticate('discord', options)(req, res, next);
        return; // Add return statement
    }
});

// Callback route for Discord authentication
app.get('/auth/discord/callback', passport.authenticate('discord', {}), (req, res) => {
    // Set the refresh token as a secure HTTP-only cookie
    res.cookie('refreshToken', req.refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
        sameSite: 'strict' // Helps to prevent CSRF attacks
    });
    res.cookie('user', JSON.stringify(req.user), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production', // Use HTTPS in production
        sameSite: 'strict' // Helps to prevent CSRF attacks
    });
    return res.redirect(req.session.returnTo || '/lobby'); // Add return statement
});

// Protected route that requires authentication
app.get('/lobby', (req, res) => {
    // Check if user is authenticated
    if (req.isAuthenticated()) {
        res.send(lobby.welcome(req.user));
    } else {
        // User is not authenticated, redirect to login
        return res.redirect('/login'); // Add return statement
    }
});

// Route for login page
app.get('/login', (req, res) => {
    res.send(`Please <a href="${process.env.CALLBALL_BASE_URL}auth/discord">login with Discord</a>`);
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on ${process.env.CALLBALL_BASE_URL}`);
});