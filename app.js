// Copyright (c) 2017 Chandan B N. All rights reserved.

const express = require('express');
const path = require('path');
const fs = require('fs');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const https = require('https');
const pug = require('pug');
// TODO: don't use express-session for large-scale production use
const session = require('express-session');

const passport = require('passport');
const crypto = require('crypto');
const compress = require('compression');
const helmet = require('helmet');

const dotenv = require('dotenv').config()
if (dotenv.error) {
    console.log(".env was not loaded.");
}

const conf = require('./config/conf');
const optSet = require('./models/set');

if(!process.env.NODE_ENV) {
    process.env.NODE_ENV = "production";
}

mongoose.Promise = global.Promise;
mongoose.set('strictQuery', false);
mongoose.connect(conf.database, {
    keepAlive: true,
}).catch(function(e){
    console.log("Error"+e.message);
});
const db = mongoose.connection;

//Check connection
db.once('open', function () {
    console.log('Connected to MongoDB');
});

//Check for db errors
db.on('error', function (err) {
   console.error(err.message);
   console.error('Check mongodb connection URL configuration. Ensure Mongodb server is running!');
});

const app = express();

var rateLimit = require('express-rate-limit');
var limiter = rateLimit({
  windowMs: 1*60*1000, // 1 minute
  max: 200
});
// apply rate limiter to all requests
app.use(limiter);

app.disable('x-powered-by');

// Secure HTTP headers. CSP is disabled for now: the app loads editor assets
// from a CDN and uses inline scripts/styles, so a strict policy would break it.
// A real Content-Security-Policy lands with the frontend bundler work (Phase 3).
app.use(helmet({
    contentSecurityPolicy: false
}));

// enable compression
app.use(compress());

app.set('env', 'production');
// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

// make conf available for pug
app.locals.conf = conf;
app.locals.pugLib = pug;

// parse urlencoded forms
app.use(express.urlencoded({
    extended: true
}));

// parse application/json
app.use(express.json({limit:'16mb'}));

// serve files under public freely
app.use(express.static('public'));

// Express Session middleware.
// SESSION_SECRET must be set in production; the random fallback is dev-only and
// invalidates all sessions on restart (so set it once you deploy). The session
// store remains the default in-memory store for now — a persistent store is part
// of the planned auth replacement (BetterAuth), not patched in here.
app.use(session({
    secret: process.env.SESSION_SECRET || crypto.randomBytes(64).toString('hex'),
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production' && !!conf.httpsOptions
    }
}));

// Passport config
require('./config/passport')(passport);

app.use(passport.initialize());
app.use(passport.session());

// Express Messages Middleware
// This shows error messages on the client
app.use(require('connect-flash')());
app.use(function (req, res, next) {
    res.locals.user = req.user || null;
    res.locals.startTime = Date.now();
    res.locals.messages = require('express-messages')(req, res);
    next();
});

// add this to route for authenticating before certain requests.
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        res.redirect('/users/login')
    }
}

function ensureConnected(req, res, next) {
    if (mongoose.connection.readyState == 1) {
        return next();
    } else {
        req.session.returnTo = req.originalUrl;
        req.flash('error', 'Database error! Ensure mongod is up and check the settings on the server.')
        res.status(500);
        res.render('splash', {
            title: 'Vulndesk'
        });
    }
}

app.use(ensureConnected);

//delete return redirect path
app.use(function (req, res, next) {
    // Security headers (X-Frame-Options, X-Content-Type-Options, etc.) are now
    // set centrally by helmet above. The previous wildcard
    // `Access-Control-Allow-Origin: *` (flagged "XXX investigate") was removed:
    // it exposed the API to every origin and is unnecessary for the same-origin
    // UI. If cross-origin API access is needed later, add a configurable
    // allow-list rather than a wildcard.
    if (req.path != '/users/login' && req.session.returnTo) {
        delete req.session.returnTo
    }
    next()
})

// set up routes
let users = require('./routes/users');
app.use('/users', users.public);
app.use('/users', ensureAuthenticated, users.protected);

let docs = require('./routes/doc');

app.locals.confOpts = {};

var sections = require('./models/sections.js')();

for(section of sections) {
    var s = optSet(section, ['default', 'custom']);
    //var s = conf.sections[section];
    if(s.facet && s.facet.ID) {
        app.locals.confOpts[section] = s;
        let r = docs(section, app.locals.confOpts[section]);
        app.use('/' + section, ensureAuthenticated, r.router);
    }
}

app.use('/home/stats', ensureAuthenticated, async function(req, res, next){
    var sections = [];
    for(section of conf.sections){
        var s = {};
        try {
            var s = await db.collection(section+'s').stats();
        } catch (e){

        };
        if (s === {}) {
        try {
            var s = await db.collection(section).stats();
        } catch (e){

        };
        };

        sections.push({
            name: section,
            items: s.count,
            size: s.size,
            avgSize: s.avgObjSize
        });
    }
    res.render('list',
    {
        docs: sections,
        columns: ['name', 'items', 'size', 'avgSize'],
        fields: {
            'name': {
                className: 'icn'
            }
        }
    })
});

app.use(function (req, res, next) {
    res.locals.confOpts = app.locals.confOpts;
    next();
});

if(conf.customRoutes) {
    for(r of conf.customRoutes) {
        app.use(r.path, require(r.route));
    }
}

app.get('/', function (req, res, next) {
    res.redirect(conf.homepage? conf.homepage : '/home');
});

// Centralized error handler. Keeps thrown errors and next(err) from crashing
// the process, and avoids leaking stack traces to clients in production.
// eslint-disable-next-line no-unused-vars
app.use(function (err, req, res, next) {
    console.error(err && err.stack ? err.stack : err);
    if (res.headersSent) {
        return next(err);
    }
    res.status((err && err.status) || 500);
    if (req.accepts('html')) {
        res.render('splash', {
            title: 'Vulndesk'
        });
    } else {
        var isProd = process.env.NODE_ENV === 'production';
        res.json({
            ok: 0,
            msg: isProd ? 'An unexpected error occurred.' : String((err && err.message) || err)
        });
    }
});

if(conf.httpsOptions) {
    https.createServer(conf.httpsOptions, app).listen(conf.serverPort, conf.serverHost, function () {
        console.log('Server started at https://' + conf.serverHost + ':' + conf.serverPort);
    });
} else {
    app.listen(conf.serverPort, conf.serverHost, function () {
        console.log('Server started at http://' + conf.serverHost + ':' + conf.serverPort);
    });
}
