// Copyright (c) 2017 Chandan B N. All rights reserved.

const LocalStrategy = require('passport-local').Strategy;
import User = require('../models/user')
import config = require('./conf')
import pbkdf2 = require('../lib/pbkdf2.js')

export = function (passport) {
    // Local strategy
    passport.use(new LocalStrategy(function (username, password, done) {
        User.findOne({username: username}, function (err, user) {
            if (err) return done(err);
            if (!user) {
                return done(null, false, {
                    message: 'No user found'
                });
            }
            pbkdf2.compare(password, user.password, function (err, same) {
                if (err) return done(err);
                if (same) {
                    return done(null, user);
                } else {
                    return done(null, false, {
                        message: 'Wrong password'
                    });
                }
            });
        });
    }));

    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        User.findById(id, function (err, user) {
            done(err, user);
        });
    });
};