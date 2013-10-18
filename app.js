/*
 * https://nutty.io
 * Copyright (c) 2013 krishna.srinivas@gmail.com All rights reserved.
 * AGPLv3 License <http://www.gnu.org/licenses/agpl-3.0.txt>
 */


var express = require('express'),
    passport = require('passport'),
    util = require('util'),
    GoogleStrategy = require('passport-google').Strategy,
    crypto = require('crypto'),
    check = require('validator').check,
    AWS = require('aws-sdk'),
    MongoStore = require('connect-mongo')(express);

AWS.config.loadFromPath('./config.json');

var s3 = new AWS.S3();

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(obj, done) {
    done(null, obj);
});

var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/nuttyapp');

var db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', function callback() {
    console.log("mongodb opened!");
});

var UserSchema = new mongoose.Schema({
    fname: String,
    lname: String,
    email: {
        type: String,
        index: {
            unique: true
        }
    },
    username: {
        type: String,
        index: {
            unique: true
        }
    },
    recordings: []
});

var User = mongoose.model('user', UserSchema);

var RecordingSchema = new mongoose.Schema({
    desc: String,
    creator: String
});

var Recording = mongoose.model('Recording', RecordingSchema);

passport.use(new GoogleStrategy({
        returnURL: 'http://localhost:3000/api/auth/google/return',
        realm: 'http://localhost:3000/',
        ui: {
            mode: 'popup'
        },
        stateless: true,
        profile: true
    },
    function(identifier, profile, done) {
        process.nextTick(function() {
            User.findOne({
                'email': profile.emails[0].value
            }, function(err, user) {
                if (err) {
                    return done(null, null);
                }
                if (user) {
                    //profile.identifier = identifier;
                    profile.username = user.username;
                    return done(null, profile);
                } else {
                    return done(null, profile);
                }
            });
        });
    }
));

var app = express.createServer();

// configure Express
app.configure(function() {
    app.use(express.cookieParser());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.session({
        secret: 'not a secret',
        store: new MongoStore({
                    db: 'nuttyapp'
                })
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    app.use(app.router);
    app.use(express.static(__dirname + '/public'));
});


app.get('/api/policy/upload/:desc', function(req, res) {
    if (!loggedin(req)) {
        res.json({
            error: "auth",
            errormsg: "User Authentication required"
        });
        return;
    }

    try {
        check(req.params.desc).len(1,30).is(/^[a-zA-Z][a-zA-Z0-9-,.:\s]+$/);
    } catch (ex) {
        res.json({
            error: "error",
            errormsg: ex.message
        });
        return;
    }
    User.findOne({
        'username': req.user.username
    }, function(err, user) {
        if (err) {
            res.json({
                error: "unknown",
                errormsg: "User not found in DB"
            });
            return;
        }
        if (user.recordings.length == 10) {
            res.json({
                error: "unknown",
                errormsg: "number of recordings upload limit = 10"
            });
            return;
        }
        var recording = new Recording({
            desc: req.params.desc,
            creator: user.username
        });
        recording.save(function(err) {
            if (err) {
                res.json({
                    error: "unknown",
                    errormsg: "Error saving recording"
                });
                return;
            }
            user.recordings.push(recording._id.toString() + ":" + req.params.desc);
            user.save(function(err) {
                if (err) {
                    res.json({
                        error: "unknown",
                        errormsg: "Error saving recording to user profile"
                    });
                    return;
                }
                var bucket = "nutty";
                var key = recording._id.toString();
                var acl = "private";
                var type = "application/binary";
                var accessid = AWS.config.credentials.accessKeyId;
                var secret = AWS.config.credentials.secretAccessKey;
                var Expiration = new Date;
                Expiration.setSeconds(24*60*60); // expire in one day
                var JSON_POLICY = {
                    // "expiration": "2020-01-01T00:00:00Z",
                    "expiration": Expiration.getFullYear()+'-'+(Expiration.getMonth()+1)+'-'+Expiration.getDate()+'T'+Expiration.getHours()+':'+
                                  Expiration.getMinutes()+':'+Expiration.getSeconds()+'Z',
                    "conditions": [{
                            "bucket": bucket
                        },
                        ["starts-with", "$key", key], {
                            "acl": acl
                        },
                        ["starts-with", "$Content-Type", type],
                        ["content-length-range", 0, 1048576]
                    ]
                };
                var policy = new Buffer(JSON.stringify(JSON_POLICY)).toString('base64');
                var signature = crypto.createHmac('sha1', secret).update(policy).digest('base64');
                var retobj = {
                    key: key,
                    AWSAccessKeyId: accessid,
                    acl: acl,
                    policy: policy,
                    signature: signature,
                    ContentType: type,
                }
                res.json(retobj);
            });
        });
    });
});

app.get('/api/policy/download/:recid', function(req, res) {
    Recording.findOne({
        _id: req.params.recid
    }, function(err, recording) {
        if (!recording) {
            res.json({
                error: "unknown",
                errormsg: "Unable to find the recording: " + req.params.recid
            });
            return;
        }
        var accessid = AWS.config.credentials.accessKeyId;
        var secret = AWS.config.credentials.secretAccessKey;
        var ContentMD5 = "";
        var ContentType = "";
        var Expires;
        var expirytime = new Date();
        expirytime.setSeconds(1000);
        Expires = Math.floor(expirytime.getTime() / 1000);
        var StringToSign = "GET" + "\n" +
            ContentMD5 + "\n" +
            ContentType + "\n" +
            Expires + "\n" +
            "/nutty/" + req.params.recid;

        var signature = crypto.createHmac('sha1', secret).update(StringToSign).digest('base64');

        var retobj = {
            AWSAccessKeyId: accessid,
            Expires: Expires,
            Signature: signature
        };
        res.json(retobj);
        return;
    });
});

app.get('/api/policy/remove/:recid/:desc', function(req, res) {
    if (!loggedin(req)) {
        res.json({
            error: "auth",
            errormsg: "User Authentication required"
        });
        return;
    }
    Recording.findOne({
        _id: req.params.recid
    }, function(err, recording) {
        if (err) {
            res.json({
                error: "error",
                errormsg: "Unable to find the record"
            });
            return;
        }
        if (recording.creator != req.user.username) {
            res.json({
                error: "auth",
                errormsg: "User not the creator of recording"
            });
            return;
        }
        s3.deleteObject({Bucket: 'nutty', Key: req.params.recid}, function(err, data) {
            if (err) {
            }
        });
        recording.remove(function(err) {
            User.findOne({
                username: recording.creator
            }, function(err, user) {
                if (err) {
                    res.json({
                        error: "error",
                        errormsg: "Unable to find the record"
                    });
                    return;
                }
                user.recordings.remove(req.params.recid + ":" + req.params.desc);
                user.save();
                res.json({
                    success: true
                });
                return;
            });
        });
    });
});


app.get('/api/auth/google/return', function(req, res, next) {
    passport.authenticate('google', function(err, user, info) {
        if (err) {
            return next(err);
        }
        if (!user) {
            return res.json({
                error: "auth",
                errormsg: "Authentication failed"
            });
        }

        req.logIn(user, function(err) {
            if (err) {
                return next(err);
            }
            if (user.username)
                return res.send('<html><body><script>window.close()</script></body></html>');
            else
                return res.redirect('https://nutty.io/username.html');
        });
    })(req, res, next);
});


app.get('/api/auth/failed', function(req, res) {
    res.send("Auth Failed");
});

app.get('/api/auth/google/logout', function(req, res) {
    req.logout();
    res.send("logged out");
});

app.get('/api/user/info', function(req, res) {
    if (!req.isAuthenticated(req)) {
        res.json({
            error: "auth",
            errormsg: "User Authentication required"
        });
        return;
    }
    res.json(req.user);
});

app.get('/api/user/detail', function(req, res) {
    if (!loggedin(req)) {
        res.json({
            error: "auth",
            errormsg: "User Authentication required"
        });
        return;
    }
    User.findOne({
        'username': req.user.username
    }, function(err, user) {
        if (user) {
            // user for some reason is immutable
            user = JSON.parse(JSON.stringify(user));
            delete user._id;
        }
        res.json(user);
    });
});

app.post('/api/user/username', function(req, res) {
    var username;
    if (!req.isAuthenticated()) {
        res.json({
            error: "auth",
            errormsg: "User Authentication required"
        });
        return;
    }
    username = req.param('username');
    try {
        check (username).len(4,20).isLowercase().is(/^[a-z]+$/).notRegex("^api").notRegex("^info").notRegex("^home").notRegex("^share").notRegex("^recording");
    } catch (ex) {
        res.json({
            error: "error",
            errormsg: "Username should be 4-20 chars and lowercase"
        });
        return;
    }
    User.findOne({
        'username': username
    }, function(err, user) {
        if (err) {
            res.json({
                error: "error",
                errormsg: "db query error"
            });
            return;
        }
        if (user) {
            res.json({
                error: "inuse",
                errormsg: "username already in use"
            });
            return;
        }

        User.findOne({
            'email': req.user.emails[0].value
        }, function(err, user) {
            if (err) {
                res.json({
                    error: "error",
                    errormsg: "db query error"
                });
                return;
            }
            if (user) {
                res.json({
                    error: "error",
                    errormsg: "emailid found in db"
                });
                // FIXME: update username
                return;
            }

            user = new User({
                fname: req.user.name.givenName,
                lname: req.user.name.familyName,
                email: req.user.emails[0].value,
                username: req.param('username')
            });

            user.save(function(err) {
                if (err)
                    res.json({
                        error: "error",
                        errormsg: "unable to save username to db"
                    });
                else {
                    req.user.username = user.username;
                    res.json({
                        success: "registeded"
                    });
                }
                return;
            });
        });
    });
});

app.listen(3000);

function loggedin(req) {
    return (req.user && req.user.username);
}
