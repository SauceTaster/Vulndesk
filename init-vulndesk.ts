import pbkdf2 = require('./lib/pbkdf2.js')
import User = require('./models/user.js')
import mongoose = require('mongoose')
import config = require('./config/conf')

mongoose.Promise = global.Promise;
mongoose.set('strictQuery', false);

mongoose.connect(config.database, {
    keepAlive: false,
});

User.findOne({username: process.env.VULNDESK_ADMIN_USERNAME}, function(err, adminUser) {

    if (err) {
        console.log("MongoDB Error: " + err);
        return false; // or callback
    }

    if (adminUser) {
        console.log(`Admin user, ${process.env.VULNDESK_ADMIN_USERNAME}, already exists. Skipping initialization.`);
        mongoose.connection.close();
        process.exit(0);
    }

    pbkdf2.hash(process.env.VULNDESK_ADMIN_PASSWORD, function (err, hash) {

        if (err) {
            console.error(err);
        }

        let newUser = new User({
            name: process.env.VULNDESK_ADMIN_NAME,
            email: process.env.VULNDESK_ADMIN_EMAIL,
            username: process.env.VULNDESK_ADMIN_USERNAME,
            priv: 0,
            group: process.env.VULNDESK_ADMIN_CNA_EMAIL,
            password: hash
        }, { _id: false });

        let error = newUser.validateSync();
        if (error) {
            console.log("Error: " + error);
            process.exit(1);
        }

        User.findOneAndUpdate({
            username: newUser.username
        },
        newUser,
        {
            upsert: true,
            setDefaultsOnInsert: true
        },
        function (err, doc) {
            if (err) {
                console.error(err);
            } else {
                if (doc) {
                    console.log('Success', 'User ' + doc.username + ' is now updated.\n');
                } else {
                    console.log('Success', 'New user is now registered and can log in: ' + newUser.username);
                }
            }
            mongoose.connection.close();
        });
    });

});
