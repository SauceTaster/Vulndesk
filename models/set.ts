// Copyright (c) 2018 Chandan B N. All rights reserved.

import fs = require('fs')
import extend = require('extend')

// go through default and custom configurations and return them.
export = function (setName, paths) {
    var result: any = {
        list: 'list',
        edit: 'edit',
        render: 'render'
    };
    var conf: any = {};
    if (!paths) 
        paths = ['default','custom'];
    for (let p in paths) {
        let path=paths[p];
        if(fs.existsSync(path + '/' + setName + '/conf.js')) {
            var temp = require('../' + path + '/' + setName + '/conf.js');
            conf = extend(true, conf, temp);
        }
        if(fs.existsSync(path + '/' + setName + '/static')) {
            result.static = path + '/' + setName + '/static';
        }
        if(!conf.style && fs.existsSync(path + '/' + setName + '/style.css')) {
            result.style = fs.readFileSync(path + '/' + setName + '/style.css', 'utf8');
        }
        if(!conf.script && fs.existsSync(path + '/' + setName + '/script.js')) {
            result.script = (result.script ? result.script : '')+fs.readFileSync(path + '/' + setName + '/script.js', {encoding:'utf8'});
        }
        for (let template of ['list', 'edit', 'render']) {
            if (fs.existsSync(path + '/' + setName + '/' + template + '.pug')) {
                result[template] = '../' + path + '/' + setName + '/' + template;
            }
        }
    }
    var ret = extend(conf, result);
    //TODO: merge old script object with new file
    return ret;
}