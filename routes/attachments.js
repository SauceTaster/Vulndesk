const express = require('express');
const csurf = require('csurf');
var csrfProtection = csurf();
const path = require('path');
const os = require('os');
const Busboy = require('busboy');
const fs = require('fs');
var sanitizeFile = require("sanitize-filename");
// input doc, opts

module.exports = function (Document, opts) {
    var router = express.Router();
    // SAVE a file.

    async function checkDir(req, res, next) {
        if(sanitizeFile(req.params.id) != req.params.id) {
            res.json({
                type: 'err',
                msg: 'Error! document ID contain disallowed characters.'
            });
        } else {
            return next();
        }
    }
    router.post('/:id(' + opts.idpattern + ')/file', csrfProtection, checkDir, async function (req, res) {
        var fq = {};
        fq[opts.idpath] = req.params.id;
        var doc = await Document.findOne(fq);
        if (doc) {
            var comment;
            var pending = 0;       // in-flight file writes
            var parsing = true;    // busboy still reading the request body
            var responded = false; // ensure a single response
            // busboy v1 is a factory (not a constructor) and emits 'close' when done.
            var busboy = Busboy({
                headers: req.headers
            });

            function sendOnce(payload) {
                if (!responded) {
                    responded = true;
                    res.json(payload);
                }
            }
            function maybeDone() {
                if (!parsing && pending === 0) {
                    sendOnce({ ok: '1' });
                }
            }

            // busboy v1 field signature: (name, value, info)
            busboy.on('field', function (fieldname, val) {
                if (fieldname == 'comment') {
                    comment = val;
                }
            });

            // busboy v1 file signature: (name, stream, info) where
            // info = { filename, encoding, mimeType }
            busboy.on('file', function (fieldname, file, info) {
                var filename = info && info.filename;
                var mimetype = info && info.mimeType;
                if (!filename) { file.resume(); return; } // skip empty file fields

                var collectionDir = opts.conf.files;
                if (!fs.existsSync(collectionDir)) {
                    fs.mkdirSync(collectionDir);
                }
                var docDir = path.join(collectionDir, req.params.id);
                if (!fs.existsSync(docDir)) {
                    fs.mkdirSync(docDir);
                }
                docDir = path.join(docDir, 'file');
                if (!fs.existsSync(docDir)) {
                    fs.mkdirSync(docDir);
                }

                var saveTo = path.join(docDir, path.basename(filename));
                var pn = path.normalize(saveTo);
                if (!pn.startsWith(docDir)) {
                    file.resume();
                    sendOnce({ ok: 0, msg: 'Invalid file path!' });
                    return;
                }

                pending++;
                var w = fs.createWriteStream(pn);
                file.pipe(w);

                w.on('finish', async function () {
                    try {
                        var [ftype, fsubtype] = mimetype ? mimetype.split('/', 2) : ['unknown', 'unknown'];
                        var nf = {
                            "name": filename,
                            "updatedAt": new Date(),
                            "size": w.bytesWritten,
                            "comment": comment,
                            "user": req.user.username,
                            "type": ftype,
                            "subtype": fsubtype
                        };
                        var fileq = {};
                        fileq[opts.idpath] = req.params.id;
                        fileq['files.name'] = filename;
                        var ret = await Document.findOneAndUpdate(fileq, {
                            '$set': { "files.$": nf }
                        }, { new: true }).exec();
                        if (ret === null) {
                            await Document.findOneAndUpdate(fq, {
                                $push: { files: nf }
                            }, { new: true }).exec();
                        }
                    } catch (e) {
                        console.error(e);
                    } finally {
                        pending--;
                        maybeDone();
                    }
                });
                w.on('error', function (e) {
                    console.error(e);
                    pending--;
                    maybeDone();
                });
            });

            busboy.on('close', function () {
                parsing = false;
                maybeDone();
            });

            req.pipe(busboy);
        } else {
            res.json({
                ok: 0,
                msg: 'Document not found!'
            });
        }
    });

    //GET file contents
    router.get('/:id(' + opts.idpattern + ')/file/:filename', checkDir,
        async function (req, res, next) {
            res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'none'");
            return next();
        },
        function (req, res) {
            // Serve a single file from THIS document's directory only; never let
            // the URL-supplied name escape it (path traversal). Previously this
            // handed the raw path to express.static rooted at the whole files dir.
            var name = path.basename(req.params.filename);
            if (name !== req.params.filename || sanitizeFile(name) !== name) {
                return res.status(400).json({ ok: 0, msg: 'Invalid file name' });
            }
            res.sendFile(name, {
                root: path.join(opts.conf.files, req.params.id, 'file'),
                dotfiles: 'deny'
            }, function (err) {
                if (err && !res.headersSent) {
                    res.status(404).json({ ok: 0, msg: 'File not found' });
                }
            });
        }
    );

    // delete file
    router.delete('/:id(' + opts.idpattern + ')/file/:filename', csrfProtection, checkDir, async function (req, res) {
        var fq = {};
        fq[opts.idpath] = req.params.id;
        try {
            var ret = await Document.update(fq, { $pull: { files: { name: req.params.filename } } });
            // Remove the bytes from disk too — the $pull only drops the metadata,
            // leaving an orphaned, still-downloadable file otherwise.
            var name = path.basename(req.params.filename);
            if (name === req.params.filename && sanitizeFile(name) === name) {
                fs.unlink(path.join(opts.conf.files, req.params.id, 'file', name), function () {});
            }
            res.json({ ok: ret.ok, n: ret.n });
        } catch (e) {
            res.json(e);
        }
    });

    // file listing in JSON format
    router.get('/files/:id(' + opts.idpattern + ')', checkDir,
        async function (req, res, next) {
            res.setHeader("Content-Security-Policy", "default-src 'none'; connect-src 'none'");
            return next();
        },

        async function (req, res) {
            var fq = {};
            fq[opts.idpath] = req.params.id;
            var doc = await Document.findOne(fq, { files: 1 });
            if (!doc) {
                return res.status(404).json({ ok: 0, msg: 'Document not found!' });
            }
            res.json(doc.files);
        });

    // Directory listing
    router.get('/:id(' + opts.idpattern + ')/file/', checkDir, function (req, res) {
        fs.readdir(path.join(opts.conf.files, req.params.id, '/file/'), function (err, items) {
            res.render(opts.list, {
                title: req.params.id + ' files',
                docs: items ? items.map(x => {
                    return ({
                        'File': x,
                        'Filetype': x.substr(x.lastIndexOf('.') + 1)
                    })
                }) : [],
                columns: ['File', 'Filetype'],
                subtitle: 'Attachments for ' + req.params.id
            });
        });
    });

    return router;
}
