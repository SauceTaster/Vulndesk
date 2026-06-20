// Copyright (c) 2017 Chandan B N. All rights reserved.

import crypto = require('crypto')

type Callback<T> = (err: Error | null, result?: T) => void

const saltBytes = 16
const hashBytes = 32
const iterations = 100599
const digest = 'sha512'
const version = 1
const encoding: BufferEncoding = 'base64'

export = {
  hash: function (password: string, callback: Callback<string>) {
    crypto.randomBytes(saltBytes, function (err: Error | null, salt: Buffer) {
      if (err) {
        return callback(err)
      }
      crypto.pbkdf2(
        password,
        salt,
        iterations,
        hashBytes,
        digest,
        function (err: Error | null, hash: Buffer) {
          if (err) {
            return callback(err)
          }
          const result = Buffer.alloc(12 + hash.length + salt.length)
          // version (4) + salt length (4) + iteration count (4) + salt + hash.
          result.writeUInt32BE(version, 0)
          result.writeUInt32BE(salt.length, 4)
          result.writeUInt32BE(iterations, 8)
          salt.copy(result, 12)
          hash.copy(result, salt.length + 12)
          callback(null, result.toString(encoding))
        }
      )
    })
  },
  compare: function (password: string, shadow: string, callback: Callback<boolean>) {
    if (password && shadow) {
      const buf = Buffer.from(shadow, encoding)
      const saltBytes = buf.readUInt32BE(4)
      const hashBytes = buf.length - saltBytes - 12
      const iterations = buf.readUInt32BE(8)
      const salt = buf.subarray(12, saltBytes + 12)
      const storedHash = buf.toString('binary', saltBytes + 12)
      // verify the salt and hash against the password
      crypto.pbkdf2(
        password,
        salt,
        iterations,
        hashBytes,
        digest,
        function (err: Error | null, verify: Buffer) {
          if (err) {
            return callback(err, false)
          }
          callback(null, verify.toString('binary') === storedHash)
        }
      )
    } else {
      // empty passwords or empty shadow == no login!
      callback(null, false)
    }
  },
}
