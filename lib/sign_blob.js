var crypto = require('crypto')

var APP_PREFIX = 'APP'

var APP_EXPIRE = 3600
var IKEY_LEN = 20
var AKEY_LEN = 40
/* Exception Messages */
var ERR_USER = 'ERR|The username passed to sign_request() is invalid.'
var ERR_IKEY = 'ERR|The Duo integration key passed to sign_request() is invalid'
var ERR_AKEY = 'ERR|The application secret key passed to sign_request() must be at least ' + String(AKEY_LEN) + ' characters.'

/**
 * @function sign a value
 *
 * @param {String} key Integration's Secret Key
 * @param {String} vals Value(s) to sign
 * @param {String} prefix DUO/APP/AUTH Prefix
 * @param {Integer} expire time till expiry
 *
 * @return {String} Containing the signed value in sha1-hmac with prefix
 *
 * @api private
 */
function _sign_vals (key, vals, prefix, expire) {
  var exp = Math.round((new Date()).getTime() / 1000) + expire

  var val = vals + '|' + exp
  // console.log('PYTHON VALS: ' + 'dbloembe|DI2Y51EW995UKZ8DR14N|1531840332')
  // console.log('val: ' + val)
  /**
   * Move to Buffer.from and remove no-deprecated-api
   * lint exception when we remove Node v4 support
   */
  var b64 = new Buffer(val).toString('base64')
  var cookie = prefix + '|' + b64
  // console.log('COOKIE: ' + cookie)

  var sig = crypto.createHmac('sha512', key)
    .update(cookie)
    .digest('hex')
  return cookie + '|' + sig
}

/**
 * @function sign's a login request to be passed onto Duo Security
 *
 * @param {String} ikey Integration Key
 * @param {String} skey Secret Key
 * @param {String} akey Application Security Key
 * @param {String} username Username
 *
 * @return {String} Duo Signature
 *
 * @api public
 */
exports.sign_request = function (ikey, akey, username) {
  try {
    username.toString('utf8')
  } catch (error) {
    console.error(error)
  }
  if (!username || username.length < 1) {
    return ERR_USER
  }
  if (username.indexOf('|') !== -1) {
    return ERR_USER
  }
  if (!ikey || ikey.length !== IKEY_LEN) {
    return ERR_IKEY
  }
  if (!akey || akey.length < AKEY_LEN) {
    return ERR_AKEY
  }

  var vals = username + '|' + ikey

  var app_sig = _sign_vals(akey, vals, APP_PREFIX, APP_EXPIRE)
  var sig_request = app_sig
  return sig_request
}
