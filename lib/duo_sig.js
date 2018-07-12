var crypto = require('crypto')
var _ = require('lodash')

// Compare two strings based on character unicode values.
//
// If a string is a subset of another, it should sort before.
// i.e. 'foo' < 'foo_bar'
function compare (a, b) {
  var aChar, bChar

  for (var i = 0; i < Math.min(a.length, b.length); i++) {
    aChar = a.charCodeAt(i)
    bChar = b.charCodeAt(i)

    if (aChar < bChar) {
      return -1
    } else if (aChar > bChar) {
      return 1
    }
  }

  if (a.length < b.length) {
    return -1
  } else if (a.length > b.length) {
    return 1
  }

  return 0
}

// Given an Object mapping from parameter name to its value as either
// a single string or an Array of strings, return the
// application/x-www-form-urlencoded parameters string.
function canonParams (params) {
  var ks = Object.keys(params).sort(compare)

  // Build application/x-www-form-urlencoded string.
  var qs = ks.map(function (k) {
    var keq = encodeURIComponent(k) + '='
    if (Array.isArray(params[k])) {
      return params[k].map(function (v) {
        return keq + encodeURIComponent(v)
      }).join('&')
    } else {
      return keq + encodeURIComponent(params[k])
    }
  }).join('&')

  // encodeURIComponent doesn't escape all needed characters.
  return qs
    .replace('!', '%21')
    .replace("'", '%27')
    .replace('(', '%28')
    .replace(')', '%29')
    .replace('*', '%2A')
}

// Return a request's canonical representation as a string to sign.
function canonicalize (method, host, path, params, date, sig_version) {
  let canon = ''
  if (sig_version === 2) {
    canon = [
      date,
      method.toUpperCase(),
      host.toLowerCase(),
      path,
      canonParams(params)
    ].join('\n')
  } else if (sig_version === 3) {
    // sig_version 3 is json only
    canon = [
      date,
      method.toUpperCase(),
      host.toLowerCase(),
      path,
      params
    ].join('\n')
  } else if (sig_version === 4) {
    // sig_version 4 is json only
    // let sorted_params = JSON.stringify(_(params).toPairs().sortBy(0).fromPairs().value())
    let hashed_body = crypto.createHash('sha512')
      .update(params.toString('utf8'))
      .digest('hex')

    canon = [
      date,
      method.toUpperCase(),
      host.toLowerCase(),
      path,
      '',
      hashed_body
    ].join('\n')
  }
  return canon
}

// Return the Authorization header for an HMAC signed request.
function sign (ikey, skey, method, host, path, params, date, sig_version, digestmod) {
  var canon = canonicalize(method, host, path, params, date, sig_version)
  var sig = crypto.createHmac(digestmod, skey)
    .update(canon)
    .digest('hex')

  /**
   * Move to Buffer.from and remove no-deprecated-api
   * lint exception when we remove Node v4 support
   */
  var auth = new Buffer([ikey, sig].join(':')).toString('base64')
  // console.log('Auth: ' + auth)
  // var decoded = new Buffer(auth, 'base64').toString('ascii')
  // console.log('AUTH: ' + decoded)
  return 'Basic ' + auth
}

module.exports = {
  'sign': sign
}
