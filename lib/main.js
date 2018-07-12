var duo_sig = require('./duo_sig')
var https = require('https')
var querystring = require('querystring')
var _ = require('lodash')

function Client (ikey, skey, host, sig_version = 2, digestmod = 'sha1') {
  this.ikey = ikey
  this.skey = skey
  this.host = host
  this.sig_version = sig_version
  this.digestmod = digestmod

  if (sig_version === 4 && digestmod !== 'sha512') {
    throw new Error('sha512 required for sig_version 4')
  }
}

Client.prototype.apiCall = function (method, path, params, callback) {
  var date = new Date().toUTCString()
  var headers = {
    'date': date,
    'hostname': this.host
  }
  headers['Authorization'] = duo_sig.sign(
    this.ikey, this.skey, method, this.host, path, params, date, this.sig_version, this.digestmod)

  var qs = querystring.stringify(params)
  var body = ''
  if (method === 'POST' || method === 'PUT') {
    if (this.sig_version === 3 || this.sig_version === 4) {
      // body = JSON.stringify(_(params).toPairs().sortBy(0).fromPairs().value())
      // console.log(body)
      body = JSON.stringify(params)
      headers['content-type'] = 'application/json'
    } else {
      body = qs
      headers['Content-Type'] = 'application/x-www-form-urlencoded'
    }
    headers['content-length'] = Buffer.byteLength(body)
    console.log(Buffer.byteLength(body))
  } else if (qs) {
    path += '?' + qs
  }

  console.log('Method: ' + method)
  console.log('Path: ' + path)
  console.log('Body: ' + body)
  console.log('Headers: ' + JSON.stringify(headers))
  console.log(this.host)
  headers = JSON.stringify(headers)
  var req = https.request({
    host: this.host,
    method: method,
    path: path,
    headers: headers
  }, function (res) {
    console.log('STATUS: ' + res.status)
    console.log('Headers: ' + JSON.stringify(res.headers));
    res.setEncoding('utf8')
    var buffer = ''
    res.on('data', function (data) {
      buffer = buffer + data
    })

    res.on('end', function (data) {
      callback(buffer)
    })
  })
  req.write(body)
  req.end()
}

Client.prototype.jsonApiCall = function (method, path, params, callback) {
  this.apiCall(method, path, params, function (data) {
    callback(JSON.parse(data))
  })
}

module.exports = {
  'Client': Client
}
