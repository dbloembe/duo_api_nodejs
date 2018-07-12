const {Client} = require('./main.js')
const {sign_request} = require('./sign_blob')

const ikey = ''
const skey = ''
const akey = ''
const username = ''
const api_hostname = ''

// let client_config = {
//   'ikey': 'DI2Y51EW995UKZ8DR14N',
//   'skey': 'QJLwWxTPE7ejU5CWmGYvysK5QI8WzvSippEaMjLX',
//   'akey': '8c2f67da98076f2bdc12e98131b1a65500ed1c73',
//   'host': 'api-first.test.duosecurity.com'
// }
let client = new Client(ikey, skey, api_hostname, 4, 'sha512')
let blob = sign_request(ikey, akey, username)
console.log('BLOB: ' + blob)
let d = new Date()
let init_txid_path = '/frame/init'
let params = {
  'app_blob': blob,
  'client_version': 'duo_nodejs',
  'expire': Math.floor(d.getTime() / 1000) + 300, // not a problem with expire - same blob if same expire time
  'user': username
}
// let string_params = JSON.stringify(params)
client.jsonApiCall('POST', init_txid_path, params, (data) => {
  console.log('FINISHED: ' + JSON.stringify(data))
})
