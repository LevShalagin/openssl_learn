const addon = require('../build/Release/openssl_addon-native')

addon.opensslVersion()
console.log('')
addon.opensslHashHelp()

console.log('')
addon.GenRSA()
