const addon = require('../build/Release/openssl_addon-native')


console.log('-----------------------------------')
addon.opensslVersion()
console.log('-----------------------------------')
addon.opensslHashHelp()
console.log('-----------------------------------')
addon.GetCertificate('RU', 'LeoPC', 'LeoPC.com')
console.log('-----------------------------------')