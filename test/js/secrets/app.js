// Vulnerable: hardcoded private key (CWE-798)
var PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIBVexampleexample\n-----END PRIVATE KEY-----";

module.exports = { PRIVATE_KEY: PRIVATE_KEY };
