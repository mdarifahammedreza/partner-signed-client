'use strict';

const { signedRequest } = require('./src/client');
const { buildSigningString, signHmac, signEd25519, sign, SIGNATURE_VERSION } = require('./src/crypto');
const { handoff } = require('./src/handoff');

module.exports = {
  signedRequest,
  buildSigningString,
  signHmac,
  signEd25519,
  sign,
  SIGNATURE_VERSION,
  handoff,
};
