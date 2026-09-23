'use strict';

const crypto = require('crypto');

const SIGNATURE_VERSION = 'v1';

/**
 * Binds timestamp, request id and body together so tampering with any one invalidates the
 * signature. Must byte-for-byte match the backend's PartnerCryptoService.buildSigningString
 * (libs/business-partner/domain/src/services/partner-crypto.service.ts) — this is not an
 * independent implementation, it's a compatible client for the same protocol.
 */
function buildSigningString(timestamp, requestId, rawBody) {
  const bodyHash = crypto
    .createHash('sha256')
    .update(rawBody ?? '')
    .digest('hex');

  return `${timestamp}.${requestId}.${bodyHash}`;
}

/** @param {string} secret raw HMAC secret (not encrypted-at-rest form) */
function signHmac(signingString, secret) {
  const mac = crypto.createHmac('sha256', secret).update(signingString).digest('hex');
  return `${SIGNATURE_VERSION}=${mac}`;
}

/** @param {string} privateKeyPem Ed25519 private key, PEM format */
function signEd25519(signingString, privateKeyPem) {
  const signature = crypto.sign(null, Buffer.from(signingString), privateKeyPem);
  return `${SIGNATURE_VERSION}=${signature.toString('base64')}`;
}

/**
 * Scheme-agnostic entry point — the "works for both HMAC and Ed25519" piece. Returns the
 * already-prefixed (`v1=...`) signature header value.
 *
 * @param {'hmac' | 'ed25519'} scheme
 * @param {string} signingString
 * @param {string} secret HMAC secret, or Ed25519 private key PEM
 */
function sign(scheme, signingString, secret) {
  if (scheme === 'hmac') return signHmac(signingString, secret);
  if (scheme === 'ed25519') return signEd25519(signingString, secret);
  throw new Error(`Unsupported signing scheme "${scheme}" — expected "hmac" or "ed25519"`);
}

module.exports = { SIGNATURE_VERSION, buildSigningString, signHmac, signEd25519, sign };
