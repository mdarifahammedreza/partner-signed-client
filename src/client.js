'use strict';

const crypto = require('crypto');
const { buildSigningString, sign } = require('./crypto');

/**
 * The universal signed-request function — works for both HMAC and Ed25519, calls the target URL,
 * and returns just the response. Compatible with BOTH directions of BanglaReels' partner protocol:
 *
 *  - Calling INTO BanglaReels (e.g. the old `POST partner/callbacks/subscription`, or any other
 *    partner-signed endpoint under PartnerSignatureGuard): pass `partnerId` so the `X-Partner-Id`
 *    header is sent.
 *  - Simulating what BanglaReels sends OUT to a partner's own `/deduct` endpoint
 *    (PartnerPaymentAdapterService): omit `partnerId` — that direction never sends it.
 *
 * Signing string / header shape must match the backend's PartnerCryptoService +
 * PartnerSignatureGuard exactly — see src/crypto.js's own doc comment.
 *
 * @param {object} options
 * @param {string} options.baseUrl e.g. "https://dev-api.banglareels.com" or a partner's own API base
 * @param {string} options.path e.g. "/api/v1/partner/callbacks/subscription"
 * @param {'GET'|'POST'|'PUT'|'PATCH'|'DELETE'} [options.method='POST']
 * @param {object|undefined} options.body request body — sent as JSON, undefined for no body
 * @param {'hmac'|'ed25519'} options.scheme
 * @param {string} options.secret HMAC secret, or Ed25519 private key PEM
 * @param {string} [options.partnerId] X-Partner-Id — omit for the outbound (BanglaReels->partner) direction
 * @param {string} [options.requestId] X-Request-Id — reuse the same value on any retry of the same
 *   attempt; auto-generated (UUID) if omitted
 * @param {Record<string,string>} [options.extraHeaders]
 * @returns {Promise<{ status: number, ok: boolean, headers: Record<string,string>, body: any }>}
 *   `body` is parsed JSON when the response declares a JSON content-type, otherwise raw text.
 */
async function signedRequest(options) {
  const {
    baseUrl,
    path,
    method = 'POST',
    body,
    scheme,
    secret,
    partnerId,
    requestId = crypto.randomUUID(),
    extraHeaders = {},
  } = options;

  if (!baseUrl) throw new Error('signedRequest: "baseUrl" is required');
  if (!path) throw new Error('signedRequest: "path" is required');
  if (!scheme) throw new Error('signedRequest: "scheme" is required ("hmac" | "ed25519")');
  if (!secret) throw new Error('signedRequest: "secret" is required');

  const timestamp = Math.floor(Date.now() / 1000).toString();
  // Signed and sent as the EXACT same bytes — re-serializing after signing (e.g. a different key
  // order) would produce a body whose hash no longer matches the signature.
  const rawBody = body === undefined ? '' : JSON.stringify(body);

  const signingString = buildSigningString(timestamp, requestId, rawBody);
  const signature = sign(scheme, signingString, secret);

  const headers = {
    'Content-Type': 'application/json',
    'X-Request-Id': requestId,
    'X-Timestamp': timestamp,
    'X-Signature': signature,
    ...(partnerId ? { 'X-Partner-Id': partnerId } : {}),
    ...extraHeaders,
  };

  const url = `${baseUrl.replace(/\/+$/, '')}${path.startsWith('/') ? path : `/${path}`}`;

  const response = await fetch(url, {
    method,
    headers,
    body: rawBody === '' ? undefined : rawBody,
  });

  const contentType = response.headers.get('content-type') ?? '';
  const responseBody = contentType.includes('application/json')
    ? await response.json().catch(() => null)
    : await response.text();

  return {
    status: response.status,
    ok: response.ok,
    headers: Object.fromEntries(response.headers.entries()),
    body: responseBody,
  };
}

module.exports = { signedRequest };
