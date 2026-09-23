'use strict';

const { signedRequest } = require('./client');

/**
 * The actual flow: sign + call `POST partner/auth/handoff` first, get its response back
 * (handoffCode/entryUrl/...). This is the partner-signed request — always requires `partnerId`
 * and `secret`, unlike the raw outbound-/deduct direction which has neither.
 *
 * Body shape matches PartnerHandoffDto exactly
 * (libs/business-partner/domain/src/dto/partner-handoff.dto.ts):
 *   { partnerUserId, phoneNumber, name?, email?, returnPath? }
 *
 * Response shape (HandoffResult):
 *   { handoffCode, expiresIn, entryUrl, hasActiveSubscription, pendingMerge? }
 *
 * @param {object} options
 * @param {string} options.baseUrl e.g. "https://dev-api.banglareels.com"
 * @param {string} [options.apiPrefix='/api/v1']
 * @param {'hmac'|'ed25519'} options.scheme
 * @param {string} options.secret HMAC secret, or Ed25519 private key PEM
 * @param {string} options.partnerId the partner's slug (X-Partner-Id)
 * @param {string} options.partnerUserId
 * @param {string} options.phoneNumber E.164 preferred
 * @param {string} [options.name]
 * @param {string} [options.email]
 * @param {string} [options.returnPath]
 * @param {string} [options.requestId]
 * @returns {Promise<{ status: number, ok: boolean, body: any }>}
 */
async function handoff(options) {
  const {
    baseUrl,
    apiPrefix = '/api/v1',
    scheme,
    secret,
    partnerId,
    partnerUserId,
    phoneNumber,
    name,
    email,
    returnPath,
    requestId,
  } = options;

  if (!partnerId) throw new Error('handoff: "partnerId" (X-Partner-Id) is required for this call');
  if (!partnerUserId) throw new Error('handoff: "partnerUserId" is required');
  if (!phoneNumber) throw new Error('handoff: "phoneNumber" is required');

  return signedRequest({
    baseUrl,
    path: `${apiPrefix}/partner/auth/handoff`,
    method: 'POST',
    scheme,
    secret,
    partnerId,
    requestId,
    body: { partnerUserId, phoneNumber, name, email, returnPath },
  });
}

module.exports = { handoff };
