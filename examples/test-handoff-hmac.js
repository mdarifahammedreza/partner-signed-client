'use strict';

require('../src/load-env').loadEnv();
const { handoff } = require('..');

async function main() {
  const result = await handoff({
    baseUrl: process.env.API_BASE_URL,
    scheme: 'hmac',
    secret: process.env.HMAC_SECRET,
    partnerId: process.env.HMAC_PARTNER_SLUG,
    partnerUserId: process.env.HMAC_TEST_PARTNER_USER_ID,
    phoneNumber: process.env.HMAC_TEST_PHONE_NUMBER,
  });

  console.log('status:', result.status);
  console.log('body:', JSON.stringify(result.body, null, 2));
}

main().catch((error) => {
  console.error('Request failed:', error);
  process.exitCode = 1;
});
