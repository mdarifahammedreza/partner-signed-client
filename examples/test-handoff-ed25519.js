'use strict';

require('../src/load-env').loadEnv();
const { handoff } = require('..');

async function main() {
  const result = await handoff({
    baseUrl: process.env.API_BASE_URL,
    scheme: 'ed25519',
    // .env can only carry the PEM with real newlines escaped as literal "\n".
    secret: process.env.ED25519_PRIVATE_KEY_PEM.replace(/\\n/g, '\n'),
    partnerId: process.env.ED25519_PARTNER_SLUG,
    partnerUserId: process.env.ED25519_TEST_PARTNER_USER_ID,
    phoneNumber: process.env.ED25519_TEST_PHONE_NUMBER,
  });

  console.log('status:', result.status);
  console.log('body:', JSON.stringify(result.body, null, 2));
}

main().catch((error) => {
  console.error('Request failed:', error);
  process.exitCode = 1;
});
