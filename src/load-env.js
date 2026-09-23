'use strict';

const fs = require('fs');
const path = require('path');

/** Minimal .env loader — no external dependency needed for a package this small. */
function loadEnv() {
  const envPath = path.join(__dirname, '..', '.env');
  if (!fs.existsSync(envPath)) return;

  fs.readFileSync(envPath, 'utf8')
    .split('\n')
    .forEach((line) => {
      const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
      if (match && !(match[1] in process.env)) {
        process.env[match[1]] = match[2] ?? '';
      }
    });
}

module.exports = { loadEnv };
