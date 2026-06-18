#!/usr/bin/env node

'use strict';

const fs = require('fs');

function toBase64(base64Url) {
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = (4 - (base64.length % 4)) % 4;
  return base64 + '='.repeat(padding);
}

function extractToken(raw) {
  const text = String(raw || '').trim();
  if (!text) {
    throw new Error('Input JWT is empty.');
  }

  const firstLine = text.split(/\r?\n/).find(Boolean) || text;
  const token = firstLine.trim();

  if (token.split('.').length < 2) {
    throw new Error('Input does not look like a JWT token.');
  }

  return token;
}

function decodePayload(token) {
  const parts = token.split('.');
  if (parts.length < 2) {
    throw new Error('JWT token does not contain a payload section.');
  }

  const payloadBase64 = toBase64(parts[1]);
  const jsonText = Buffer.from(payloadBase64, 'base64').toString('utf8');

  return JSON.parse(jsonText);
}

function main() {
  const inputPath = process.argv[2];
  const outputPath = process.argv[3] || 'mds_metadata.json';

  if (!inputPath) {
    throw new Error('Usage: node scripts/update-mds-metadata.js <input.jwt> [output.json]');
  }

  const rawToken = fs.readFileSync(inputPath, 'utf8');
  const token = extractToken(rawToken);
  const payload = decodePayload(token);

  fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  const no = payload && Object.prototype.hasOwnProperty.call(payload, 'no') ? payload.no : 'unknown';
  const nextUpdate = payload && payload.nextUpdate ? payload.nextUpdate : 'unknown';
  console.log(`Updated ${outputPath}: no=${no}, nextUpdate=${nextUpdate}`);
}

try {
  main();
} catch (err) {
  console.error(err.message || err);
  process.exit(1);
}
