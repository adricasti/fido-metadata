#!/usr/bin/env node

'use strict';

const fs = require('fs');

const CONVENIENCE_METADATA_URL = 'https://c-mds.fidoalliance.org';

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

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
      'User-Agent': 'fido-metadata-updater',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch ${url}: ${response.status} ${response.statusText}`);
  }

  return response.json();
}

async function main() {
  const inputPath = process.argv[2];
  const outputPath = process.argv[3] || 'mds_metadata.json';
  const convenienceOutputPath = process.argv[4] || 'convenience-metadata.json';

  if (!inputPath) {
    throw new Error('Usage: node scripts/update-mds-metadata.js <input.jwt> [mds_output.json] [convenience_output.json]');
  }

  const rawToken = fs.readFileSync(inputPath, 'utf8');
  const token = extractToken(rawToken);
  const payload = decodePayload(token);

  fs.writeFileSync(outputPath, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');

  const convenienceMetadata = await fetchJson(CONVENIENCE_METADATA_URL);
  fs.writeFileSync(convenienceOutputPath, `${JSON.stringify(convenienceMetadata, null, 2)}\n`, 'utf8');

  const no = payload && Object.prototype.hasOwnProperty.call(payload, 'no') ? payload.no : 'unknown';
  const nextUpdate = payload && payload.nextUpdate ? payload.nextUpdate : 'unknown';
  const convenienceNo = convenienceMetadata && Object.prototype.hasOwnProperty.call(convenienceMetadata, 'no') ? convenienceMetadata.no : 'unknown';
  console.log(`Updated ${outputPath}: no=${no}, nextUpdate=${nextUpdate}`);
  console.log(`Updated ${convenienceOutputPath}: no=${convenienceNo}`);
}

try {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(1);
  });
} catch (err) {
  console.error(err.message || err);
  process.exit(1);
}
