// netlify/functions/gate.js
// Step 1: Bot/IP check + issue one-time token
// Called by frontend after browser checks pass

const crypto = require('crypto');
const db = require('../db/mongo');

function makeFingerprint(ip, ua, fpData = {}) {
  const raw = [
    ip,
    ua,
    fpData.tz || '',
    fpData.lang || '',
    fpData.w || '',
    fpData.h || ''
  ].join('|');
  return crypto.createHash('sha256').update(raw).digest('hex');
}

function getIp(event) {
  return (
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers['client-ip'] ||
    '0.0.0.0'
  );
}

exports.handler = async (event) => {
  const CORS = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type'
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: CORS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Invalid JSON' }) };
  }

  const { id: linkId, fp: fpData = {} } = body;

  if (!linkId) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Missing link ID' }) };
  }

  // ── Bot / automation checks ──────────────────────────
  const ua = event.headers['user-agent'] || '';
  const uaLower = ua.toLowerCase();

  // Block known automation tools
  const blockedAgents = ['python-requests', 'python/', 'curl/', 'wget/', 'httpx/', 'go-http', 'java/', 'axios'];
  if (blockedAgents.some(b => uaLower.includes(b))) {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Access denied' }) };
  }

  // ── Verify link exists ───────────────────────────────
  let link;
  try {
    link = await db.getShortener(linkId);
  } catch (e) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'DB error' }) };
  }

  if (!link) {
    return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: 'Link not found' }) };
  }

  // ── Create fingerprint + token ───────────────────────
  const ip = getIp(event);
  const fingerprint = makeFingerprint(ip, ua, fpData);
  const token = await db.createToken(linkId, fingerprint);

  // Split token — never send full token in one piece
  const half = Math.floor(token.length / 2);
  return {
    statusCode: 200,
    headers: CORS,
    body: JSON.stringify({
      a: token.slice(0, half),
      b: token.slice(half)
    })
  };
};
