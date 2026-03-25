// netlify/functions/proxy.js
// THE CORE PROTECTION:
// 1. Validates one-time token + fingerprint
// 2. Server fetches shortener URL (client never sees it)
// 3. Returns only a short-lived session key
// 4. Client uses session key → /go → server 302 redirects
// Original shortener URL = NEVER in any network response

const crypto = require('crypto');
const db = require('../db/mongo');

// Private token from Netlify environment variable
// This is never in any client-side code
const PROXY_SECRET = process.env.PROXY_SECRET;

function makeFingerprint(ip, ua, fpData = {}) {
  const raw = [ip, ua, fpData.tz || '', fpData.lang || '', fpData.w || '', fpData.h || ''].join('|');
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

  if (event.httpMethod === 'OPTIONS') return { statusCode: 200, headers: CORS, body: '' };
  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: CORS, body: JSON.stringify({ error: 'Not allowed' }) };

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Bad request' }) };
  }

  const { t: token, fp: fpData = {} } = body;

  if (!token) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Missing token' }) };
  }

  // ── Block automation tools ───────────────────────────
  const ua = event.headers['user-agent'] || '';
  const uaLower = ua.toLowerCase();
  const blockedAgents = ['python-requests', 'python/', 'curl/', 'wget/', 'httpx/', 'go-http', 'axios'];
  if (blockedAgents.some(b => uaLower.includes(b))) {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Access denied' }) };
  }

  // ── Validate token + fingerprint ─────────────────────
  const ip = getIp(event);
  const fingerprint = makeFingerprint(ip, ua, fpData);
  let linkId;

  try {
    linkId = await db.consumeToken(token, fingerprint);
  } catch (e) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'DB error' }) };
  }

  if (!linkId) {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Invalid or expired session' }) };
  }

  // ── Get shortener URL from DB ────────────────────────
  const link = await db.getShortener(linkId);
  if (!link) {
    return { statusCode: 404, headers: CORS, body: JSON.stringify({ error: 'Link not found' }) };
  }

  const destinationUrl = link.url;

  // ── SERVER fetches shortener using PRIVATE token ─────
  // The shortener URL never leaves the server
  // Client will NEVER see this URL in any response
  try {
    const response = await fetch(destinationUrl, {
      method: 'GET',
      redirect: 'follow',
      headers: {
        // Use our private PROXY_SECRET to authenticate with shortener if needed
        'Authorization': `Bearer ${PROXY_SECRET}`,
        'User-Agent': ua || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
        'Accept-Language': 'en-US,en;q=0.9',
      }
    });

    // Get the final resolved URL after all redirects
    const finalUrl = response.url;

    await db.incrementView(linkId);

    // Store final URL in DB — create session token for client
    // Client only gets session key, NEVER the real URL
    const sessionToken = await db.createSession(linkId, finalUrl, fingerprint);

    // Return ONLY the session token — zero URL exposure
    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({ session: sessionToken })
    };

  } catch (e) {
    // Even on error — no URL leaked to client
    return { statusCode: 502, headers: CORS, body: JSON.stringify({ error: 'Could not resolve destination' }) };
  }
};
