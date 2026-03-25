// netlify/functions/admin.js
// Add or manage protected links
// Protect this with ADMIN_KEY env variable

const db = require('../db/mongo');

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

  const ADMIN_KEY = process.env.ADMIN_KEY;
  if (!ADMIN_KEY || body.key !== ADMIN_KEY) {
    return { statusCode: 403, headers: CORS, body: JSON.stringify({ error: 'Unauthorized' }) };
  }

  const { id: linkId, url } = body;
  if (!linkId || !url) {
    return { statusCode: 400, headers: CORS, body: JSON.stringify({ error: 'Missing id or url' }) };
  }

  try {
    await db.addShortener(linkId, url);
    return {
      statusCode: 200,
      headers: CORS,
      body: JSON.stringify({ status: 'ok', id: linkId })
    };
  } catch (e) {
    return { statusCode: 500, headers: CORS, body: JSON.stringify({ error: 'DB error: ' + e.message }) };
  }
};
