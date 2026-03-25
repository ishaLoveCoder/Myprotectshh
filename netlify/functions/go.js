// netlify/functions/go.js
// Final step: client sends session token → server does 302 redirect
// This is a GET request — browser follows the redirect
// Network tab shows: your-domain.netlify.app → destination
// Shortener URL only appears as the final destination in browser address bar
// It is NEVER in any JSON response

const db = require('../db/mongo');

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return { statusCode: 405, body: 'Method not allowed' };
  }

  const sessionToken = event.queryStringParameters?.s;

  if (!sessionToken) {
    return {
      statusCode: 400,
      headers: { 'Content-Type': 'text/html' },
      body: '<h2>Invalid request</h2>'
    };
  }

  let session;
  try {
    session = await db.consumeSession(sessionToken);
  } catch (e) {
    return {
      statusCode: 500,
      headers: { 'Content-Type': 'text/html' },
      body: '<h2>Server error</h2>'
    };
  }

  if (!session) {
    return {
      statusCode: 403,
      headers: { 'Content-Type': 'text/html' },
      body: `
        <html>
        <head><title>Session Expired</title>
        <style>
          body{background:#050508;color:#f0f0ff;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;}
          h2{font-size:1.5rem;margin-bottom:10px;}
          p{color:#5a5a7a;font-size:.9rem;}
          a{color:#7c6aff;text-decoration:none;}
        </style>
        </head>
        <body>
          <div>
            <h2>⏱️ Session Expired</h2>
            <p>This link has expired or already been used.</p>
            <p style="margin-top:16px"><a href="javascript:history.back()">← Go back</a></p>
          </div>
        </body>
        </html>
      `
    };
  }

  const finalUrl = session.url;

  // 302 server-side redirect — this is the cleanest approach
  // URL appears only as the destination, never in JSON/API response
  return {
    statusCode: 302,
    headers: {
      'Location': finalUrl,
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'Pragma': 'no-cache'
    },
    body: ''
  };
};
