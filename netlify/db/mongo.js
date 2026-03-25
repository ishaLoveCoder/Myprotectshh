// netlify/db/mongo.js
// MongoDB helper - pure Node.js (no motor, using mongodb driver)

const { MongoClient } = require('mongodb');

let _client = null;
let _db = null;

async function getDb() {
  if (_db) return _db;
  _client = new MongoClient(process.env.DATABASE_URI);
  await _client.connect();
  _db = _client.db(process.env.DATABASE_NAME || 'admin_database');
  return _db;
}

// ─── SHORTENERS ───────────────────────────────────────
async function getShortener(linkId) {
  const db = await getDb();
  return db.collection('shorteners').findOne({ _id: linkId });
}

async function addShortener(linkId, url) {
  const db = await getDb();
  await db.collection('shorteners').updateOne(
    { _id: linkId },
    { $set: { _id: linkId, url, created_at: new Date(), total_views: 0 } },
    { upsert: true }
  );
}

async function incrementView(linkId) {
  const db = await getDb();
  await db.collection('shorteners').updateOne(
    { _id: linkId },
    { $inc: { total_views: 1 } }
  );
}

// ─── ONE-TIME TOKENS ───────────────────────────────────
async function createToken(linkId, fingerprint) {
  const db = await getDb();
  const crypto = require('crypto');
  const token = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  const expires = new Date(now.getTime() + 90 * 1000); // 90 seconds

  await db.collection('secure_tokens').insertOne({
    token,
    link_id: linkId,
    fingerprint,
    used: false,
    created_at: now,
    expires_at: expires
  });
  return token;
}

async function consumeToken(token, fingerprint) {
  const db = await getDb();
  const doc = await db.collection('secure_tokens').findOne({
    token,
    used: false,
    fingerprint
  });

  if (!doc) return null;
  if (new Date() > doc.expires_at) {
    await db.collection('secure_tokens').deleteOne({ token });
    return null;
  }

  await db.collection('secure_tokens').updateOne(
    { token },
    { $set: { used: true, used_at: new Date() } }
  );
  return doc.link_id;
}

// ─── PROXY SESSIONS ────────────────────────────────────
// After server resolves the shortener URL, we store it here
// Client NEVER sees the real URL — only a short session key
async function createSession(linkId, resolvedUrl, fingerprint) {
  const db = await getDb();
  const crypto = require('crypto');
  const session = crypto.randomBytes(24).toString('base64url');
  const now = new Date();
  const expires = new Date(now.getTime() + 30 * 1000); // 30 seconds only

  await db.collection('proxy_sessions').insertOne({
    session,
    link_id: linkId,
    url: resolvedUrl,
    fingerprint,
    used: false,
    created_at: now,
    expires_at: expires
  });
  return session;
}

async function consumeSession(sessionToken) {
  const db = await getDb();
  const doc = await db.collection('proxy_sessions').findOne({
    session: sessionToken,
    used: false
  });

  if (!doc) return null;
  if (new Date() > doc.expires_at) {
    await db.collection('proxy_sessions').deleteOne({ session: sessionToken });
    return null;
  }

  await db.collection('proxy_sessions').updateOne(
    { session: sessionToken },
    { $set: { used: true } }
  );
  return doc;
}

module.exports = {
  getShortener,
  addShortener,
  incrementView,
  createToken,
  consumeToken,
  createSession,
  consumeSession
};
