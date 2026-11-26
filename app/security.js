const crypto = require('crypto');
const db = require('../db/database');

function audit(userId, action, details, req) {
  const previous = db.prepare('SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  const previousHash = previous?.entry_hash || 'GENESIS';
  const createdAt = new Date().toISOString();
  const ip = req?.ip || null;
  const payload = JSON.stringify({ userId: userId || null, action, details: details || null, ip, createdAt, previousHash });
  const entryHash = crypto.createHash('sha256').update(payload).digest('hex');
  db.prepare(`INSERT INTO audit_logs (user_id, action, details, ip_address, created_at, previous_hash, entry_hash)
              VALUES (?, ?, ?, ?, ?, ?, ?)`).run(userId || null, action, details || null, ip, createdAt, previousHash, entryHash);
}

function encryptionKey() {
  const value = process.env.PII_ENCRYPTION_KEY || '';
  if (!/^[a-fA-F0-9]{64}$/.test(value)) throw new Error('PII_ENCRYPTION_KEY must be 64 hexadecimal characters.');
  return Buffer.from(value, 'hex');
}
function encryptText(plainText) {
  if (!plainText) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), encrypted.toString('hex')].join(':');
}
function decryptText(value) {
  if (!value) return '';
  // Preserve legacy plaintext rows created by earlier project versions.
  const parts = String(value).split(':');
  if (parts.length !== 3 || !parts.every(part => /^[a-fA-F0-9]+$/.test(part))) return value;
  const [ivHex, tagHex, encryptedHex] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', encryptionKey(), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encryptedHex, 'hex')), decipher.final()]).toString('utf8');
}

function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const output = [];
  for (const char of String(input).replace(/=+$/g, '').toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) throw new Error('Invalid base32 secret.');
    value = (value << 5) | index; bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(output);
}
function totpCode(secret, time = Date.now()) {
  const counter = Math.floor(time / 30000);
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(buffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1000000).padStart(6, '0');
}
function verifyTotp(secret, token) {
  if (!secret || !/^\d{6}$/.test(String(token || ''))) return false;
  const now = Date.now();
  for (const drift of [-30000, 0, 30000]) {
    const expected = totpCode(secret, now + drift);
    const a = Buffer.from(expected);
    const b = Buffer.from(String(token));
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}
function verifyAuditChain() {
  const rows = db.prepare('SELECT user_id, action, details, ip_address, created_at, previous_hash, entry_hash FROM audit_logs WHERE entry_hash IS NOT NULL ORDER BY id ASC').all();
  let previousHash = 'GENESIS';
  for (const row of rows) {
    if (row.previous_hash !== previousHash) return { valid: false, checked: rows.length, reason: 'Previous hash does not match.' };
    const payload = JSON.stringify({ userId: row.user_id || null, action: row.action, details: row.details || null, ip: row.ip_address || null, createdAt: row.created_at, previousHash });
    const expected = crypto.createHash('sha256').update(payload).digest('hex');
    if (expected !== row.entry_hash) return { valid: false, checked: rows.length, reason: 'An audit entry hash does not match.' };
    previousHash = row.entry_hash;
  }
  return { valid: true, checked: rows.length, reason: rows.length ? 'Hash chain verified.' : 'No hash-chained events yet.' };
}

function base32Encode(buffer) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (const byte of buffer) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}
module.exports = { audit, encryptText, decryptText, verifyTotp, base32Encode, verifyAuditChain };
