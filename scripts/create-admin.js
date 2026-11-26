require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const db = require('../db/database');
const { audit } = require('../app/security');

const username = process.argv[2] || process.env.ADMIN_USERNAME || 'secureadmin';
const email = process.argv[3] || process.env.ADMIN_EMAIL || 'admin@securelocal.test';
const configuredPassword = process.env.ADMIN_PASSWORD;

if (!/^[A-Za-z0-9_]{3,30}$/.test(username)) {
  console.error('Username must be 3–30 letters, numbers or underscores.');
  process.exitCode = 1;
} else if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  console.error('Provide a valid email address.');
  process.exitCode = 1;
} else if (configuredPassword && (Buffer.byteLength(configuredPassword, 'utf8') < 12 || Buffer.byteLength(configuredPassword, 'utf8') > 72 || configuredPassword.toLowerCase().includes(username.toLowerCase()))) {
  console.error('ADMIN_PASSWORD must be 12–72 UTF-8 bytes and must not contain the username.');
  process.exitCode = 1;
} else if (db.prepare("SELECT id FROM users WHERE role IN ('Owner', 'Admin') LIMIT 1").get()) {
  console.error('An Owner or Admin account already exists; refusing to create another bootstrap account.');
  process.exitCode = 1;
} else if (db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email)) {
  console.error('That username or email is already registered.');
  process.exitCode = 1;
} else {
  const password = configuredPassword || crypto.randomBytes(32).toString('base64url');
  const passwordHash = bcrypt.hashSync(password, 12);
  const createAdmin = db.transaction(() => {
    const result = db.prepare(`
      INSERT INTO users (username, email, password_hash, role, consent_accepted_at)
      VALUES (?, ?, ?, 'Admin', ?)
    `).run(username, email.toLowerCase(), passwordHash, new Date().toISOString());
    audit(result.lastInsertRowid, 'ADMIN_ACCOUNT_CREATED', 'Initial admin account provisioned.', null);
  });

  try {
    createAdmin();
    console.log(`Admin account created.
Username: ${username}
Email: ${email.toLowerCase()}
Temporary password (shown once): ${password}

Sign in at http://localhost:${process.env.PORT || 3000}/login, then enable MFA before opening /admin.`);
  } catch (error) {
    console.error('Unable to create the admin account:', error.message);
    process.exitCode = 1;
  }
}

db.close();
