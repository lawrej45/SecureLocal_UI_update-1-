require('dotenv').config();
const bcrypt = require('bcrypt');
const db = require('../db/database');

if (process.env.NODE_ENV !== 'development') {
  console.error('Demo accounts can only be seeded when NODE_ENV=development.');
  process.exitCode = 1;
} else {
  const password = process.env.DEMO_PASSWORD || '';
  const passwordBytes = Buffer.byteLength(password, 'utf8');

  if (passwordBytes < 12 || passwordBytes > 72) {
    console.error('Set DEMO_PASSWORD in .env to a value between 12 and 72 UTF-8 bytes.');
    process.exitCode = 1;
  } else {
    const accounts = [
      ['demo_owner', 'owner@securelocal.test', 'Owner'],
      ['demo_admin', 'admin-demo@securelocal.test', 'Admin'],
      ['demo_staff', 'staff@securelocal.test', 'Staff'],
      ['demo_security', 'security@securelocal.test', 'Security Officer'],
      ['demo_customer', 'customer@securelocal.test', 'Customer']
    ];
    const passwordHash = bcrypt.hashSync(password, 12);
    const insert = db.prepare(`
      INSERT OR IGNORE INTO users (username, email, password_hash, role, consent_accepted_at)
      VALUES (?, ?, ?, ?, ?)
    `);
    const seedAccounts = db.transaction(() => accounts.reduce((count, account) => {
      return count + insert.run(account[0], account[1], passwordHash, account[2], new Date().toISOString()).changes;
    }, 0));

    try {
      const inserted = seedAccounts();
      console.log(`Demo seed complete. Added ${inserted} account(s); existing demo accounts were left unchanged.`);
      console.log(`Demo usernames: ${accounts.map(([username]) => username).join(', ')}`);
      console.log('The shared demo password is stored in the ignored .env file.');
    } catch (error) {
      console.error('Unable to seed demo accounts:', error.message);
      process.exitCode = 1;
    }
  }
}

db.close();
