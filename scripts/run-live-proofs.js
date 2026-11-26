require('dotenv').config();
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const db = require('../db/database');
const { requireRole, requireAdminMfa } = require('../app/middleware/auth');
const { verifyAuditChain } = require('../app/security');

const baseUrl = `http://localhost:${process.env.PORT || 3000}`;
const proofName = process.env.PROOF_NAME || 'Lawrence Dial';
const proofDate = new Date();
const outputDirectory = path.join(__dirname, '..', 'evidence', 'proofs');
const stepDirectory = path.join(__dirname, '..', 'evidence', 'steps');

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

function invoke(middleware, user) {
  const result = { next: false, status: null, redirect: null, rendered: null };
  const req = { session: user ? { user: { ...user } } : {}, method: 'GET', path: '/admin' };
  const res = {
    redirect(location) { result.redirect = location; return this; },
    status(code) { result.status = code; return this; },
    render(view) { result.rendered = view; return this; }
  };
  middleware(req, res, () => { result.next = true; });
  return result;
}

function writeProof(index, title, detail, result) {
  const date = proofDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Live Proof ${index} | SecureLocal</title>
<style>
  *{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#202b3b;font:16px/1.5 "Segoe UI",Arial,sans-serif}
  main{max-width:900px;margin:12vh auto;padding:42px;background:#fff;border:1px solid #e1e6ed;border-radius:20px;box-shadow:0 12px 36px #17203312}
  .top{display:flex;justify-content:space-between;gap:20px;align-items:center;color:#8f391b;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
  h1{font-size:36px;margin:22px 0 12px}p{font-size:19px;color:#526174}.status{display:inline-block;margin-top:18px;padding:8px 14px;border-radius:999px;background:#e8f7ed;color:#176b3a;font-weight:700}
  .meta{margin-top:30px;padding-top:18px;border-top:1px solid #e7ebf0;color:#6b7480;font-size:14px}
</style></head>
<body><main><div class="top"><span>SecureLocal · Live Proof ${index} of 5</span><span>${escapeHtml(proofName)} · ${escapeHtml(date)}</span></div>
<h1>${escapeHtml(title)}</h1><p>${escapeHtml(detail)}</p><span class="status">${escapeHtml(result)}</span>
<div class="meta">Captured from the running local project at ${escapeHtml(baseUrl)}. Generated ${escapeHtml(proofDate.toLocaleTimeString('en-US'))}.</div>
</main></body></html>`;
  fs.writeFileSync(path.join(outputDirectory, `proof-${String(index).padStart(2, '0')}.html`), html, 'utf8');
}

function writeStep(index, title, detail, result) {
  const date = proofDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Project Step ${index} | SecureLocal</title>
<style>
  *{box-sizing:border-box}body{margin:0;background:#f3f5f8;color:#202b3b;font:16px/1.5 "Segoe UI",Arial,sans-serif}
  main{max-width:900px;margin:12vh auto;padding:42px;background:#fff;border:1px solid #e1e6ed;border-radius:20px;box-shadow:0 12px 36px #17203312}
  .top{display:flex;justify-content:space-between;gap:20px;align-items:center;color:#8f391b;font-size:13px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
  h1{font-size:36px;margin:22px 0 12px}p{font-size:19px;color:#526174}.status{display:inline-block;margin-top:18px;padding:8px 14px;border-radius:999px;background:#e8f7ed;color:#176b3a;font-weight:700}
  .meta{margin-top:30px;padding-top:18px;border-top:1px solid #e7ebf0;color:#6b7480;font-size:14px}
</style></head>
<body><main><div class="top"><span>SecureLocal · Project Step ${index} of 4</span><span>${escapeHtml(proofName)} · ${escapeHtml(date)}</span></div>
<h1>${escapeHtml(title)}</h1><p>${escapeHtml(detail)}</p><span class="status">${escapeHtml(result)}</span>
<div class="meta">Project v1 · Local coursework evidence · ${escapeHtml(date)}</div></main></body></html>`;
  fs.writeFileSync(path.join(stepDirectory, `step-${String(index).padStart(2, '0')}.html`), html, 'utf8');
}

async function main() {
  const results = [];
  const loginPage = await fetch(`${baseUrl}/login`);
  assert.equal(loginPage.status, 200);
  const loginHtml = await loginPage.text();
  assert.match(loginHtml, /Welcome back/);
  const csrfToken = loginHtml.match(/name="_csrf" value="([^"]+)"/)?.[1];
  assert.ok(csrfToken, 'Login page must include a CSRF token.');
  const cookies = typeof loginPage.headers.getSetCookie === 'function'
    ? loginPage.headers.getSetCookie()
    : [loginPage.headers.get('set-cookie')];
  const cookie = cookies.find(Boolean)?.split(';', 1)[0];
  assert.ok(cookie, 'Login page must set a session cookie.');
  const injectionResponse = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      _csrf: csrfToken,
      username: "' OR '1'='1",
      password: 'WrongTestPassword123!'
    }),
    redirect: 'manual'
  });
  assert.equal(injectionResponse.status, 401);
  assert.match(await injectionResponse.text(), /Invalid username or password/);
  results.push([
    'Login input is handled safely',
    'The login form serves successfully; a SQL-injection-shaped username with an invalid password receives 401 and does not authenticate.'
  ]);

  const csrfResponse = await fetch(`${baseUrl}/auth/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: 'demo_customer', password: 'WrongTestPassword123!' }),
    redirect: 'manual'
  });
  assert.equal(csrfResponse.status, 403);
  results.push([
    'CSRF protection rejects tokenless POSTs',
    'A state-changing login request without the form token receives HTTP 403.'
  ]);

  const adminResponse = await fetch(`${baseUrl}/admin`, { redirect: 'manual' });
  assert.equal(adminResponse.status, 302);
  assert.equal(adminResponse.headers.get('location'), '/login');
  results.push([
    'Admin dashboard requires authentication',
    'An anonymous request to /admin redirects to /login.'
  ]);

  const admin = db.prepare("SELECT id, role FROM users WHERE role = 'Admin' ORDER BY id LIMIT 1").get();
  const customer = db.prepare("SELECT id, role FROM users WHERE role = 'Customer' ORDER BY id LIMIT 1").get();
  assert.ok(admin, 'Seed or create an Admin account before running proofs.');
  assert.ok(customer, 'Seed a Customer account before running proofs.');
  const adminGate = invoke(requireRole('Admin'), admin);
  const customerGate = invoke(requireRole('Admin'), customer);
  assert.equal(adminGate.next, true);
  assert.equal(customerGate.status, 403);
  results.push([
    'Role-based access is enforced on the server',
    'An Admin passes the role gate; a Customer receives HTTP 403.'
  ]);

  const mfaGate = invoke(requireAdminMfa, admin);
  const adminMfa = db.prepare('SELECT mfa_enabled FROM users WHERE id = ?').get(admin.id);
  assert.equal(mfaGate.redirect, adminMfa.mfa_enabled ? '/mfa/step-up' : '/mfa/setup?required=1');
  const audit = verifyAuditChain();
  assert.equal(audit.valid, true, audit.reason);
  results.push([
    'Admin access requires MFA and the audit chain verifies',
    `Admin is sent to ${mfaGate.redirect}; ${audit.checked} audit entries passed hash-chain verification.`
  ]);

  fs.mkdirSync(outputDirectory, { recursive: true });
  results.forEach(([title, detail], index) => writeProof(index + 1, title, detail, 'PASS'));
  const demoAccounts = db.prepare("SELECT username, role FROM users WHERE username LIKE 'demo_%' ORDER BY username").all();
  assert.equal(demoAccounts.length, 5, 'All five demo role accounts must exist before proof windows are created.');
  const expectedRoles = ['Admin', 'Customer', 'Owner', 'Security Officer', 'Staff'];
  assert.deepEqual(demoAccounts.map((account) => account.role).sort(), expectedRoles);
  fs.mkdirSync(stepDirectory, { recursive: true });
  const reportPdfExists = fs.existsSync(path.join(__dirname, '..', 'SecureLocal-Part2-Report.pdf'));
  const steps = [
    ['Set up the stack', 'Node.js, Express, and SQLite are wired into the project. Routes, middleware, security helpers, views, and public assets are separated into their own folders.'],
    ['Merge components and seed demo roles', 'The five demo roles are present in SQLite. README setup steps and the project folder map are included.'],
    ['Run the five live proofs', results.map(([title]) => title).join(' · ')],
    ['Write Part 2 and prepare the submission', `The overview, permission matrix, tracker, test table, member responsibilities, and deployment note are in the report. PDF ${reportPdfExists ? 'is present' : 'is ready to print from Edge'}.`]
  ];
  steps.forEach(([title, detail], index) => writeStep(index + 1, title, detail, 'READY'));
  console.log(`All ${results.length} live proofs passed.`);
  console.log(`Screenshot-ready proof windows: ${outputDirectory}`);
  console.log(`Screenshot-ready project-step windows: ${stepDirectory}`);
}

main()
  .catch((error) => {
    console.error('Live proof failed:', error.message);
    process.exitCode = 1;
  })
  .finally(() => db.close());
