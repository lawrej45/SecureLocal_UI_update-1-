const { audit } = require('../security');
const db = require('../../db/database');

function requireAuth(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  next();
}
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.session?.user) return res.redirect('/login');
    const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.user.id);
    if (user) req.session.user.role = user.role;
    if (!user || !roles.includes(user.role)) {
      try { audit(req.session.user.id, 'ACCESS_DENIED', `Denied ${req.method} ${req.path}`, req); } catch (e) { console.error('Audit failure:', e.message); }
      return res.status(403).render('error', { title: 'Access denied', message: 'You do not have permission to access this page.' });
    }
    next();
  };
}
function requireAdminMfa(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.user.id);
  if (!user) return res.redirect('/login');
  req.session.user.role = user.role;
  if (user.role !== 'Admin') return next();
  return requireRecentMfa(req, res, next);
}
function requireRecentMfa(req, res, next) {
  if (!req.session?.user) return res.redirect('/login');
  const user = db.prepare('SELECT mfa_enabled FROM users WHERE id = ?').get(req.session.user.id);
  if (!user?.mfa_enabled) return res.redirect('/mfa/setup?required=1');
  if (!req.session.mfaVerifiedAt || Date.now() - req.session.mfaVerifiedAt > 5 * 60 * 1000) return res.redirect('/mfa/step-up');
  next();
}
module.exports = { requireAuth, requireRole, requireRecentMfa, requireAdminMfa };
