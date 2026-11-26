const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const QRCode = require('qrcode');
const db = require('../../db/database');
const { requireAuth } = require('../middleware/auth');
const { audit, base32Encode, verifyTotp, encryptText, decryptText } = require('../security');
const router = express.Router();
const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function randomBackupCode() { const b=crypto.randomBytes(10); let s=''; for(let i=0;i<10;i++) s+=alphabet[b[i]%alphabet.length]; return s.match(/.{1,5}/g).join('-'); }
function pendingUser(req) { return req.session.pendingMfaUserId ? db.prepare('SELECT * FROM users WHERE id=?').get(req.session.pendingMfaUserId) : null; }
router.get('/setup',requireAuth,async(req,res) => {
  const existing=db.prepare('SELECT mfa_enabled FROM users WHERE id=?').get(req.session.user.id);
  if(existing?.mfa_enabled && (!req.session.mfaVerifiedAt || Date.now()-req.session.mfaVerifiedAt>5*60*1000)) return res.redirect('/mfa/step-up');
  const secret = base32Encode(crypto.randomBytes(20)); req.session.pendingMfaSecret=secret;
  const uri=`otpauth://totp/SecureLocal:${encodeURIComponent(req.session.user.username)}?secret=${secret}&issuer=SecureLocal&algorithm=SHA1&digits=6&period=30`;
  const qr=await QRCode.toDataURL(uri);
  res.render('mfa-setup',{qr,secret,error:null,backupCodes:null,required:req.query.required==='1'});
});
router.post('/setup',requireAuth,async(req,res) => {
  const existing=db.prepare('SELECT mfa_enabled FROM users WHERE id=?').get(req.session.user.id);
  if(existing?.mfa_enabled && (!req.session.mfaVerifiedAt || Date.now()-req.session.mfaVerifiedAt>5*60*1000)) return res.redirect('/mfa/step-up');
  const secret=req.session.pendingMfaSecret;
  if(!secret || !verifyTotp(secret,req.body.code)) {
    const uri=secret?`otpauth://totp/SecureLocal:${encodeURIComponent(req.session.user.username)}?secret=${secret}&issuer=SecureLocal&algorithm=SHA1&digits=6&period=30`:'';
    const qr=uri?await QRCode.toDataURL(uri):null;
    return res.status(400).render('mfa-setup',{qr,secret,error:'The code did not match. Check your authenticator app and try again.',backupCodes:null,required:false});
  }
  const codes=Array.from({length:10},randomBackupCode);
  const insert=db.prepare('INSERT INTO mfa_backup_codes (user_id,code_hash) VALUES (?,?)');
  db.prepare('DELETE FROM mfa_backup_codes WHERE user_id=?').run(req.session.user.id);
  for(const code of codes) insert.run(req.session.user.id,await bcrypt.hash(code,10));
  db.prepare('UPDATE users SET mfa_enabled=1,mfa_secret=? WHERE id=?').run(encryptText(secret),req.session.user.id);
  req.session.pendingMfaSecret=null; req.session.mfaVerifiedAt=Date.now();
  audit(req.session.user.id,'MFA_ENABLED','TOTP multi-factor authentication enabled.',req);
  if(req.session.user.role==='Admin') audit(req.session.user.id,'ADMIN_LOGIN_SUCCESS','Admin completed MFA setup during sign-in.',req);
  res.render('mfa-setup',{qr:null,secret:null,error:null,backupCodes:codes,required:false});
});
router.get('/verify',(req,res)=>{ if(!pendingUser(req)) return res.redirect('/login'); res.render('mfa-verify',{error:null,stepUp:false}); });
router.post('/verify',async(req,res)=>{
  const user=pendingUser(req); if(!user) return res.redirect('/login');
  let valid=verifyTotp(decryptText(user.mfa_secret),req.body.code);
  if(!valid && typeof req.body.code==='string') {
    const codes=db.prepare('SELECT id,code_hash FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL').all(user.id);
    for(const item of codes) if(await bcrypt.compare(req.body.code.trim().toUpperCase(),item.code_hash)) { valid=true; db.prepare('UPDATE mfa_backup_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?').run(item.id); audit(user.id,'MFA_BACKUP_CODE_USED','A one-time backup code was used.',req); break; }
  }
  if(!valid) { audit(user.id,'MFA_FAILED','Invalid second-factor code.',req); return res.status(401).render('mfa-verify',{error:'Invalid code. Try again.',stepUp:false}); }
  req.session.user={id:user.id,username:user.username,role:user.role}; req.session.pendingMfaUserId=null; req.session.mfaVerifiedAt=Date.now();
  audit(user.id,'MFA_LOGIN_SUCCESS','MFA login completed.',req);
  if(user.role==='Admin') audit(user.id,'ADMIN_LOGIN_SUCCESS','Admin signed in with MFA.',req);
  res.redirect('/dashboard');
});
router.get('/step-up',requireAuth,(req,res)=>res.render('mfa-verify',{error:null,stepUp:true}));
router.post('/step-up',requireAuth,async(req,res)=>{
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.session.user.id);
  let valid=verifyTotp(decryptText(user.mfa_secret),req.body.code);
  if(!valid && typeof req.body.code==='string') {
    const codes=db.prepare('SELECT id,code_hash FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL').all(user.id);
    for(const item of codes) if(await bcrypt.compare(req.body.code.trim().toUpperCase(),item.code_hash)) { valid=true; db.prepare('UPDATE mfa_backup_codes SET used_at=CURRENT_TIMESTAMP WHERE id=?').run(item.id); audit(user.id,'MFA_BACKUP_CODE_USED','A one-time backup code was used for step-up verification.',req); break; }
  }
  if(!valid) return res.status(401).render('mfa-verify',{error:'Invalid code. Try again.',stepUp:true});
  req.session.mfaVerifiedAt=Date.now(); audit(user.id,'MFA_STEP_UP','Fresh MFA verification completed.',req); res.redirect('/admin');
});
router.get('/my-data',requireAuth,(req,res)=>{
  const user=db.prepare('SELECT id,username,email,role,consent_accepted_at,created_at,mfa_enabled FROM users WHERE id=?').get(req.session.user.id);
  const orders=db.prepare('SELECT id,customer_name,contact_number,contact_number_enc,address,address_enc,total,notes,item_name,quantity,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(user.id)
    .map(order=>({...order,contact_number:decryptText(order.contact_number_enc||order.contact_number),address:decryptText(order.address_enc||order.address)}));
  const incidents=db.prepare('SELECT id,category,description,severity,status,created_at FROM incidents WHERE reporter_id=? ORDER BY id DESC').all(user.id);
  const dataRequests=db.prepare('SELECT id,request_type,details,status,resolution,created_at,processed_at FROM data_requests WHERE user_id=? ORDER BY id DESC').all(user.id);
  res.render('my-data',{user,orders,incidents,dataRequests,error:null});
});
router.get('/my-data/export',requireAuth,(req,res)=>{
  const user=db.prepare('SELECT id,username,email,role,consent_accepted_at,created_at,mfa_enabled FROM users WHERE id=?').get(req.session.user.id);
  const orders=db.prepare('SELECT id,customer_name,contact_number,contact_number_enc,address,address_enc,total,notes,item_name,quantity,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(user.id)
    .map(order=>({...order,contact_number:decryptText(order.contact_number_enc||order.contact_number),address:decryptText(order.address_enc||order.address)}));
  const incidents=db.prepare('SELECT id,category,description,severity,status,created_at FROM incidents WHERE reporter_id=? ORDER BY id DESC').all(user.id);
  const dataRequests=db.prepare('SELECT id,request_type,details,status,resolution,created_at,processed_at FROM data_requests WHERE user_id=? ORDER BY id DESC').all(user.id);
  audit(user.id,'MY_DATA_EXPORTED','User exported their account data.',req);
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Disposition','attachment; filename="securelocal-my-data.json"'); res.json({exportedAt:new Date().toISOString(),user,orders,incidents,dataRequests});
});
router.post('/my-data/requests',requireAuth,(req,res)=>{
  const requestType=req.body.request_type;
  const details=typeof req.body.details==='string'?req.body.details.trim():'';
  if(!['Correction','Deletion'].includes(requestType)||details.length<10||details.length>1000) {
    const user=db.prepare('SELECT id,username,email,role,consent_accepted_at,created_at,mfa_enabled FROM users WHERE id=?').get(req.session.user.id);
    const orders=db.prepare('SELECT id,customer_name,contact_number,contact_number_enc,address,address_enc,total,notes,item_name,quantity,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC').all(user.id)
      .map(order=>({...order,contact_number:decryptText(order.contact_number_enc||order.contact_number),address:decryptText(order.address_enc||order.address)}));
    const incidents=db.prepare('SELECT id,category,description,severity,status,created_at FROM incidents WHERE reporter_id=? ORDER BY id DESC').all(user.id);
    const dataRequests=db.prepare('SELECT id,request_type,details,status,resolution,created_at,processed_at FROM data_requests WHERE user_id=? ORDER BY id DESC').all(user.id);
    return res.status(400).render('my-data',{user,orders,incidents,dataRequests,error:'Choose a request type and provide 10–1000 characters of detail.'});
  }
  const result=db.prepare('INSERT INTO data_requests (user_id,request_type,details) VALUES (?,?,?)').run(req.session.user.id,requestType,details);
  audit(req.session.user.id,'DATA_REQUEST_SUBMITTED',`Data ${requestType.toLowerCase()} request #${result.lastInsertRowid} submitted.`,req);
  res.redirect('/mfa/my-data');
});
module.exports=router;
