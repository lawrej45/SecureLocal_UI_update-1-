const express = require('express');
const crypto = require('crypto');
const db = require('../../db/database');
const { requireAuth, requireRole, requireRecentMfa } = require('../middleware/auth');
const { audit, verifyAuditChain, encryptText, decryptText } = require('../security');
const router = express.Router();
router.use(requireAuth, requireRole('Admin'), requireRecentMfa);
router.get('/',(req,res)=>{
  audit(req.session.user.id,'ADMIN_DASHBOARD_VIEWED','Admin dashboard accessed.',req);
  const stats={users:db.prepare('SELECT COUNT(*) n FROM users').get().n,orders:db.prepare('SELECT COUNT(*) n FROM orders').get().n,openIncidents:db.prepare("SELECT COUNT(*) n FROM incidents WHERE status IN ('Reported','Investigating','Contained')").get().n,events:db.prepare('SELECT COUNT(*) n FROM audit_logs').get().n};
  const recent=db.prepare('SELECT action,details,created_at FROM audit_logs ORDER BY id DESC LIMIT 8').all();
  res.render('admin',{user:req.session.user,stats,recent});
});
router.get('/audit-logs',(req,res)=>{
  audit(req.session.user.id,'ADMIN_AUDIT_LOGS_VIEWED','Admin viewed audit logs.',req);
  const logs=db.prepare(`SELECT a.id,a.user_id,COALESCE(u.username,'System / Unknown') username,a.action,a.details,a.ip_address,a.created_at,a.previous_hash,a.entry_hash FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 250`).all();
  res.render('audit-logs',{user:req.session.user,logs,integrity:verifyAuditChain()});
});
router.get('/backup',(req,res)=>{
  const now=new Date().toISOString();
  const users=db.prepare('SELECT id,username,email,role,consent_accepted_at,mfa_enabled,failed_attempts,locked_until,created_at FROM users ORDER BY id').all();
  const orders=db.prepare('SELECT id,user_id,customer_name,contact_number,contact_number_enc,address,address_enc,total,notes,menu_item_id,item_name,quantity,status,created_at FROM orders ORDER BY id').all()
    .map(order=>({
      ...order,
      contact_number_enc:encryptText(decryptText(order.contact_number_enc||order.contact_number)),
      address_enc:encryptText(decryptText(order.address_enc||order.address)),
      contact_number:undefined,
      address:undefined
    }));
  const data={
    generatedAt:now,
    note:'Credential hashes, MFA secrets, and backup codes are excluded. Order contact details are encrypted with PII_ENCRYPTION_KEY.',
    users,
    menu:db.prepare('SELECT * FROM menu ORDER BY id').all(),
    orders,
    incidents:db.prepare('SELECT * FROM incidents ORDER BY id').all(),
    dataRequests:db.prepare('SELECT * FROM data_requests ORDER BY id').all(),
    auditLogs:db.prepare('SELECT * FROM audit_logs ORDER BY id').all()
  };
  const checksum=crypto.createHash('sha256').update(JSON.stringify(data)).digest('hex');
  audit(req.session.user.id,'BACKUP_EXPORTED','Application data backup downloaded with SHA-256 checksum.',req);
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Disposition','attachment; filename="securelocal-backup.json"');
  res.json({algorithm:'SHA-256',checksum,data});
});
router.get('/menu',(req,res)=>{ audit(req.session.user.id,'ADMIN_MENU_VIEWED','Admin viewed menu management.',req); const menu=db.prepare('SELECT * FROM menu ORDER BY id DESC').all(); res.render('admin-menu',{user:req.session.user,menu}); });
router.post('/menu',(req,res)=>{ const name=String(req.body.name||'').trim(); const description=String(req.body.description||'').trim(); const price=Number(req.body.price); if(name.length<2||name.length>100||description.length>500||!Number.isFinite(price)||price<0||price>100000) return res.status(400).send('Invalid menu item.'); const result=db.prepare('INSERT INTO menu(name,description,price) VALUES(?,?,?)').run(name,description,price); audit(req.session.user.id,'MENU_ITEM_CREATED',`Menu item #${result.lastInsertRowid} created.`,req); res.redirect('/admin/menu'); });
router.post('/menu/:id/update',(req,res)=>{ const id=Number(req.params.id); const name=String(req.body.name||'').trim(); const description=String(req.body.description||'').trim(); const price=Number(req.body.price); if(!Number.isInteger(id)||name.length<2||name.length>100||description.length>500||!Number.isFinite(price)||price<0||price>100000) return res.status(400).send('Invalid menu item.'); const result=db.prepare('UPDATE menu SET name=?,description=?,price=? WHERE id=?').run(name,description,price,id); if(result.changes) audit(req.session.user.id,'MENU_ITEM_UPDATED',`Menu item #${id} updated.`,req); res.redirect('/admin/menu'); });
router.post('/menu/:id/delete',(req,res)=>{ const result=db.prepare('DELETE FROM menu WHERE id=?').run(Number(req.params.id)); if(result.changes) audit(req.session.user.id,'MENU_ITEM_DELETED',`Menu item #${req.params.id} deleted.`,req); res.redirect('/admin/menu'); });
router.post('/menu/:id/availability',(req,res)=>{ const available=req.body.available==='1'?1:0; const result=db.prepare('UPDATE menu SET available=? WHERE id=?').run(available,Number(req.params.id)); if(result.changes) audit(req.session.user.id,'MENU_AVAILABILITY_CHANGED',`Menu item #${req.params.id} availability set to ${available}.`,req); res.redirect('/admin/menu'); });
router.get('/users',(req,res)=>{
  audit(req.session.user.id,'ADMIN_USERS_VIEWED','Admin viewed user records.',req);
  const users=db.prepare('SELECT id,username,email,role,mfa_enabled,failed_attempts,locked_until,created_at FROM users ORDER BY id').all();
  res.render('admin-users',{user:req.session.user,users});
});
router.get('/data-requests',(req,res)=>{
  audit(req.session.user.id,'ADMIN_DATA_REQUESTS_VIEWED','Admin viewed privacy requests.',req);
  const requests=db.prepare(`
    SELECT r.*,u.username,u.email
    FROM data_requests r JOIN users u ON u.id=r.user_id
    ORDER BY r.id DESC
  `).all();
  res.render('data-requests',{user:req.session.user,requests});
});
router.post('/data-requests/:id/status',(req,res)=>{
  const id=Number(req.params.id);
  const nextStatus=req.body.status;
  const resolution=typeof req.body.resolution==='string'?req.body.resolution.trim():'';
  const request=Number.isInteger(id)?db.prepare('SELECT status,request_type FROM data_requests WHERE id=?').get(id):null;
  if(!request) return res.status(404).render('error',{title:'Request not found',message:'The privacy request could not be found.'});
  const transitions={Pending:['In review'],'In review':['Completed','Rejected']};
  if(!transitions[request.status]?.includes(nextStatus)||resolution.length>1000) {
    return res.status(400).render('error',{title:'Invalid request update',message:'Review pending requests first, then complete or reject them with an optional note.'});
  }
  const processed=nextStatus==='Completed'||nextStatus==='Rejected';
  db.prepare('UPDATE data_requests SET status=?,resolution=?,processed_at=?,processed_by=? WHERE id=?')
    .run(nextStatus,resolution||null,processed?new Date().toISOString():null,processed?req.session.user.id:null,id);
  audit(req.session.user.id,'DATA_REQUEST_PROCESSED',`Data ${request.request_type.toLowerCase()} request #${id} marked ${nextStatus}.`,req);
  res.redirect('/admin/data-requests');
});
router.post('/users/:id/role',requireRole('Admin'),(req,res)=>{
  const id=Number(req.params.id); const role=req.body.role;
  const allowed=['Admin','Staff','Security Officer','Customer'];
  if(!Number.isInteger(id)||!allowed.includes(role)) return res.status(400).send('Invalid role update.');
  const target=db.prepare('SELECT username,role FROM users WHERE id=?').get(id);
  if(!target) return res.status(404).send('User not found.');
  if(target.role==='Owner') return res.status(403).send('Owner accounts cannot be changed by an Admin.');
  if(id===req.session.user.id && role!=='Admin') return res.status(400).send('You cannot remove your own Admin role.');
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role,id);
  audit(req.session.user.id,'ROLE_CHANGED',`Changed ${target.username} from ${target.role} to ${role}.`,req);
  res.redirect('/admin/users');
});
module.exports=router;
