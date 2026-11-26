const express = require('express');
const db = require('../../db/database');
const { requireAuth, requireRole, requireRecentMfa, requireAdminMfa } = require('../middleware/auth');
const { audit, encryptText, decryptText } = require('../security');
const router=express.Router();
router.get('/menu',(req,res)=>{
  const menu=db.prepare('SELECT id,name,description,price,available FROM menu WHERE available=1 ORDER BY name').all();
  res.render('menu',{user:req.session.user||null,menu});
});
router.post('/orders',requireAuth,(req,res)=>{
  const menuId=Number(req.body.menu_id); const quantity=Number(req.body.quantity);
  const customerName=String(req.body.customer_name||'').trim(); const phone=String(req.body.contact_number||'').trim(); const address=String(req.body.address||'').trim(); const notes=String(req.body.notes||'').trim();
  if(!Number.isInteger(menuId)||!Number.isInteger(quantity)||quantity<1||quantity>20||customerName.length<2||customerName.length>100||phone.length>30||address.length<5||address.length>500||notes.length>500) return res.status(400).render('error',{title:'Invalid order',message:'Check the order fields and try again.'});
  const item=db.prepare('SELECT id,name,price FROM menu WHERE id=? AND available=1').get(menuId);
  if(!item) return res.status(400).render('error',{title:'Unavailable item',message:'That menu item is no longer available.'});
  try {
    const total=Number((item.price*quantity).toFixed(2));
    const result=db.prepare(`INSERT INTO orders (user_id,customer_name,contact_number,address,contact_number_enc,address_enc,total,notes,menu_item_id,item_name,quantity) VALUES (?,?,NULL,NULL,?,?,?,?,?,?,?)`).run(req.session.user.id,customerName,encryptText(phone),encryptText(address),total,notes,item.id,item.name,quantity);
    audit(req.session.user.id,'ORDER_CREATED',`Order #${result.lastInsertRowid} placed.`,req);
    res.redirect('/orders');
  } catch(e) { console.error('Order create error:',e); res.status(500).render('error',{title:'Order failed',message:'The order could not be saved. Check the encryption key in .env.'}); }
});
router.get('/orders',requireAuth,requireAdminMfa,(req,res)=>{
  const isStaff=req.session.user.role==='Admin';
  if(isStaff) audit(req.session.user.id,'ADMIN_ORDERS_VIEWED','Admin viewed order records.',req);
  const rows=isStaff?db.prepare(`SELECT o.*,u.username FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200`).all():db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.session.user.id);
  const orders=rows.map(o=>({...o,contact_number:decryptText(o.contact_number_enc||o.contact_number),address:decryptText(o.address_enc||o.address)}));
  res.render('orders',{user:req.session.user,orders,isStaff});
});
router.post('/orders/:id/cancel',requireAuth,(req,res)=>{
  const order=db.prepare('SELECT user_id,status FROM orders WHERE id=?').get(Number(req.params.id));
  if(!order || order.user_id!==req.session.user.id || order.status!=='Pending') return res.status(403).render('error',{title:'Unable to cancel',message:'Only your own pending order can be cancelled.'});
  db.prepare('UPDATE orders SET status=\'Cancelled\' WHERE id=?').run(Number(req.params.id)); audit(req.session.user.id,'ORDER_CANCELLED',`Order #${req.params.id} cancelled by customer.`,req); res.redirect('/orders');
});
router.post('/orders/:id/status',requireAuth,requireRole('Admin'),requireRecentMfa,(req,res)=>{
  const status=req.body.status; const allowed=['Pending','Confirmed','Preparing','Ready','Completed','Cancelled'];
  if(!allowed.includes(status)) return res.status(400).send('Invalid order status.');
  const result=db.prepare('UPDATE orders SET status=? WHERE id=?').run(status,Number(req.params.id));
  if(result.changes) audit(req.session.user.id,'ORDER_STATUS_CHANGED',`Order #${req.params.id} changed to ${status}.`,req);
  res.redirect('/orders');
});
module.exports=router;
