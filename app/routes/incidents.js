const express=require('express');
const db=require('../../db/database');
const {requireAuth,requireRole,requireAdminMfa}=require('../middleware/auth');
const {audit}=require('../security');
const router=express.Router();
router.get('/report',requireAuth,(req,res)=>res.render('incident-report',{user:req.session.user,error:null}));
router.post('/report',requireAuth,(req,res)=>{
  const category=String(req.body.category||'').trim(); const description=String(req.body.description||'').trim(); const severity=req.body.severity;
  if(!['Account security','Suspicious activity','Privacy concern','System issue','Other'].includes(category)||description.length<10||description.length>2000||!['Low','Medium','High','Critical'].includes(severity)) return res.status(400).render('incident-report',{user:req.session.user,error:'Complete the form. Description must be 10–2000 characters.'});
  const result=db.prepare("INSERT INTO incidents (reporter_id,category,description,severity,status) VALUES (?,?,?,?, 'Reported')").run(req.session.user.id,category,description,severity);
  audit(req.session.user.id,'INCIDENT_REPORTED',`Incident #${result.lastInsertRowid} submitted (${severity}).`,req); res.redirect('/incidents');
});
router.get('/',requireAuth,requireAdminMfa,(req,res)=>{
  const canReview=['Admin','Security Officer'].includes(req.session.user.role);
  if(canReview) audit(req.session.user.id,'INCIDENTS_REVIEWED','Authorized incident responder viewed incident records.',req);
  const incidents=canReview?db.prepare('SELECT i.*,u.username FROM incidents i JOIN users u ON u.id=i.reporter_id ORDER BY i.id DESC').all():db.prepare('SELECT * FROM incidents WHERE reporter_id=? ORDER BY id DESC').all(req.session.user.id);
  res.render('incidents',{user:req.session.user,incidents,canReview});
});
router.post('/:id/status',requireAuth,requireRole('Admin','Security Officer'),requireAdminMfa,(req,res)=>{
  const id=Number(req.params.id); const status=req.body.status;
  const workflow=['Reported','Investigating','Contained','Resolved','Lessons learned'];
  const incident=Number.isInteger(id)?db.prepare('SELECT status FROM incidents WHERE id=?').get(id):null;
  if(!incident) return res.status(404).render('error',{title:'Incident not found',message:'The incident could not be found.'});
  const currentIndex=workflow.indexOf(incident.status);
  if(!workflow.includes(status)||workflow.indexOf(status)!==currentIndex+1) return res.status(400).render('error',{title:'Invalid incident transition',message:'Move an incident one step forward through the response workflow.'});
  db.prepare('UPDATE incidents SET status=? WHERE id=?').run(status,id);
  audit(req.session.user.id,'INCIDENT_STATUS_CHANGED',`Incident #${id} moved from ${incident.status} to ${status}.`,req);
  res.redirect('/incidents');
});
module.exports=router;
