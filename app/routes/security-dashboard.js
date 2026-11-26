const express=require('express');
const crypto=require('crypto');
const db=require('../../db/database');
const {requireAuth,requireRole,requireAdminMfa}=require('../middleware/auth');
const {audit}=require('../security');

const router=express.Router();
router.use(requireAuth,requireRole('Admin','Security Officer'),requireAdminMfa);

function dashboardData(now=new Date()) {
  const dayStart=new Date(now.getTime()-6*24*60*60*1000).toISOString();
  const hourStart=new Date(now.getTime()-60*60*1000).toISOString();
  const dayAgo=new Date(now.getTime()-24*60*60*1000).toISOString();
  const failuresByDay=db.prepare(`
    SELECT substr(created_at,1,10) day,COUNT(*) count
    FROM audit_logs
    WHERE action='LOGIN_FAILED' AND created_at>=?
    GROUP BY substr(created_at,1,10)
  `).all(dayStart);
  const failureCounts=new Map(failuresByDay.map(row=>[row.day,row.count]));
  const failedLoginsByDay=Array.from({length:7},(_,index)=>{
    const date=new Date(now.getTime()-(6-index)*24*60*60*1000);
    const day=date.toISOString().slice(0,10);
    return {day,count:failureCounts.get(day)||0};
  });
  const recentFailures=db.prepare("SELECT COUNT(*) count FROM audit_logs WHERE action='LOGIN_FAILED' AND created_at>=?").get(hourStart).count;
  const lockedAccounts=db.prepare('SELECT COUNT(*) count FROM users WHERE locked_until IS NOT NULL AND locked_until>?').get(now.toISOString()).count;
  const deniedAccess=db.prepare("SELECT COUNT(*) count FROM audit_logs WHERE action='ACCESS_DENIED' AND created_at>=?").get(dayAgo).count;
  return {
    generatedAt:now.toISOString(),
    failedLoginsByDay,
    lockedAccounts,
    deniedAccessLast24Hours:deniedAccess,
    failedLoginsLastHour:recentFailures,
    alert:recentFailures>=10
  };
}

router.get('/',(req,res)=>{
  const metrics=dashboardData();
  audit(req.session.user.id,'SECURITY_DASHBOARD_VIEWED','Security dashboard viewed.',req);
  res.render('security-dashboard',{user:req.session.user,metrics});
});

router.get('/report',(req,res)=>{
  const metrics=dashboardData();
  const report=JSON.stringify(metrics);
  audit(req.session.user.id,'SECURITY_REPORT_EXPORTED','Security dashboard report downloaded.',req);
  res.setHeader('Cache-Control','no-store');
  res.setHeader('Content-Type','application/json; charset=utf-8');
  res.setHeader('Content-Disposition','attachment; filename="securelocal-security-report.json"');
  res.setHeader('X-Content-SHA256',crypto.createHash('sha256').update(report).digest('hex'));
  res.send(report);
});

module.exports=router;
