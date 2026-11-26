require('dotenv').config();
const express=require('express');
const session=require('express-session');
const helmet=require('helmet');
const path=require('path');
const crypto=require('crypto');
const db=require('../db/database');
const authRoutes=require('./routes/auth');
const adminRoutes=require('./routes/admin');
const accountRoutes=require('./routes/account');
const shopRoutes=require('./routes/shop');
const incidentRoutes=require('./routes/incidents');
const securityDashboardRoutes=require('./routes/security-dashboard');
const {audit}=require('./security');
const {requireAuth,requireRole,requireRecentMfa}=require('./middleware/auth');
const app=express(); const PORT=Number(process.env.PORT)||3000; const production=process.env.NODE_ENV==='production';
if(!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32) throw new Error('SESSION_SECRET must be set in .env and contain at least 32 characters.');
if(production) app.set('trust proxy',1);
app.disable('x-powered-by'); app.set('view engine','ejs'); app.set('views',path.join(__dirname,'views'));
app.use(helmet()); app.use(express.urlencoded({extended:false,limit:'20kb'})); app.use(express.json({limit:'20kb'})); app.use(express.static(path.join(__dirname,'../public')));
if(!production) app.use('/proofs',express.static(path.join(__dirname,'../evidence/proofs'),{index:false}));
app.use(session({name:'securelocal.sid',secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,rolling:true,cookie:{httpOnly:true,secure:production,sameSite:'lax',maxAge:30*60*1000}}));
// Synchronizer-token CSRF protection for every state-changing browser form.
app.use((req,res,next)=>{
  if(!req.session.csrfToken) req.session.csrfToken=crypto.randomBytes(32).toString('hex');
  res.locals.csrfToken=req.session.csrfToken; res.locals.currentUser=req.session.user||null;
  if(['POST','PUT','PATCH','DELETE'].includes(req.method)) {
    const supplied=req.body?._csrf||req.get('x-csrf-token')||''; const expected=req.session.csrfToken;
    const a=Buffer.from(String(supplied)); const b=Buffer.from(String(expected));
    if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return res.status(403).render('error',{title:'Request blocked',message:'The security token is missing or expired. Refresh the page and try again.'});
  }
  if(req.session.user) {
    const idleLimit=['Owner','Admin'].includes(req.session.user.role)?15*60*1000:30*60*1000;
    if(req.session.lastActivity&&Date.now()-req.session.lastActivity>idleLimit) {
      try{audit(req.session.user.id,'SESSION_IDLE_TIMEOUT','Session ended after inactivity.',req);}catch(e){console.error(e.message);}
      return req.session.destroy(()=>res.redirect('/login?expired=1'));
    }
    req.session.lastActivity=Date.now();
  }
  next();
});
app.get('/',(req,res)=>res.render('home',{user:req.session.user||null}));
app.get('/register',(req,res)=>req.session.user?res.redirect('/dashboard'):res.render('register',{error:null,username:'',email:''}));
app.get('/login',(req,res)=>req.session.user?res.redirect('/dashboard'):res.render('login',{error:req.query.expired==='1'?'Your session expired due to inactivity. Please log in again.':null,registered:req.query.registered==='1',username:''}));
app.get('/privacy',(req,res)=>res.render('privacy',{user:req.session.user||null}));
app.get('/dashboard',(req,res)=>{if(!req.session.user)return res.redirect('/login');res.render('dashboard',{user:req.session.user});});
app.use('/auth',authRoutes); app.use('/mfa',accountRoutes); app.use('/',shopRoutes); app.use('/incidents',incidentRoutes); app.use('/security',securityDashboardRoutes); app.use('/admin',adminRoutes);
app.get('/db-test',requireAuth,requireRole('Admin'),requireRecentMfa,(req,res)=>{audit(req.session.user.id,'ADMIN_DATABASE_DIAGNOSTIC_VIEWED','Admin checked database connectivity.',req);try{const total=db.prepare('SELECT COUNT(*) total FROM users').get().total;res.json({status:'success',message:'Database connection successful!',totalUsers:total});}catch(e){console.error('DB test failed:',e);res.status(500).json({status:'error',message:'Database connection failed.'});}});
app.use((req,res)=>res.status(404).render('error',{title:'Page not found',message:'The page you requested does not exist.'}));
app.use((err,req,res,next)=>{console.error('Application error:',err);res.status(500).render('error',{title:'Unexpected error',message:'Something went wrong. Please try again.'});});
const server=app.listen(PORT,()=>console.log(`SecureLocal running at http://localhost:${PORT}`));
function shutdown(){server.close(()=>{db.close();process.exit(0);});} process.on('SIGINT',shutdown);process.on('SIGTERM',shutdown);
module.exports=app;
