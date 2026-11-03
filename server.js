'use strict';

// LZ EDITORS API — Node.js 20+
require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'OWNER_USER_ID', 'FRONTEND_ORIGIN'];
const missing = required.filter(k => !process.env[k]?.trim());
if (missing.length) {
  console.error('Missing environment variables:', missing.join(', '));
  process.exit(1);
}
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
const origins = process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin: origins, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'], optionsSuccessStatus: 204 }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));

const pages = ['login-dashboard.html','login-designers.html','dashboard.html','designers.html'];
app.get('/', (_req,res) => res.sendFile(path.join(__dirname, 'login-dashboard.html')));
for (const page of pages) app.get('/' + page, (_req,res) => res.sendFile(path.join(__dirname, page)));
for (const asset of ['logo.png','manifest.webmanifest']) app.get('/' + asset, (_req,res) => res.sendFile(path.join(__dirname, asset)));

const roleValues = ['member','owner','co_owner','manager_admin','help_admin','admin'];
const adminRoles = new Set(['owner','co_owner','manager_admin']);
const uuid = v => typeof v === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const fail = (res,status,message,extra={}) => res.status(status).json({ error: message, ...extra });
const validUrl = value => { try { const u = new URL(value); return ['https:','http:'].includes(u.protocol) ? u.href : null; } catch { return null; } };

async function getRole(userId) {
  if (userId === process.env.OWNER_USER_ID) return 'owner';
  const { data, error } = await supabase.from('lz_user_roles').select('role').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return roleValues.includes(data?.role) ? data.role : 'member';
}
async function getActiveBan(userId) {
  const { data, error } = await supabase.from('lz_user_bans')
    .select('user_id,reason,expires_at,banned_by,created_at')
    .eq('user_id', userId).order('created_at', { ascending: false }).limit(1).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  if (data.expires_at && new Date(data.expires_at).getTime() <= Date.now()) return null;
  return data;
}
async function auth(req,res,next) {
  try {
    const token = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '')?.[1];
    if (!token) return fail(res,401,'جلسة الدخول غير موجودة. سجّل الدخول مجدداً.');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return fail(res,401,'انتهت الجلسة أو أن رمز الدخول غير صالح.');
    req.user = data.user;
    // Allow a banned user to submit an appeal, but block all other authenticated API actions.
    if (req.path === '/api/bans/appeal') return next();
    const ban = await getActiveBan(req.user.id);
    if (ban) return fail(res,403,'هذا الحساب محظور من LZ EDITORS.',{ banned: true, ban });
    next();
  } catch (e) { next(e); }
}
function requireAdmin(req,res,next) {
  getRole(req.user.id).then(role => {
    req.role = role;
    if (!adminRoles.has(role)) return fail(res,403,'هذه العملية مخصصة للإدارة.');
    next();
  }).catch(next);
}
function requireOwner(req,res,next) {
  getRole(req.user.id).then(role => {
    req.role = role;
    if (role !== 'owner') return fail(res,403,'هذه العملية مخصصة للمالك فقط.');
    next();
  }).catch(next);
}

app.get('/api/health', (_req,res) => res.json({ ok:true, service:'LZ EDITORS API' }));

app.get('/api/designers', async (_req,res,next) => {
  try {
    const { data: profiles, error } = await supabase.from('profiles')
      .select('id,username,display_name,discord_username,discord_avatar_url,tiktok_url,onboarding_completed')
      .eq('onboarding_completed', true).order('created_at',{ascending:false}).limit(1500);
    if (error) throw error;
    const ids = (profiles || []).map(p => p.id);
    let roleMap = new Map();
    if (ids.length) {
      const { data: assigned, error: roleError } = await supabase.from('lz_user_roles').select('user_id,role').in('user_id', ids);
      if (roleError) throw roleError;
      roleMap = new Map((assigned || []).map(r => [r.user_id, r.role]));
    }
    res.json((profiles || []).map(p => ({ ...p, role: p.id === process.env.OWNER_USER_ID ? 'owner' : (roleMap.get(p.id) || 'member') })));
  } catch(e) { next(e); }
});

app.get('/api/me', auth, async (req,res,next) => {
  try {
    const { data: profile, error } = await supabase.from('profiles')
      .select('id,username,display_name,discord_username,discord_avatar_url,tiktok_url,onboarding_completed')
      .eq('id',req.user.id).maybeSingle();
    if (error) throw error;
    res.json({ user_id:req.user.id, profile, role:await getRole(req.user.id) });
  } catch(e) { next(e); }
});

app.put('/api/me/profile', auth, async (req,res,next) => {
  try {
    const tiktok = validUrl(req.body?.tiktok_url);
    if (!tiktok || !['tiktok.com','www.tiktok.com','m.tiktok.com'].includes(new URL(tiktok).hostname)) return fail(res,400,'رابط TikTok غير صالح.');
    const identity = req.user.identities?.find(x => x.provider === 'discord')?.identity_data || req.user.user_metadata || {};
    const name = String(identity.full_name || identity.name || identity.user_name || identity.preferred_username || 'Discord member').slice(0,80);
    const avatar = validUrl(identity.avatar_url) || null;
    const { data, error } = await supabase.from('profiles').upsert({ id:req.user.id, username:name, display_name:name, discord_username:name, discord_avatar_url:avatar, tiktok_url:tiktok, onboarding_completed:true },{onConflict:'id'}).select().single();
    if (error) throw error;
    res.json(data);
  } catch(e) { next(e); }
});

app.get('/api/messages', async (req,res,next) => {
  try {
    const limit = Math.min(100,Math.max(1,parseInt(req.query.limit,10)||50));
    const { data,error } = await supabase.from('community_messages').select('id,user_id,author_name,author_avatar,text,created_at').order('created_at',{ascending:false}).limit(limit);
    if (error) throw error; res.json(data || []);
  } catch(e) { next(e); }
});
app.post('/api/messages', auth, async (req,res,next) => {
  try {
    const text = String(req.body?.text || '').trim();
    if (!text || text.length > 500) return fail(res,400,'الرسالة يجب أن تكون بين 1 و500 حرف.');
    const { data:profile,error:pe } = await supabase.from('profiles').select('discord_username,discord_avatar_url,onboarding_completed').eq('id',req.user.id).maybeSingle();
    if (pe) throw pe;
    if (!profile?.onboarding_completed) return fail(res,403,'أكمل ملفك الشخصي أولاً.');
    const { data,error } = await supabase.from('community_messages').insert({user_id:req.user.id,author_name:profile.discord_username || 'Discord member',author_avatar:profile.discord_avatar_url,text}).select().single();
    if (error) throw error; res.status(201).json(data);
  } catch(e) { next(e); }
});
app.delete('/api/messages/:id', auth, async (req,res,next) => {
  try {
    if (!/^[1-9]\d*$/.test(req.params.id)) return fail(res,400,'معرّف الرسالة غير صالح.');
    const { data:message,error:re } = await supabase.from('community_messages').select('user_id').eq('id',req.params.id).maybeSingle();
    if (re) throw re; if (!message) return fail(res,404,'الرسالة غير موجودة.');
    const role = await getRole(req.user.id);
    if (message.user_id !== req.user.id && !adminRoles.has(role)) return fail(res,403,'غير مسموح.');
    const { error } = await supabase.from('community_messages').delete().eq('id',req.params.id); if (error) throw error;
    res.status(204).end();
  } catch(e) { next(e); }
});

app.put('/api/roles/:userId', auth, requireAdmin, async (req,res,next) => {
  try {
    const target = req.params.userId; const role = req.body?.role;
    if (!uuid(target) || !roleValues.includes(role) || role === 'owner') return fail(res,400,'العضو أو الرتبة غير صالحين.');
    if (target === process.env.OWNER_USER_ID) return fail(res,403,'لا يمكن تغيير رتبة المالك.');
    if (role === 'co_owner' && req.role !== 'owner') return fail(res,403,'المالك فقط يستطيع تعيين Co Owner.');
    if (role === 'manager_admin' && !adminRoles.has(req.role)) return fail(res,403,'لا تملك صلاحية تعيين Manager Admin.');
    const { data:profile,error:pe } = await supabase.from('profiles').select('id').eq('id',target).maybeSingle();
    if (pe) throw pe; if (!profile) return fail(res,404,'المستخدم غير موجود.');
    const { error } = await supabase.from('lz_user_roles').upsert({user_id:target,role},{onConflict:'user_id'});
    if (error) throw error; res.json({user_id:target,role});
  } catch(e) { next(e); }
});

// Content in the existing JSONB row. Existing content is returned unchanged when present.
app.get('/api/content', async (_req,res,next) => {
  try {
    const { data,error } = await supabase.from('lz_site_content').select('content,updated_at').eq('id',1).maybeSingle();
    if (error) throw error;
    res.json(data?.content || {works:[],awards:[],winners:[],designers:[],giveaways:[]});
  } catch(e) { next(e); }
});
app.put('/api/content', auth, requireAdmin, async (req,res,next) => {
  try {
    const content = req.body?.content;
    if (!content || typeof content !== 'object' || Array.isArray(content)) return fail(res,400,'محتوى غير صالح.');
    const allowed = ['works','awards','winners','designers','giveaways'];
    for (const key of allowed) if (content[key] !== undefined && !Array.isArray(content[key])) return fail(res,400,`الحقل ${key} يجب أن يكون قائمة.`);
    const safe = Object.fromEntries(allowed.map(k => [k,Array.isArray(content[k]) ? content[k] : []]));
    const { data,error } = await supabase.from('lz_site_content').upsert({id:1,content:safe,updated_at:new Date().toISOString()},{onConflict:'id'}).select('content,updated_at').single();
    if (error) throw error; res.json(data);
  } catch(e) { next(e); }
});

// Ban management: only Owner, Co Owner and Manager Admin.
app.get('/api/bans', auth, requireAdmin, async (_req,res,next) => {
  try {
    const { data:bans,error } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').order('created_at',{ascending:false}).limit(1000);
    if (error) throw error;
    const rows = bans || []; const ids = [...new Set(rows.map(x=>x.user_id))];
    const latestByUser = new Map();
    for (const row of rows) if (!latestByUser.has(row.user_id)) latestByUser.set(row.user_id, row);
    let profiles = new Map();
    if (ids.length) {
      const { data:ps,error:pe } = await supabase.from('profiles').select('id,discord_username,display_name,discord_avatar_url').in('id',ids);
      if (pe) throw pe; profiles = new Map((ps||[]).map(p=>[p.id,p]));
    }
    res.json(rows.map(b=>({...b,profile:profiles.get(b.user_id)||null,active:latestByUser.get(b.user_id)===b && (!b.expires_at || new Date(b.expires_at).getTime()>Date.now())})));
  } catch(e) { next(e); }
});
app.post('/api/bans/ban/:userId', auth, requireAdmin, async (req,res,next) => {
  try {
    const target=req.params.userId; const reason=String(req.body?.reason||'').trim().slice(0,500);
    const minutes=Number(req.body?.duration_minutes);
    if (!uuid(target) || target===process.env.OWNER_USER_ID) return fail(res,400,'لا يمكن حظر هذا الحساب.');
    if (!reason) return fail(res,400,'اكتب سبب الحظر.');
    if (!Number.isFinite(minutes) || minutes<0 || (minutes!==0 && minutes>5256000)) return fail(res,400,'مدة الحظر غير صالحة.');
    const {data:profile,error:pe}=await supabase.from('profiles').select('id').eq('id',target).maybeSingle();
    if(pe) throw pe; if(!profile) return fail(res,404,'المستخدم غير موجود.');
    const expires_at=minutes===0?null:new Date(Date.now()+minutes*60000).toISOString();
    const {data,error}=await supabase.from('lz_user_bans').insert({user_id:target,reason,expires_at,banned_by:req.user.id}).select().single();
    if(error) throw error; res.status(201).json(data);
  } catch(e) { next(e); }
});
app.delete('/api/bans/unban/:userId', auth, requireAdmin, async (req,res,next) => {
  try {
    if(!uuid(req.params.userId)) return fail(res,400,'معرّف المستخدم غير صالح.');
    const {error}=await supabase.from('lz_user_bans').delete().eq('user_id',req.params.userId);
    if(error) throw error; res.json({ok:true,user_id:req.params.userId});
  } catch(e) { next(e); }
});

// Banned users can still send an appeal. Discord bot credentials stay server-side.
app.post('/api/bans/appeal', auth, async (req,res,next) => {
  try {
    const message=String(req.body?.message||'').trim();
    if(message.length<10 || message.length>1500) return fail(res,400,'اكتب طعناً من 10 إلى 1500 حرف.');
    const ban=await getActiveBan(req.user.id);
    if(!ban) return fail(res,400,'لا يوجد حظر نشط على حسابك.');
    const channel=process.env.DISCORD_APPEALS_CHANNEL_ID || '1565737674357342228';
    const token=process.env.DISCORD_BOT_TOKEN;
    if(!token) return fail(res,503,'إرسال الطعون إلى Discord غير مفعّل بعد. أضف DISCORD_BOT_TOKEN إلى إعدادات السيرفر.');
    const {data:profile}=await supabase.from('profiles').select('discord_username,display_name').eq('id',req.user.id).maybeSingle();
    const displayName=profile?.discord_username || profile?.display_name || 'عضو LZ';
    const body={
      content:'📨 طعن حظر جديد — LZ EDITORS',
      allowed_mentions:{parse:[]},
      embeds:[{
        title:'طعن حظر جديد',
        color:0x9b5cff,
        description:message,
        fields:[
          {name:'العضو',value:String(displayName).slice(0,80),inline:true},
          {name:'Supabase User ID',value:req.user.id,inline:false},
          {name:'سبب الحظر',value:String(ban.reason||'غير محدد').slice(0,900),inline:false},
          {name:'ينتهي في',value:ban.expires_at || 'حظر دائم',inline:false}
        ],
        footer:{text:'LZ EDITORS • Ban Appeals'}
      }]
    };
    const discord=await fetch(`https://discord.com/api/v10/channels/${channel}/messages`,{method:'POST',headers:{Authorization:`Bot ${token}`,'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!discord.ok){const detail=await discord.text();console.error('Discord appeal error',discord.status,detail);return fail(res,502,'تعذر إرسال الطعن إلى Discord. تحقق من صلاحية البوت والقناة.');}
    res.status(201).json({ok:true,message:'تم إرسال الطعن إلى فريق الإدارة.'});
  } catch(e) { next(e); }
});

app.use((error,_req,res,_next)=>{ console.error('Backend error:',error); res.status(500).json({error:'خطأ في الخادم. راجع سجلات Render.'}); });
const port=Number(process.env.PORT)||3000;
app.listen(port,()=>console.log(`LZ EDITORS API listening on ${port}`));
