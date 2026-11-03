'use strict';

require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const required = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY', 'OWNER_USER_ID', 'FRONTEND_ORIGIN'];
const missing = required.filter(k => !String(process.env[k] || '').trim());
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
app.use(express.json({ limit: '4mb' }));
const origins = process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()).filter(Boolean);
app.use(cors({ origin: origins, methods: ['GET','POST','PUT','DELETE','OPTIONS'], allowedHeaders: ['Content-Type','Authorization'], optionsSuccessStatus: 204 }));
app.use('/api', rateLimit({ windowMs: 60_000, limit: 90, standardHeaders: 'draft-7', legacyHeaders: false }));

const ROLE_LABELS = {
  owner: 'LZ Owner 👑', co_owner: 'LZ Co Owner 💎', manager_admin: '𝐌𝐀𝐍𝐀𝐆𝐄𝐑 𝐀𝐃𝐌𝐈𝐍', admin: '𝐋𝐙 𝐀𝐝𝐦𝐢𝐧 🎭', member: 'عضو'
};
const ROLES = Object.keys(ROLE_LABELS);
const STAFF = new Set(['owner', 'co_owner', 'manager_admin']);
const uuid = v => typeof v === 'string' && /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(v);
const fail = (res, status, error, extra = {}) => res.status(status).json({ error, ...extra });
const cleanText = (v, max) => String(v ?? '').trim().slice(0, max);
function validUrl(value) {
  try { const u = new URL(value); return ['https:', 'http:'].includes(u.protocol) ? u.href : null; }
  catch { return null; }
}
async function getRole(userId) {
  if (userId === process.env.OWNER_USER_ID) return 'owner';
  const { data, error } = await supabase.from('lz_user_roles').select('role').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return ROLES.includes(data?.role) ? data.role : 'member';
}
async function readActiveBan(userId) {
  const { data, error } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  if (!data) return null;
  if (data.expires_at && new Date(data.expires_at).getTime() <= Date.now()) {
    const { error: deleteError } = await supabase.from('lz_user_bans').delete().eq('user_id', userId);
    if (deleteError) throw deleteError;
    return null;
  }
  return data;
}
async function auth(req, res, next) {
  try {
    const token = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '')?.[1];
    if (!token) return fail(res, 401, 'سجّل الدخول للمتابعة');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data?.user) return fail(res, 401, 'انتهت جلسة الدخول، سجّل الدخول مجددًا');
    req.user = data.user;
    const ban = await readActiveBan(req.user.id);
    if (ban) return fail(res, 403, 'هذا الحساب محظور', { code: 'USER_BANNED', ban, appeal_url: `https://discord.com/channels/${process.env.DISCORD_GUILD_ID || '1528679532637454376'}/${process.env.DISCORD_APPEAL_CHANNEL_ID || '1565737674357342228'}` });
    next();
  } catch (e) { next(e); }
}
function requireStaff(req, res, next) {
  getRole(req.user.id).then(role => {
    req.role = role;
    if (!STAFF.has(role)) return fail(res, 403, 'ليس لديك صلاحية لهذا الإجراء');
    next();
  }).catch(next);
}
function requireOwner(req, res, next) {
  getRole(req.user.id).then(role => {
    req.role = role;
    if (role !== 'owner') return fail(res, 403, 'هذه العملية متاحة للمالك فقط');
    next();
  }).catch(next);
}

const pages = ['login-dashboard.html','login-designers.html','dashboard.html','designers.html'];
app.get('/', (_req,res) => res.sendFile(path.join(__dirname, 'login-dashboard.html')));
pages.forEach(page => app.get('/' + page, (_req,res) => res.sendFile(path.join(__dirname,page))));
app.get('/logo.png', (_req,res) => res.sendFile(path.join(__dirname,'logo.png')));
app.get('/api/health', (_req,res) => res.json({ ok: true, service: 'LZ EDITORS' }));

// Public designer directory, including each member's current role.
app.get('/api/designers', async (_req,res,next) => {
  try {
    const selectProfiles = () => supabase.from('profiles').select('id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed').eq('onboarding_completed',true).order('created_at',{ascending:false});
    const [first,second] = await Promise.all([selectProfiles().range(0,999),selectProfiles().range(1000,1499)]);
    if(first.error) throw first.error; if(second.error) throw second.error;
    const profiles = [...(first.data || []),...(second.data || [])];
    const ids = profiles.map(p => p.id); const assigned=[];
    for(let i=0;i<ids.length;i+=400){ const {data,error}=await supabase.from('lz_user_roles').select('user_id,role').in('user_id',ids.slice(i,i+400)); if(error) throw error; assigned.push(...(data || [])); }
    const map = new Map(assigned.map(r => [r.user_id,r.role]));
    res.json(profiles.map(p => ({...p,role:p.id===process.env.OWNER_USER_ID?'owner':(map.get(p.id)||'member')})));
  } catch(e) { next(e); }
});

app.get('/api/me', auth, async (req,res,next) => {
  try {
    const identity = req.user.identities?.find(x => x.provider === 'discord')?.identity_data || req.user.user_metadata || {};
    const discordId = cleanText(identity.provider_id || identity.user_id || identity.id || identity.sub || req.user.user_metadata?.provider_id || '', 32);
    const name = cleanText(identity.global_name || identity.full_name || identity.name || identity.username || identity.user_name || identity.preferred_username || 'Discord member',80);
    const avatar = validUrl(identity.avatar_url || identity.image_url) || null;
    const sync = { id:req.user.id, discord_username:name, discord_avatar_url:avatar };
    if (/^\d{15,22}$/.test(discordId)) sync.discord_user_id = discordId;
    const { error:syncError } = await supabase.from('profiles').upsert(sync,{onConflict:'id'});
    if (syncError) throw syncError;
    const { data: profile, error } = await supabase.from('profiles')
      .select('id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed,discord_user_id')
      .eq('id', req.user.id).maybeSingle();
    if (error) throw error;
    res.json({ user_id: req.user.id, profile, role: await getRole(req.user.id) });
  } catch(e) { next(e); }
});

app.put('/api/me/profile', auth, async (req,res,next) => {
  try {
    const tiktok = validUrl(req.body?.tiktok_url);
    if (!tiktok || !['tiktok.com','www.tiktok.com','m.tiktok.com'].includes(new URL(tiktok).hostname)) return fail(res,400,'رابط TikTok غير صالح');
    const identity = req.user.identities?.find(x => x.provider === 'discord')?.identity_data || req.user.user_metadata || {};
    const name = cleanText(identity.global_name || identity.full_name || identity.name || identity.username || identity.user_name || identity.preferred_username || 'Discord member',80);
    const avatar = validUrl(identity.avatar_url || identity.image_url) || null;
    const discordId = cleanText(identity.provider_id || identity.user_id || identity.id || identity.sub || req.user.user_metadata?.provider_id || '', 32);
    const payload = { id:req.user.id, username:name, display_name:name, discord_username:name, discord_avatar_url:avatar, tiktok_url:tiktok, onboarding_completed:true };
    if (/^\d{15,22}$/.test(discordId)) payload.discord_user_id = discordId;
    const { data, error } = await supabase.from('profiles').upsert(payload,{onConflict:'id'})
      .select('id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed').single();
    if (error) throw error;
    res.json(data);
  } catch(e) { next(e); }
});

app.get('/api/messages', async (req,res,next) => {
  try {
    const limit = Math.min(100,Math.max(1,Number.parseInt(req.query.limit,10)||50));
    const { data,error } = await supabase.from('community_messages').select('id,user_id,author_name,author_avatar,text,created_at').order('created_at',{ascending:false}).limit(limit);
    if(error) throw error; res.json(data || []);
  } catch(e) { next(e); }
});
app.post('/api/messages', auth, async (req,res,next) => {
  try {
    const message = cleanText(req.body?.text,500);
    if(!message) return fail(res,400,'اكتب رسالة من 1 إلى 500 حرف');
    const { data:profile,error:pe } = await supabase.from('profiles').select('discord_username,discord_avatar_url,onboarding_completed').eq('id',req.user.id).maybeSingle();
    if(pe) throw pe; if(!profile?.onboarding_completed) return fail(res,403,'أكمل ملفك الشخصي أولاً');
    const { data,error } = await supabase.from('community_messages').insert({user_id:req.user.id,author_name:profile.discord_username || 'Discord member',author_avatar:profile.discord_avatar_url,text:message}).select('id,user_id,author_name,author_avatar,text,created_at').single();
    if(error) throw error; res.status(201).json(data);
  } catch(e) { next(e); }
});
app.delete('/api/messages/:id', auth, async (req,res,next) => {
  try {
    if(!/^[1-9]\d*$/.test(req.params.id)) return fail(res,400,'رقم الرسالة غير صالح');
    const { data:msg,error:re } = await supabase.from('community_messages').select('user_id').eq('id',req.params.id).maybeSingle();
    if(re) throw re; if(!msg) return fail(res,404,'الرسالة غير موجودة');
    const role = await getRole(req.user.id);
    if(msg.user_id !== req.user.id && !STAFF.has(role)) return fail(res,403,'ليس لديك صلاحية الحذف');
    const { error } = await supabase.from('community_messages').delete().eq('id',req.params.id); if(error) throw error;
    res.status(204).end();
  } catch(e) { next(e); }
});

// Role assignment by Supabase user UUID. Owner is fixed and can never be overwritten.
app.put('/api/roles/:userId', auth, requireStaff, async (req,res,next) => {
  try {
    const target = req.params.userId, role = req.body?.role;
    if(!uuid(target) || !ROLES.includes(role)) return fail(res,400,'المستخدم أو الرتبة غير صالحين');
    if(target === process.env.OWNER_USER_ID || role === 'owner') return fail(res,403,'رتبة المالك لا تتغير من هنا');
    if(req.role !== 'owner' && ['co_owner','manager_admin'].includes(role)) return fail(res,403,'المالك فقط يمنح هذه الرتبة');
    if(await getRole(target) === 'owner') return fail(res,403,'لا يمكن تغيير رتبة Owner');
    const { data:profile,error:pe } = await supabase.from('profiles').select('id').eq('id',target).maybeSingle();
    if(pe) throw pe; if(!profile) return fail(res,404,'العضو غير موجود');
    const { error } = await supabase.from('lz_user_roles').upsert({user_id:target,role},{onConflict:'user_id'});
    if(error) throw error; res.json({user_id:target,role,label:ROLE_LABELS[role]});
  } catch(e) { next(e); }
});

// Owner-only: assign the site Owner role using the member's Discord numeric ID.
app.post('/api/roles/owner-by-discord', auth, requireOwner, async (req,res,next) => {
  try {
    const discordId = cleanText(req.body?.discord_id,32);
    if(!/^\d{15,22}$/.test(discordId)) return fail(res,400,'أدخل Discord ID صحيحاً');
    const { data:profile,error } = await supabase.from('profiles').select('id,discord_username').eq('discord_user_id',discordId).maybeSingle();
    if(error) throw error; if(!profile) return fail(res,404,'لم يتم العثور على الحساب. اطلب من العضو تسجيل الدخول إلى الموقع أولاً ثم أعد المحاولة.');
    if(profile.id === process.env.OWNER_USER_ID) return fail(res,409,'هذا الحساب هو المالك الحالي بالفعل');
    const { error:saveError } = await supabase.from('lz_user_roles').upsert({user_id:profile.id,role:'owner'},{onConflict:'user_id'});
    if(saveError) throw saveError;
    res.json({user_id:profile.id,discord_username:profile.discord_username,role:'owner'});
  } catch(e) { next(e); }
});

// Ban management: permanent when expires_at is null; otherwise timed.
app.get('/api/bans', auth, requireStaff, async (_req,res,next) => {
  try {
    const queryBans=()=>supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').order('created_at',{ascending:false});
    const [first,second]=await Promise.all([queryBans().range(0,999),queryBans().range(1000,1499)]);
    if(first.error) throw first.error; if(second.error) throw second.error;
    const bans=[...(first.data || []),...(second.data || [])];
    const active = (bans || []).filter(b => !b.expires_at || new Date(b.expires_at).getTime() > Date.now());
    const ids = active.map(b => b.user_id);
    const { data:profiles,error:pe } = ids.length ? await supabase.from('profiles').select('id,discord_username,discord_avatar_url,discord_user_id').in('id',ids) : {data:[],error:null};
    if(pe) throw pe;
    const map = new Map((profiles || []).map(p => [p.id,p]));
    res.json(active.map(b => ({...b,profile:map.get(b.user_id) || null})));
  } catch(e) { next(e); }
});
app.post('/api/bans', auth, requireStaff, async (req,res,next) => {
  try {
    const userId = req.body?.user_id;
    const reason = cleanText(req.body?.reason,500);
    const rawExpiry = req.body?.expires_at;
    const expiryDate = rawExpiry == null || rawExpiry === '' ? null : new Date(rawExpiry);
    if (expiryDate && !Number.isFinite(expiryDate.getTime())) return fail(res,400,'تاريخ انتهاء الحظر غير صالح');
    const expiresAt = expiryDate ? expiryDate.toISOString() : null;
    if(!uuid(userId) || !reason) return fail(res,400,'اختر عضواً واكتب سبب الحظر');
    if(userId === process.env.OWNER_USER_ID) return fail(res,403,'لا يمكن حظر المالك');
    const targetRole = await getRole(userId);
    if(targetRole === 'owner' || (req.role !== 'owner' && ['co_owner','manager_admin'].includes(targetRole))) return fail(res,403,'لا يمكنك حظر هذا العضو');
    const { data,error } = await supabase.from('lz_user_bans').upsert({user_id:userId,reason,banned_by:req.user.id,expires_at:expiresAt},{onConflict:'user_id'}).select().single();
    if(error) throw error; res.status(201).json(data);
  } catch(e) { next(e); }
});
app.delete('/api/bans/:userId', auth, requireStaff, async (req,res,next) => {
  try {
    if(!uuid(req.params.userId)) return fail(res,400,'معرّف العضو غير صالح');
    const { error } = await supabase.from('lz_user_bans').delete().eq('user_id',req.params.userId);
    if(error) throw error; res.status(204).end();
  } catch(e) { next(e); }
});

app.use((error,_req,res,_next) => {
  console.error('Backend error:',error?.message || error);
  res.status(500).json({error:'حدث خطأ في الخادم. حاول مجدداً.'});
});
const port = Number(process.env.PORT) || 3000;
app.listen(port,() => console.log(`LZ EDITORS service listening on ${port}`));
