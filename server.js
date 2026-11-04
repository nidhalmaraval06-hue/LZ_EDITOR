'use strict';

// LZ EDITORS Backend — Node.js 20+
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');

const required = [
  'SUPABASE_URL',
  'SUPABASE_SERVICE_ROLE_KEY',
  'OWNER_USER_ID',
  'FRONTEND_ORIGIN'
];

const missing = required.filter(name => !process.env[name]?.trim());

if (missing.length) {
  console.error('\n❌ Missing environment variables:');
  for (const name of missing) console.error(` - ${name}`);
  console.error('\nAdd them to your .env file and restart the server.\n');
  process.exit(1);
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// صفحات الموقع
const pages = [
  'login-dashboard.html',
  'login-designers.html',
  'dashboard.html',
  'designers.html'
];

app.get('/', (_req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  res.sendFile(path.join(__dirname, 'login-dashboard.html'));
});
app.get('/login-dashboard.html', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login-dashboard.html'));
});

pages.forEach(page => {
  app.get('/' + page, (_req, res) => {
    res.set('Cache-Control', 'no-store, max-age=0');
    res.sendFile(path.join(__dirname, page));
  });
});

// الشعار
app.get('/logo.png', (_req, res) => {
  res.sendFile(path.join(__dirname, 'logo.png'));
});
app.get('/manifest.webmanifest', (_req, res) => {
  res.type('application/manifest+json').sendFile(path.join(__dirname, 'manifest.webmanifest'));
});
app.get('/sw.js', (_req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Service-Worker-Allowed', '/').type('application/javascript').sendFile(path.join(__dirname, 'sw.js'));
});

app.use(express.json({ limit: '6mb' }));

const origins = process.env.FRONTEND_ORIGIN
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);

app.use(cors({
  origin: origins,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
}));

app.use('/api', rateLimit({
  windowMs: 60_000,
  limit: 90,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const roles = ['member', 'owner', 'co_owner', 'manager_admin', 'admin'];
const adminRoles = new Set(['owner', 'co_owner', 'manager_admin']);

const uuid = value =>
  typeof value === 'string' &&
  /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);

function discordIdFromUser(user) {
  const identity = user?.identities?.find(item => item.provider === 'discord')?.identity_data || {};
  const metadata = user?.user_metadata || {};
  const value = identity.id || identity.sub || identity.user_id || metadata.provider_id || metadata.discord_id || metadata.sub;
  const normalized = value == null ? '' : String(value);
  return /^\d{17,20}$/.test(normalized) ? normalized : null;
}

function validUrl(value) {
  try {
    const parsed = new URL(value);
    return ['https:', 'http:'].includes(parsed.protocol)
      ? parsed.href
      : null;
  } catch {
    return null;
  }
}

const fail = (res, status, message) =>
  res.status(status).json({ error: message });

// التحقق من تسجيل الدخول
async function auth(req, res, next) {
  try {
    const token = /^Bearer (.+)$/i.exec(
      req.get('authorization') || ''
    )?.[1];

    if (!token) {
      return fail(res, 401, 'Discord/Supabase login required');
    }

    const { data, error } = await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return fail(res, 401, 'Invalid or expired session');
    }

    req.user = data.user;

    // منع الحسابات المحظورة من استخدام واجهات API المحمية
    const { data: ban, error: banError } = await supabase
      .from('lz_user_bans')
      .select('reason,expires_at')
      .eq('user_id', req.user.id)
      .maybeSingle();

    if (banError) throw banError;
    if (ban) {
      const expired = ban.expires_at && new Date(ban.expires_at).getTime() <= Date.now();
      if (!expired) {
        return res.status(403).json({
          code: 'USER_BANNED',
          error: 'هذا الحساب محظور من الموقع',
          ban: { reason: ban.reason || '', expires_at: ban.expires_at }
        });
      }
      await supabase.from('lz_user_bans').delete().eq('user_id', req.user.id);
    }

    next();
  } catch (error) {
    next(error);
  }
}

// جلب رتبة العضو
async function getRole(userId) {
  if (userId === process.env.OWNER_USER_ID) {
    return 'owner';
  }

  const { data, error } = await supabase
    .from('lz_user_roles')
    .select('role')
    .eq('user_id', userId)
    .maybeSingle();

  if (error) throw error;

  return data?.role || 'member';
}

async function requireOwnerOrCoOwner(req, res, next) {
  try {
    const role = await getRole(req.user.id);

    if (!adminRoles.has(role)) {
      return fail(res, 403, 'Not allowed');
    }

    next();
  } catch (error) {
    next(error);
  }
}


function validStreamerUrl(value) {
  try {
    const u = new URL(String(value || ''));
    if (u.protocol !== 'https:') return null;
    const host = u.hostname.toLowerCase();
    const kick = ['kick.com','www.kick.com'].includes(host) && /^\/[a-z0-9_]+\/?$/i.test(u.pathname);
    const tiktok = ['tiktok.com','www.tiktok.com','m.tiktok.com'].includes(host) && /^\/@[a-z0-9._]+\/?$/i.test(u.pathname);
    return kick || tiktok ? u.href : null;
  } catch { return null; }
}

function decodeMeta(value) {
  return String(value || '').replace(/&amp;/g, '&').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/\\u002F/gi, '/').replace(/\\u0026/gi, '&')
    .replace(/\\\//g, '/');
}

app.get('/api/streamer-preview', async (req, res, next) => {
  try {
    const profileUrl = validStreamerUrl(req.query.url);
    if (!profileUrl) return fail(res, 400, 'ضع رابط حساب Kick أو TikTok صحيحاً');
    const response = await fetch(profileUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml'
      },
      signal: AbortSignal.timeout(10000),
      redirect: 'follow'
    });
    const finalHost = new URL(response.url || profileUrl).hostname.toLowerCase();
    const samePlatform = profileUrl.includes('kick.com')
      ? ['kick.com','www.kick.com'].includes(finalHost)
      : ['tiktok.com','www.tiktok.com','m.tiktok.com'].includes(finalHost);
    if (!samePlatform) return fail(res, 502, 'رابط الحساب أعاد توجيهاً غير مسموح');
    if (!response.ok) return fail(res, 502, 'تعذر جلب صفحة الحساب من المنصة');
    const html = (await response.text()).slice(0, 3_000_000);
    const tags = html.match(/<meta\b[^>]*>/gi) || [];
    let image = '';
    let title = '';
    for (const tag of tags) {
      const prop = (tag.match(/(?:property|name)=["']([^"']+)["']/i) || [])[1]?.toLowerCase();
      const content = (tag.match(/content=["']([^"']+)["']/i) || [])[1] || '';
      if (!image && ['og:image','twitter:image','og:image:secure_url'].includes(prop)) image = decodeMeta(content);
      if (!title && ['og:title','twitter:title'].includes(prop)) title = decodeMeta(content);
    }
    // TikTok embeds its profile avatar in page JSON on many profile responses.
    if (!image && profileUrl.includes('tiktok.com')) {
      const match = html.match(/"avatar(?:Larger|Medium|Thumb)"\s*:\s*"([^"]+)"/i);
      if (match) image = decodeMeta(match[1]);
    }
    if (image && !/^https:\/\//i.test(image)) image = '';
    res.json({
      platform: profileUrl.includes('kick.com') ? 'kick' : 'tiktok',
      name: title.replace(/\s*[|·-]\s*(TikTok|Kick).*$/i, '').slice(0, 80),
      image
    });
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') return fail(res, 504, 'انتهت مهلة جلب صورة الحساب');
    next(error);
  }
});

// Shared site content: public read, Owner/Co Owner write. Never trust browser roles.
const EMPTY_SITE_CONTENT = { designers: [], works: [], awards: [], giveaways: [], winners: [], videoLinks: {}, streamers: [] };
app.get('/api/site-content', async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (error) throw error;
    res.json(data?.content || EMPTY_SITE_CONTENT);
  } catch (error) { next(error); }
});
app.put('/api/site-content', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const input = req.body?.content;
    if (!input || typeof input !== 'object' || Array.isArray(input)) return fail(res, 400, 'Invalid content');
    const content = {
      designers: Array.isArray(input.designers) ? input.designers : [],
      works: Array.isArray(input.works) ? input.works : [],
      awards: Array.isArray(input.awards) ? input.awards : [],
      giveaways: Array.isArray(input.giveaways) ? input.giveaways : [],
      winners: Array.isArray(input.winners) ? input.winners : [],
      videoLinks: input.videoLinks && typeof input.videoLinks === 'object' && !Array.isArray(input.videoLinks) ? input.videoLinks : {},
      streamers: Array.isArray(input.streamers) ? input.streamers.slice(0, 100).map(item => ({
        id: String(item?.id || '').slice(0, 80),
        platform: ['kick','tiktok'].includes(item?.platform) ? item.platform : '',
        name: String(item?.name || '').slice(0, 80),
        url: validStreamerUrl(item?.url) || '',
        image: validUrl(item?.image) || '',
        addedAt: String(item?.addedAt || '').slice(0, 40)
      })).filter(item => item.id && item.platform && item.name && item.url) : []
    };
    if (JSON.stringify(content).length > 4500000) return fail(res, 413, 'Content is too large');
    const { error } = await supabase.from('lz_site_content').upsert({ id: 1, content, updated_at: new Date().toISOString() }, { onConflict: 'id' });
    if (error) throw error;
    res.json({ ok: true, content });
  } catch (error) { next(error); }
});

// Full member picker for authorized administrators (includes profiles not yet onboarded).
app.get('/api/admin/members', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('profiles').select('id,discord_username,display_name,created_at').order('created_at', { ascending: false }).limit(5000);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});

// Achievements catalog and member badges.
const BADGE_CATALOG = [
  { key: 'first_design', name: 'أول إبداع', icon: '🎨', description: 'تكريم أول مشاركة إبداعية' },
  { key: 'designer_star', name: 'نجم التصميم', icon: '⭐', description: 'مصمم مميز في المجتمع' },
  { key: 'video_creator', name: 'صانع المحتوى', icon: '🎬', description: 'صانع فيديوهات مبدع' },
  { key: 'community_hero', name: 'بطل المجتمع', icon: '💜', description: 'مساهم نشيط في مجتمع LZ' },
  { key: 'giveaway_winner', name: 'فائز Giveaway', icon: '🏆', description: 'فاز في إحدى مسابقات LZ' },
  { key: 'staff_choice', name: 'اختيار الإدارة', icon: '👑', description: 'شارة خاصة من إدارة LZ' }
];
app.get('/api/badges', (_req, res) => res.json(BADGE_CATALOG));
app.get('/api/me/badges', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_user_badges')
      .select('id,badge_key,note,created_at').eq('user_id', req.user.id)
      .order('created_at', { ascending: false });
    if (error) throw error;
    res.json((data || []).map(row => ({ ...row, badge: BADGE_CATALOG.find(b => b.key === row.badge_key) || null })));
  } catch (error) { next(error); }
});
app.post('/api/badges/grant', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const userId = String(req.body?.user_id || '');
    const badgeKey = String(req.body?.badge_key || '');
    const note = String(req.body?.note || '').trim().slice(0, 240);
    if (!uuid(userId) || !BADGE_CATALOG.some(b => b.key === badgeKey)) return fail(res, 400, 'عضو أو شارة غير صالحة');
    const { data: profile, error: profileError } = await supabase.from('profiles').select('id').eq('id', userId).maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return fail(res, 404, 'العضو غير موجود');
    const { data, error } = await supabase.from('lz_user_badges').upsert({
      user_id: userId, badge_key: badgeKey, note, awarded_by: req.user.id
    }, { onConflict: 'user_id,badge_key' }).select('id,badge_key,note,created_at').single();
    if (error) throw error;
    const badge = BADGE_CATALOG.find(b => b.key === badgeKey);
    await supabase.from('lz_notifications').insert({ user_id: userId, title: 'حصلت على شارة جديدة!', body: `${badge.icon} ${badge.name}${note ? ' — ' + note : ''}`, kind: 'badge', link: '#badges' });
    res.json({ ok: true, ...data, badge });
  } catch (error) { next(error); }
});

// Notifications inbox and admin broadcast.
app.get('/api/notifications', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_notifications')
      .select('id,title,body,kind,link,read_at,created_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.patch('/api/notifications/:id/read', auth, async (req, res, next) => {
  try {
    if (!/^[1-9]\d*$/.test(req.params.id)) return fail(res, 400, 'معرف إشعار غير صالح');
    const { error } = await supabase.from('lz_notifications').update({ read_at: new Date().toISOString() })
      .eq('id', req.params.id).eq('user_id', req.user.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.post('/api/notifications/broadcast', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const title = String(req.body?.title || '').trim().slice(0, 100);
    const body = String(req.body?.body || '').trim().slice(0, 500);
    const link = validUrl(req.body?.link) || (String(req.body?.link || '').startsWith('#') ? String(req.body.link).slice(0, 100) : null);
    if (!title || !body) return fail(res, 400, 'العنوان والرسالة مطلوبان');
    const { data: profiles, error: profileError } = await supabase.from('profiles').select('id').limit(5000);
    if (profileError) throw profileError;
    const rows = (profiles || []).map(p => ({ user_id: p.id, title, body, kind: 'announcement', link }));
    if (!rows.length) return res.json({ ok: true, sent: 0 });
    const { error } = await supabase.from('lz_notifications').insert(rows);
    if (error) throw error;
    res.json({ ok: true, sent: rows.length });
  } catch (error) { next(error); }
});

// Giveaway participation and secure random draw.
app.get('/api/giveaways/stats', async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_giveaway_entries').select('giveaway_id').limit(20000);
    if (error) throw error;
    const counts = {};
    for (const row of data || []) counts[row.giveaway_id] = (counts[row.giveaway_id] || 0) + 1;
    res.json(counts);
  } catch (error) { next(error); }
});
app.get('/api/giveaways/mine', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_giveaway_entries').select('giveaway_id').eq('user_id', req.user.id).limit(500);
    if (error) throw error;
    res.json((data || []).map(row => row.giveaway_id));
  } catch (error) { next(error); }
});
app.post('/api/giveaways/:id/enter', auth, async (req, res, next) => {
  try {
    const giveawayId = String(req.params.id || '').slice(0, 80);
    const { data: site, error: siteError } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (siteError) throw siteError;
    const giveaway = (site?.content?.giveaways || []).find(g => String(g.id) === giveawayId);
    if (!giveaway) return fail(res, 404, 'المسابقة غير موجودة');
    if (giveaway.end && giveaway.end < new Date().toISOString().slice(0, 10)) return fail(res, 400, 'انتهى وقت المشاركة');
    if (giveaway.winner) return fail(res, 400, 'تم اختيار الفائز لهذه المسابقة');
    const { error } = await supabase.from('lz_giveaway_entries').insert({ giveaway_id: giveawayId, user_id: req.user.id });
    if (error?.code === '23505') return fail(res, 409, 'أنت مشارك بالفعل في هذه المسابقة');
    if (error) throw error;
    res.status(201).json({ ok: true, message: 'تم تسجيل مشاركتك بنجاح' });
  } catch (error) { next(error); }
});
app.post('/api/giveaways/:id/draw', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const giveawayId = String(req.params.id || '').slice(0, 80);
    const { data: site, error: siteError } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (siteError) throw siteError;
    const content = site?.content || EMPTY_SITE_CONTENT;
    const giveaway = (content.giveaways || []).find(g => String(g.id) === giveawayId);
    if (!giveaway) return fail(res, 404, 'المسابقة غير موجودة');
    if (giveaway.winner) return fail(res, 409, 'تم سحب الفائز مسبقاً');
    const { data: entries, error: entriesError } = await supabase.from('lz_giveaway_entries').select('user_id').eq('giveaway_id', giveawayId).limit(10000);
    if (entriesError) throw entriesError;
    if (!entries?.length) return fail(res, 400, 'لا يوجد مشاركون في هذه المسابقة');
    const chosen = entries[crypto.randomInt(entries.length)];
    const { data: profile, error: profileError } = await supabase.from('profiles').select('discord_username').eq('id', chosen.user_id).maybeSingle();
    if (profileError) throw profileError;
    giveaway.winner = { user_id: chosen.user_id, name: profile?.discord_username || 'LZ Member' };
    giveaway.drawnAt = new Date().toISOString();
    const { error: saveError } = await supabase.from('lz_site_content').upsert({ id: 1, content, updated_at: new Date().toISOString() }, { onConflict: 'id' });
    if (saveError) throw saveError;
    await supabase.from('lz_notifications').insert({ user_id: chosen.user_id, title: 'مبروك! فزت في Giveaway 🎉', body: `أنت الفائز في ${String(giveaway.title || 'مسابقة LZ').slice(0,100)} — الجائزة: ${String(giveaway.prize || '').slice(0,100)}`, kind: 'giveaway', link: '#giveaway' });
    await supabase.from('lz_user_badges').upsert({ user_id: chosen.user_id, badge_key: 'giveaway_winner', note: String(giveaway.title || 'Giveaway').slice(0, 200), awarded_by: req.user.id }, { onConflict: 'user_id,badge_key' });
    res.json({ ok: true, winner: giveaway.winner, entries: entries.length });
  } catch (error) { next(error); }
});

// Community polls. Public results; one authenticated vote per member.
app.get('/api/polls', async (req, res, next) => {
  try {
    const { data: polls, error } = await supabase.from('lz_polls').select('*').order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    const ids = (polls || []).map(p => p.id);
    if (!ids.length) return res.json([]);
    const [{ data: options, error: optionsError }, { data: votes, error: votesError }] = await Promise.all([
      supabase.from('lz_poll_options').select('id,poll_id,option_text,position').in('poll_id', ids).order('position'),
      supabase.from('lz_poll_votes').select('poll_id,option_id,user_id').in('poll_id', ids).limit(50000)
    ]);
    if (optionsError) throw optionsError;
    if (votesError) throw votesError;
    const token = /^Bearer (.+)$/i.exec(req.get('authorization') || '')?.[1];
    let userId = null;
    if (token) {
      const { data: authData } = await supabase.auth.getUser(token);
      userId = authData?.user?.id || null;
    }
    res.json((polls || []).map(poll => {
      const pollVotes = (votes || []).filter(v => v.poll_id === poll.id);
      return { ...poll, options: (options || []).filter(o => o.poll_id === poll.id).map(o => ({ ...o, votes: pollVotes.filter(v => v.option_id === o.id).length })), total_votes: pollVotes.length, my_vote: pollVotes.find(v => v.user_id === userId)?.option_id || null };
    }));
  } catch (error) { next(error); }
});
app.post('/api/polls', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const title = String(req.body?.title || '').trim().slice(0, 120);
    const description = String(req.body?.description || '').trim().slice(0, 400);
    const options = Array.isArray(req.body?.options) ? req.body.options.map(x => String(x || '').trim().slice(0, 80)).filter(Boolean) : [];
    const endsAt = req.body?.ends_at ? new Date(req.body.ends_at) : null;
    if (!title || options.length < 2 || options.length > 8 || new Set(options.map(x => x.toLowerCase())).size !== options.length) return fail(res, 400, 'أدخل عنواناً وخيارين مختلفين على الأقل (حتى 8 خيارات)');
    if (endsAt && Number.isNaN(endsAt.getTime())) return fail(res, 400, 'تاريخ نهاية التصويت غير صالح');
    const id = crypto.randomUUID();
    const { error: pollError } = await supabase.from('lz_polls').insert({ id, title, description, ends_at: endsAt?.toISOString() || null, created_by: req.user.id });
    if (pollError) throw pollError;
    const { error: optionError } = await supabase.from('lz_poll_options').insert(options.map((option_text, position) => ({ poll_id: id, option_text, position })));
    if (optionError) { await supabase.from('lz_polls').delete().eq('id', id); throw optionError; }
    const { data: profiles, error: profileError } = await supabase.from('profiles').select('id').limit(5000);
    if (profileError) throw profileError;
    if (profiles?.length) await supabase.from('lz_notifications').insert(profiles.map(x => ({ user_id:x.id, title:'تصويت جديد في LZ EDITORS', body:title, kind:'poll', link:'#polls' })));
    res.status(201).json({ ok: true, id });
  } catch (error) { next(error); }
});
app.post('/api/polls/:id/vote', auth, async (req, res, next) => {
  try {
    const pollId = String(req.params.id || '');
    const optionId = Number(req.body?.option_id);
    if (!uuid(pollId) || !Number.isSafeInteger(optionId) || optionId < 1) return fail(res, 400, 'اختيار التصويت غير صالح');
    const { data: poll, error: pollError } = await supabase.from('lz_polls').select('id,ends_at,is_closed').eq('id', pollId).maybeSingle();
    if (pollError) throw pollError;
    if (!poll) return fail(res, 404, 'التصويت غير موجود');
    if (poll.is_closed || (poll.ends_at && new Date(poll.ends_at).getTime() <= Date.now())) return fail(res, 400, 'انتهى التصويت');
    const { data: option, error: optionError } = await supabase.from('lz_poll_options').select('id').eq('id', optionId).eq('poll_id', pollId).maybeSingle();
    if (optionError) throw optionError;
    if (!option) return fail(res, 400, 'الخيار لا يتبع هذا التصويت');
    const { error } = await supabase.from('lz_poll_votes').insert({ poll_id:pollId, option_id:optionId, user_id:req.user.id });
    if (error?.code === '23505') return fail(res, 409, 'لقد صوّت بالفعل في هذا التصويت');
    if (error) throw error;
    res.status(201).json({ ok:true });
  } catch (error) { next(error); }
});
app.patch('/api/polls/:id/close', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    if (!uuid(req.params.id)) return fail(res, 400, 'معرف التصويت غير صالح');
    const { error } = await supabase.from('lz_polls').update({ is_closed:true }).eq('id', req.params.id);
    if (error) throw error;
    res.json({ ok:true });
  } catch (error) { next(error); }
});

// فحص السيرفر
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'LZ EDITORS API'
  });
});

// جلب المصممين
app.get('/api/designers', async (_req, res, next) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select(
        'id,discord_id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
      )
      .eq('onboarding_completed', true)
      .limit(200);

    if (error) throw error;

    const profiles = data || [];
    const ids = profiles.map(profile => profile.id);

    let roleMap = new Map();

    if (ids.length) {
      const { data: assigned, error: roleError } = await supabase
        .from('lz_user_roles')
        .select('user_id,role')
        .in('user_id', ids);

      if (roleError) throw roleError;

      roleMap = new Map(
        (assigned || []).map(item => [
          item.user_id,
          item.role
        ])
      );
    }

    let banMap = new Map();
    if (ids.length) {
      const { data: bans, error: banError } = await supabase
        .from('lz_user_bans')
        .select('user_id,reason,expires_at')
        .in('user_id', ids);
      if (banError) throw banError;
      const now = Date.now();
      banMap = new Map((bans || [])
        .filter(b => !b.expires_at || new Date(b.expires_at).getTime() > now)
        .map(b => [b.user_id, b]));
    }

    let badgeMap = new Map();
    if (ids.length) {
      const { data: badgeRows, error: badgeError } = await supabase.from('lz_user_badges')
        .select('user_id,badge_key,note,created_at').in('user_id', ids);
      if (badgeError) throw badgeError;
      badgeMap = new Map();
      for (const row of badgeRows || []) {
        const list = badgeMap.get(row.user_id) || [];
        const badge = BADGE_CATALOG.find(item => item.key === row.badge_key);
        if (badge) list.push({ ...badge, note: row.note, created_at: row.created_at });
        badgeMap.set(row.user_id, list);
      }
    }

    res.json(
      profiles.map(profile => ({
        ...profile,
        role:
          profile.id === process.env.OWNER_USER_ID
            ? 'owner'
            : roleMap.get(profile.id) || 'member',
        badges: badgeMap.get(profile.id) || [],
        banned: banMap.has(profile.id),
        ban_reason: banMap.get(profile.id)?.reason || '',
        ban_expires_at: banMap.get(profile.id)?.expires_at || null
      }))
    );
  } catch (error) {
    next(error);
  }
});

// المستخدم الحالي
app.get('/api/me', auth, async (req, res, next) => {
  try {
    const discordId = discordIdFromUser(req.user);
    if (discordId) {
      const { error: syncError } = await supabase.from('profiles').upsert({
        id: req.user.id, discord_id: discordId
      }, { onConflict: 'id' });
      if (syncError) throw syncError;
    }
    const { data, error } = await supabase
      .from('profiles')
      .select(
        'id,discord_id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
      )
      .eq('id', req.user.id)
      .maybeSingle();

    if (error) throw error;

    res.json({
      user_id: req.user.id,
      profile: data,
      role: await getRole(req.user.id)
    });
  } catch (error) {
    next(error);
  }
});

// تحديث حساب تيك توك
app.put('/api/me/profile', auth, async (req, res, next) => {
  try {
    const tiktok = validUrl(req.body?.tiktok_url);

    if (
      !tiktok ||
      ![
        'tiktok.com',
        'www.tiktok.com',
        'm.tiktok.com'
      ].includes(new URL(tiktok).hostname)
    ) {
      return fail(res, 400, 'Valid TikTok URL required');
    }

    const identity =
      req.user.identities?.find(
        item => item.provider === 'discord'
      )?.identity_data ||
      req.user.user_metadata ||
      {};

    const name = String(
      identity.full_name ||
      identity.name ||
      identity.user_name ||
      identity.preferred_username ||
      'Discord member'
    ).slice(0, 80);

    const avatar = validUrl(identity.avatar_url) || null;

    const { data, error } = await supabase
      .from('profiles')
      .upsert({
        id: req.user.id,
        discord_id: discordIdFromUser(req.user),
        username: name,
        display_name: name,
        discord_username: name,
        discord_avatar_url: avatar,
        tiktok_url: tiktok,
        onboarding_completed: true
      }, {
        onConflict: 'id'
      })
      .select(
        'id,discord_id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
      )
      .single();

    if (error) throw error;

    res.json(data);
  } catch (error) {
    next(error);
  }
});

// جلب رسائل المجتمع
app.get('/api/messages', async (req, res, next) => {
  try {
    const limit = Math.min(
      100,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 50)
    );

    const { data, error } = await supabase
      .from('community_messages')
      .select(
        'id,user_id,author_name,author_avatar,text,created_at'
      )
      .order('created_at', { ascending: false })
      .limit(limit);

    if (error) throw error;

    res.json(data);
  } catch (error) {
    next(error);
  }
});

// إرسال رسالة
app.post('/api/messages', auth, async (req, res, next) => {
  try {
    const message = String(req.body?.text || '').trim();

    if (!message || message.length > 500) {
      return fail(res, 400, 'Message must be 1–500 characters');
    }

    const { data: profile, error: profileError } = await supabase
      .from('profiles')
      .select(
        'discord_username,discord_avatar_url,onboarding_completed'
      )
      .eq('id', req.user.id)
      .maybeSingle();

    if (profileError) throw profileError;

    if (!profile?.onboarding_completed) {
      return fail(res, 403, 'Complete your profile first');
    }

    const { data, error } = await supabase
      .from('community_messages')
      .insert({
        user_id: req.user.id,
        author_name: profile.discord_username,
        author_avatar: profile.discord_avatar_url,
        text: message
      })
      .select(
        'id,user_id,author_name,author_avatar,text,created_at'
      )
      .single();

    if (error) throw error;

    res.status(201).json(data);
  } catch (error) {
    next(error);
  }
});

// حذف رسالة
app.delete('/api/messages/:id', auth, async (req, res, next) => {
  try {
    const messageId = req.params.id;

    if (
      !/^[1-9]\d*$/.test(messageId) ||
      BigInt(messageId) > 9223372036854775807n
    ) {
      return fail(res, 400, 'Invalid message ID');
    }

    const { data: message, error: readError } = await supabase
      .from('community_messages')
      .select('user_id')
      .eq('id', messageId)
      .maybeSingle();

    if (readError) throw readError;

    if (!message) {
      return fail(res, 404, 'Message not found');
    }

    const role = await getRole(req.user.id);

    if (
      message.user_id !== req.user.id &&
      !adminRoles.has(role)
    ) {
      return fail(res, 403, 'Not allowed');
    }

    const { error } = await supabase
      .from('community_messages')
      .delete()
      .eq('id', messageId);

    if (error) throw error;

    res.status(204).end();
  } catch (error) {
    next(error);
  }
});

// قائمة المحظورين النشطين — للإدارة فقط
app.get('/api/bans', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const now = new Date().toISOString();
    const { data, error } = await supabase
      .from('lz_user_bans')
      .select('user_id,reason,expires_at,banned_by,created_at')
      .or(`expires_at.is.null,expires_at.gt.${now}`)
      .order('created_at', { ascending: false })
      .limit(500);
    if (error) throw error;
    const ids = (data || []).map(row => row.user_id);
    let profiles = [];
    if (ids.length) {
      const result = await supabase.from('profiles')
        .select('id,discord_username,discord_avatar_url')
        .in('id', ids);
      if (result.error) throw result.error;
      profiles = result.data || [];
    }
    const profileMap = new Map(profiles.map(profile => [profile.id, profile]));
    res.json((data || []).map(ban => ({ ...ban, profile: profileMap.get(ban.user_id) || null })));
  } catch (error) { next(error); }
});

// حظر مصمم (مؤقت أو دائم) — Owner وCo Owner فقط
app.put('/api/bans/:userId', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const target = req.params.userId;
    const reason = String(req.body?.reason || '').trim().slice(0, 500);
    const expiresAt = req.body?.expires_at ?? null;
    if (!uuid(target)) return fail(res, 400, 'Invalid user ID');
    if (target === process.env.OWNER_USER_ID) return fail(res, 403, 'لا يمكن حظر المالك');
    if (expiresAt !== null && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now())) {
      return fail(res, 400, 'تاريخ انتهاء الحظر غير صالح');
    }
    const requesterRole = await getRole(req.user.id);
    const targetRole = await getRole(target);
    if (['co_owner', 'manager_admin'].includes(targetRole) && requesterRole !== 'owner') {
      return fail(res, 403, 'المالك فقط يمكنه حظر Co Owner أو Manager Admin');
    }
    const { data: profile, error: profileError } = await supabase
      .from('profiles').select('id').eq('id', target).maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return fail(res, 404, 'Designer not found');
    const { error } = await supabase.from('lz_user_bans').upsert({
      user_id: target, reason, expires_at: expiresAt,
      banned_by: req.user.id, created_at: new Date().toISOString()
    }, { onConflict: 'user_id' });
    if (error) throw error;
    res.json({ ok: true, user_id: target, reason, expires_at: expiresAt });
  } catch (error) { next(error); }
});

// إلغاء الحظر
app.delete('/api/bans/:userId', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const target = req.params.userId;
    if (!uuid(target)) return fail(res, 400, 'Invalid user ID');
    const { error } = await supabase.from('lz_user_bans').delete().eq('user_id', target);
    if (error) throw error;
    res.json({ ok: true, user_id: target });
  } catch (error) { next(error); }
});

// تغيير رتب الأعضاء
app.put(
  '/api/roles/:userId',
  auth,
  requireOwnerOrCoOwner,
  async (req, res, next) => {
    try {
      const target = req.params.userId;
      const role = req.body?.role;

      if (!uuid(target) || !roles.includes(role)) {
        return fail(res, 400, 'Invalid user or role');
      }

      if (target === process.env.OWNER_USER_ID || role === 'owner') {
        return fail(res, 403, 'Use the Discord ID Owner assignment endpoint; primary Owner is protected');
      }

      const requesterRole = await getRole(req.user.id);

      if (
        requesterRole !== 'owner' &&
        ['co_owner', 'manager_admin'].includes(role)
      ) {
        return fail(
          res,
          403,
          'Only Owner may assign Co Owner or Manager Admin'
        );
      }

      const existingTargetRole = await getRole(target);
      if (requesterRole !== 'owner' && ['co_owner', 'manager_admin'].includes(existingTargetRole)) {
        return fail(res, 403, 'Only Owner may change this administrator role');
      }

      const { data: profile, error: profileError } = await supabase
        .from('profiles')
        .select('id')
        .eq('id', target)
        .maybeSingle();

      if (profileError) throw profileError;

      if (!profile) {
        return fail(res, 404, 'Designer not found');
      }

      const { error } = await supabase
        .from('lz_user_roles')
        .upsert({
          user_id: target,
          role
        }, {
          onConflict: 'user_id'
        });

      if (error) throw error;

      res.json({
        user_id: target,
        role
      });
    } catch (error) {
      next(error);
    }
  }
);

// تعيين رتبة Owner بواسطة Discord ID — المالك الحالي فقط
app.post('/api/roles/by-discord/:discordId', auth, async (req, res, next) => {
  try {
    if (await getRole(req.user.id) !== 'owner') return fail(res, 403, 'Only Owner can assign Owner');
    const discordId = String(req.params.discordId || '').trim();
    if (!/^\d{17,20}$/.test(discordId)) return fail(res, 400, 'Discord ID غير صالح؛ يجب أن يكون 17 إلى 20 رقماً');
    const { data: profile, error: profileError } = await supabase
      .from('profiles').select('id,discord_id,discord_username')
      .eq('discord_id', discordId).maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return fail(res, 404, 'لم يتم العثور على هذا Discord ID. يجب على العضو تسجيل الدخول للموقع مرة واحدة أولاً.');
    if (profile.id === process.env.OWNER_USER_ID) return fail(res, 409, 'هذا الحساب هو المالك الأساسي بالفعل');
    const { error } = await supabase.from('lz_user_roles').upsert({ user_id: profile.id, role: 'owner' }, { onConflict: 'user_id' });
    if (error) throw error;
    res.json({ ok: true, user_id: profile.id, discord_id: discordId, username: profile.discord_username, role: 'owner' });
  } catch (error) { next(error); }
});

// معالجة الأخطاء
app.use((error, _req, res, _next) => {
  console.error('Backend error:', error);
  const code = error?.code;
  if (code === '42703' || code === 'PGRST204') {
    return res.status(500).json({ error: 'قاعدة البيانات ناقصها عمود أو تحديث. شغّل migration.sql في Supabase SQL Editor ثم أعد تشغيل السيرفر.' });
  }
  if (code === '23505') {
    return res.status(409).json({ error: 'يوجد سجل مكرر. راجع user_id في جداول lz_user_roles و lz_user_bans.' });
  }
  res.status(500).json({ error: 'Server error. Check backend logs.' });
});

const port = Number(process.env.PORT) || 3000;

app.listen(port, () => {
  console.log(`LZ EDITORS API listening on port ${port}`);
});
