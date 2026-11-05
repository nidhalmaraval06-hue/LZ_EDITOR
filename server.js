'use strict';

// LZ EDITORS Backend — Node.js 20+
require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
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
  'designers.html',
  'banned.html'
];

app.get('/', (_req, res) => {
  // الصفحة الرئيسية العامة تفتح تسجيل دخول المصممين مباشرة.
  // لا نستخدم sendFile هنا حتى لا تظهر صفحة دخول لوحة الإدارة للزوار.
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  return res.redirect(302, '/login-designers.html');
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
  res.set('Cache-Control', 'public, max-age=3600');
  res.sendFile(path.join(__dirname, 'logo.png'));
});
// شعار واجهة الحظر — ملف مستقل باسم logo.ban.png
app.get('/logo.ban.png', (_req, res) => {
  res.set('Cache-Control', 'no-store, max-age=0');
  res.type('png').sendFile(path.join(__dirname, 'logo.ban.png'));
});
app.get('/manifest.webmanifest', (_req, res) => {
  res.type('application/manifest+json').sendFile(path.join(__dirname, 'manifest.webmanifest'));
});
app.get('/sw.js', (_req, res) => {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Service-Worker-Allowed', '/').type('application/javascript').sendFile(path.join(__dirname, 'sw.js'));
});

// مسابقات Giveaway تحفظ صورة مضغوطة داخل محتوى الموقع؛ 32kb كانت تمنع حفظها.
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

const roles = ['member', 'owner', 'co_owner', 'manager_admin', 'admin', 'w_edit'];
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


function tiktokConfigReady() {
  return !!(process.env.TIKTOK_CLIENT_KEY && process.env.TIKTOK_CLIENT_SECRET &&
    process.env.TIKTOK_REDIRECT_URI && process.env.TIKTOK_TOKEN_ENCRYPTION_KEY);
}
function tiktokEncryptionKey() {
  const key = Buffer.from(process.env.TIKTOK_TOKEN_ENCRYPTION_KEY || '', 'hex');
  if (key.length !== 32) throw new Error('TIKTOK_TOKEN_ENCRYPTION_KEY must be 64 hexadecimal characters (32 bytes)');
  return key;
}
function encryptTikTokToken(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', tiktokEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return [iv.toString('hex'), cipher.getAuthTag().toString('hex'), encrypted.toString('hex')].join('.');
}
function decryptTikTokToken(value) {
  const [ivHex, tagHex, encryptedHex] = String(value || '').split('.');
  if (!ivHex || !tagHex || !encryptedHex) throw new Error('Stored TikTok token is invalid');
  const decipher = crypto.createDecipheriv('aes-256-gcm', tiktokEncryptionKey(), Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(encryptedHex, 'hex')), decipher.final()]).toString('utf8');
}
function signTikTokState(userId) {
  const payload = Buffer.from(JSON.stringify({ uid: userId, exp: Date.now() + 10 * 60 * 1000, nonce: crypto.randomBytes(12).toString('hex') })).toString('base64url');
  const signature = crypto.createHmac('sha256', tiktokEncryptionKey()).update(payload).digest('base64url');
  return payload + '.' + signature;
}
function verifyTikTokState(state) {
  const [payload, signature] = String(state || '').split('.');
  if (!payload || !signature) return null;
  const expected = crypto.createHmac('sha256', tiktokEncryptionKey()).update(payload).digest();
  let actual; try { actual = Buffer.from(signature, 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return uuid(data.uid) && data.exp > Date.now() ? data : null;
  } catch { return null; }
}
async function exchangeTikTokToken(form) {
  const response = await fetch('https://open.tiktokapis.com/v2/oauth/token/', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(form), signal: AbortSignal.timeout(15000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.error || !result.access_token) throw new Error(result.error_description || result.message || 'TikTok OAuth token exchange failed');
  return result;
}
async function saveTikTokConnection(userId, token) {
  const row = {
    user_id: userId, open_id: String(token.open_id || ''),
    access_token_enc: encryptTikTokToken(token.access_token),
    refresh_token_enc: encryptTikTokToken(token.refresh_token),
    access_expires_at: new Date(Date.now() + Number(token.expires_in || 86400) * 1000).toISOString(),
    refresh_expires_at: new Date(Date.now() + Number(token.refresh_expires_in || 31536000) * 1000).toISOString(),
    scopes: String(token.scope || ''), updated_at: new Date().toISOString()
  };
  const { error } = await supabase.from('lz_tiktok_connections').upsert(row, { onConflict: 'user_id' });
  if (error) throw error;
}
async function getTikTokConnection(userId) {
  const { data, error } = await supabase.from('lz_tiktok_connections').select('*').eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data;
}
async function getValidTikTokToken(connection) {
  if (new Date(connection.access_expires_at).getTime() > Date.now() + 120000) return decryptTikTokToken(connection.access_token_enc);
  if (new Date(connection.refresh_expires_at).getTime() <= Date.now()) throw new Error('TikTok authorization expired; reconnect the account');
  const refreshed = await exchangeTikTokToken({
    client_key: process.env.TIKTOK_CLIENT_KEY,
    client_secret: process.env.TIKTOK_CLIENT_SECRET,
    grant_type: 'refresh_token',
    refresh_token: decryptTikTokToken(connection.refresh_token_enc)
  });
  await saveTikTokConnection(connection.user_id, refreshed);
  return refreshed.access_token;
}
async function queryTikTokVideos(accessToken, videoIds) {
  const response = await fetch('https://open.tiktokapis.com/v2/video/query/?fields=id,like_count', {
    method: 'POST', headers: { Authorization: 'Bearer ' + accessToken, 'Content-Type': 'application/json' },
    body: JSON.stringify({ filters: { video_ids: videoIds } }), signal: AbortSignal.timeout(15000)
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.error?.code && result.error.code !== 'ok') throw new Error(result.error?.message || 'TikTok video query failed');
  return result.data?.videos || [];
}
let tikTokLikesSyncRunning = false;
async function syncTikTokContestLikes() {
  if (!tiktokConfigReady() || tikTokLikesSyncRunning) return;
  tikTokLikesSyncRunning = true;
  try {
    const { data: contentRow } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    const activeIds = new Set((contentRow?.content?.giveaways || []).filter(g => g.type === 'tiktok_contest' && (!g.end || g.end >= new Date().toISOString().slice(0,10))).map(g => String(g.id)));
    if (!activeIds.size) return;
    const { data: entries, error } = await supabase.from('lz_contest_entries').select('id,user_id,contest_id,video_url,baseline_likes_count').in('contest_id', [...activeIds]).limit(1000);
    if (error) throw error;
    const grouped = new Map();
    for (const entry of entries || []) { const arr = grouped.get(entry.user_id) || []; arr.push(entry); grouped.set(entry.user_id, arr); }
    for (const [userId, userEntries] of grouped) {
      try {
        const connection = await getTikTokConnection(userId); if (!connection) continue;
        const token = await getValidTikTokToken(connection);
        for (let i = 0; i < userEntries.length; i += 20) {
          const batch = userEntries.slice(i, i + 20).map(entry => ({ entry, id: (entry.video_url.match(/\/video\/(\d+)/) || [])[1] })).filter(item => item.id);
          if (!batch.length) continue;
          const videos = await queryTikTokVideos(token, batch.map(item => item.id));
          const byId = new Map(videos.map(video => [String(video.id), video]));
          for (const item of batch) {
            const video = byId.get(item.id);
            if (!video || !Number.isSafeInteger(Number(video.like_count))) continue;
            const observed = Number(video.like_count);
            await supabase.from('lz_contest_entries').update({ likes_count: Math.max(0, observed - Number(item.entry.baseline_likes_count || 0)), last_observed_likes_count: observed, likes_updated_at: new Date().toISOString(), likes_source: 'tiktok_api' }).eq('id', item.entry.id);
          }
        }
      } catch (userError) { console.warn('TikTok like sync skipped for one participant:', userError.message); }
    }
  } catch (error) { console.error('TikTok likes sync:', error.message); }
  finally { tikTokLikesSyncRunning = false; }
}

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

async function requireOnboarding(req, res, next) {
  try {
    const { data, error } = await supabase.from('profiles').select('onboarding_completed').eq('id', req.user.id).maybeSingle();
    if (error) throw error;
    if (!data?.onboarding_completed) return fail(res, 403, 'أكمل تسجيل ملفك الشخصي أولاً');
    next();
  } catch (error) { next(error); }
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

// Live status monitoring (Kick official API + TikTok unofficial connector).
const streamerLiveCache = { expiresAt: 0, value: null, pending: null };
let kickAccessToken = null;
let kickTokenExpiresAt = 0;
let tiktokConnectorModule = null;

function streamerHandle(streamer) {
  try {
    const u = new URL(streamer.url);
    if (streamer.platform === 'kick') return u.pathname.split('/').filter(Boolean)[0] || '';
    return (u.pathname.match(/^\/@([^/]+)/)?.[1] || '').replace(/^@/, '');
  } catch { return ''; }
}

async function getKickToken() {
  if (kickAccessToken && kickTokenExpiresAt > Date.now() + 60000) return kickAccessToken;
  const clientId = process.env.KICK_CLIENT_ID;
  const clientSecret = process.env.KICK_CLIENT_SECRET;
  if (!clientId || !clientSecret) return null;
  const response = await fetch('https://id.kick.com/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }),
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error(`Kick token request failed (${response.status})`);
  const body = await response.json();
  if (!body.access_token) throw new Error('Kick did not return an access token');
  kickAccessToken = body.access_token;
  kickTokenExpiresAt = Date.now() + Number(body.expires_in || 3600) * 1000;
  return kickAccessToken;
}

async function getKickLiveInfo(handle) {
  const token = await getKickToken();
  if (!token) return { isLive: null, viewerCount: null };
  const headers = {
    Authorization: `Bearer ${token}`,
    'Client-Id': process.env.KICK_CLIENT_ID
  };

  const channelUrl = new URL('https://api.kick.com/public/v1/channels');
  channelUrl.searchParams.set('slug', String(handle).toLowerCase());
  const channelResponse = await fetch(channelUrl, { headers, signal: AbortSignal.timeout(10000) });
  if (!channelResponse.ok) throw new Error(`Kick channels API failed (${channelResponse.status})`);
  const channelBody = await channelResponse.json();
  const channel = (channelBody.data || [])[0];
  const broadcasterUserId = channel?.broadcaster_user_id;
  if (!broadcasterUserId) return { isLive: false, viewerCount: null };

  // The channel payload includes stream.is_live and stream.viewer_count.
  if (channel.stream && typeof channel.stream.is_live === 'boolean') {
    return {
      isLive: channel.stream.is_live,
      viewerCount: channel.stream.is_live && Number.isFinite(Number(channel.stream.viewer_count))
        ? Number(channel.stream.viewer_count) : null
    };
  }

  const liveUrl = new URL('https://api.kick.com/public/v1/users/livestreams');
  liveUrl.searchParams.set('user_id', String(broadcasterUserId));
  const liveResponse = await fetch(liveUrl, { headers, signal: AbortSignal.timeout(10000) });
  if (!liveResponse.ok) throw new Error(`Kick livestream API failed (${liveResponse.status})`);
  const liveBody = await liveResponse.json();
  const live = Array.isArray(liveBody.data) ? liveBody.data[0] : null;
  return {
    isLive: Boolean(live),
    viewerCount: live && Number.isFinite(Number(live.viewer_count)) ? Number(live.viewer_count) : null
  };
}

async function getTikTokLiveInfo(handle) {
  if (!handle) return { isLive: false, viewerCount: null };
  if (!tiktokConnectorModule) tiktokConnectorModule = await import('tiktok-live-connector');
  const Client = tiktokConnectorModule.TikTokLiveConnection || tiktokConnectorModule.default?.TikTokLiveConnection;
  if (typeof Client !== 'function') throw new Error('TikTok LIVE connector v2 is unavailable; check npm install');
  const connection = new Client(String(handle).replace(/^@/, ''), {
    processInitialData: false,
    fetchRoomInfoOnConnect: false,
    enableExtendedGiftInfo: false
  });
  try {
    if (typeof connection.fetchIsLive !== 'function') throw new Error('TikTok connector v2 does not expose fetchIsLive()');
    const isLive = Boolean(await connection.fetchIsLive());
    if (!isLive) return { isLive: false, viewerCount: null };
    // Room metadata exposes the current room user_count when TikTok returns it.
    if (typeof connection.fetchRoomInfo === 'function') {
      const info = await connection.fetchRoomInfo();
      const data = info?.data || info;
      const count = data?.stats?.user_count ?? data?.user_count ?? data?.room?.user_count;
      return { isLive: true, viewerCount: Number.isFinite(Number(count)) ? Number(count) : null };
    }
    return { isLive: true, viewerCount: null };
  } finally {
    if (typeof connection.disconnect === 'function') {
      try { await connection.disconnect(); } catch {}
    }
  }
}

async function refreshStreamerLiveStatuses() {
  if (streamerLiveCache.pending) return streamerLiveCache.pending;
  streamerLiveCache.pending = (async () => {
    const { data, error } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (error) throw error;
    const streamers = Array.isArray(data?.content?.streamers) ? data.content.streamers : [];
    const queue = streamers.slice(0, 100);
    const statuses = new Array(queue.length);
    let cursor = 0;
    const worker = async () => {
      while (cursor < queue.length) {
        const index = cursor++;
        const streamer = queue[index];
        const handle = streamerHandle(streamer);
        if (!handle || !['kick', 'tiktok'].includes(streamer.platform)) {
          statuses[index] = { id: streamer.id, platform: streamer.platform || null, handle: handle || null, isLive: null, viewerCount: null };
          continue;
        }
        try {
          const liveInfo = streamer.platform === 'kick' ? await getKickLiveInfo(handle) : await getTikTokLiveInfo(handle);
          statuses[index] = { id: String(streamer.id), platform: streamer.platform, handle: String(handle).toLowerCase(), isLive: liveInfo.isLive === true, viewerCount: liveInfo.viewerCount, checkedAt: new Date().toISOString() };
        } catch (error) {
          console.warn(`LIVE status check failed for ${streamer.platform} streamer ${handle}:`, error.message);
          statuses[index] = { id: String(streamer.id), platform: streamer.platform, handle: String(handle).toLowerCase(), isLive: null, viewerCount: null, checkedAt: new Date().toISOString() };
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
    streamerLiveCache.value = { statuses, checkedAt: new Date().toISOString() };
    streamerLiveCache.expiresAt = Date.now() + 20 * 1000;
    return streamerLiveCache.value;
  })();
  try { return await streamerLiveCache.pending; }
  finally { streamerLiveCache.pending = null; }
}

app.get('/api/streamers/live', async (_req, res, next) => {
  try {
    const result = streamerLiveCache.value && streamerLiveCache.expiresAt > Date.now()
      ? streamerLiveCache.value
      : await refreshStreamerLiveStatuses();
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate').json(result);
  } catch (error) { next(error); }
});

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
    let banner = '';
    let title = '';
    for (const tag of tags) {
      const prop = (tag.match(/(?:property|name)=["']([^"']+)["']/i) || [])[1]?.toLowerCase();
      const content = (tag.match(/content=["']([^"']+)["']/i) || [])[1] || '';
      if (!image && ['og:image','twitter:image','og:image:secure_url'].includes(prop)) image = decodeMeta(content);
      if (!title && ['og:title','twitter:title'].includes(prop)) title = decodeMeta(content);
      if (!banner && /(?:banner|cover).*(?:image|url)|(?:image|url).*(?:banner|cover)/i.test(prop || '')) banner = decodeMeta(content);
    }

    // Kick's public channel API exposes the channel banner independently of its avatar.
    if (profileUrl.includes('kick.com')) {
      try {
        const slug = new URL(profileUrl).pathname.split('/').filter(Boolean)[0];
        const token = await getKickToken();
        if (token && slug) {
          const apiUrl = new URL('https://api.kick.com/public/v1/channels');
          apiUrl.searchParams.set('slug', slug.toLowerCase());
          const apiResponse = await fetch(apiUrl, {
            headers: { Authorization: `Bearer ${token}`, 'Client-Id': process.env.KICK_CLIENT_ID },
            signal: AbortSignal.timeout(9000)
          });
          if (apiResponse.ok) {
            const apiBody = await apiResponse.json();
            const channel = (apiBody.data || [])[0] || {};
            banner = channel.banner_picture || channel.banner || banner;
            title = title || channel.slug || slug;
          }
        }
      } catch (error) { console.warn('Kick banner lookup:', error.message); }
    }

    // TikTok profile pages sometimes embed cover/banner URLs in their hydration JSON.
    // Its official Display API does not expose a profile banner, so use an embedded cover only when present.
    if (profileUrl.includes('tiktok.com')) {
      const jsonBlocks = [...html.matchAll(/<script[^>]+id=["'](?:__UNIVERSAL_DATA_FOR_REHYDRATION__|SIGI_STATE)["'][^>]*>([\s\S]*?)<\/script>/gi)];
      for (const block of jsonBlocks) {
        try {
          const parsed = JSON.parse(block[1]);
          const scan = (node, depth = 0) => {
            if (!node || typeof node !== 'object' || depth > 12 || banner) return;
            for (const [key, value] of Object.entries(node)) {
              if (/(banner|cover)/i.test(key)) {
                if (typeof value === 'string' && /^https:\/\//i.test(value)) { banner = decodeMeta(value); return; }
                if (value && typeof value === 'object') {
                  const candidate = value.url_list?.[0] || value.urlList?.[0] || value.url || value.uri;
                  if (typeof candidate === 'string' && /^https:\/\//i.test(candidate)) { banner = decodeMeta(candidate); return; }
                }
              }
              if (value && typeof value === 'object') scan(value, depth + 1);
              if (banner) return;
            }
          };
          scan(parsed);
        } catch {}
        if (banner) break;
      }
      if (!image) {
        const match = html.match(/"avatar(?:Larger|Medium|Thumb)"\s*:\s*"([^"]+)"/i);
        if (match) image = decodeMeta(match[1]);
      }
    }
    if (image && !/^https:\/\//i.test(image)) image = '';
    if (banner && !/^https:\/\//i.test(banner)) banner = '';
    res.json({
      platform: profileUrl.includes('kick.com') ? 'kick' : 'tiktok',
      name: title.replace(/\s*[|·-]\s*(TikTok|Kick).*$/i, '').slice(0, 80),
      image,
      banner
    });
  } catch (error) {
    if (error.name === 'TimeoutError' || error.name === 'AbortError') return fail(res, 504, 'انتهت مهلة جلب صورة الحساب');
    next(error);
  }
});

// TikTok OAuth: each participant authorizes their own account so the API can read their own video metrics.
app.get('/api/community/tiktok/connect', auth, (req, res, next) => {
  try {
    if (!tiktokConfigReady()) return fail(res, 503, 'ربط TikTok لم يتم إعداده بعد. أضف مفاتيح تطبيق TikTok في Render.');
    const redirect = new URL(process.env.TIKTOK_REDIRECT_URI);
    if (redirect.protocol !== 'https:') return fail(res, 500, 'TIKTOK_REDIRECT_URI must use HTTPS');
    const url = new URL('https://www.tiktok.com/v2/auth/authorize/');
    url.searchParams.set('client_key', process.env.TIKTOK_CLIENT_KEY);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'user.info.basic,video.list');
    url.searchParams.set('redirect_uri', redirect.href);
    url.searchParams.set('state', signTikTokState(req.user.id));
    res.json({ auth_url: url.href });
  } catch (error) { next(error); }
});
app.get('/api/tiktok/callback', async (req, res) => {
  const frontend = process.env.FRONTEND_ORIGIN.split(',')[0].trim().replace(/\/+$/, '');
  try {
    if (req.query.error) throw new Error(String(req.query.error_description || req.query.error));
    if (!tiktokConfigReady()) throw new Error('TikTok app credentials are not configured');
    const state = verifyTikTokState(req.query.state);
    if (!state || !req.query.code) throw new Error('TikTok authorization state is invalid or expired');
    const token = await exchangeTikTokToken({
      client_key: process.env.TIKTOK_CLIENT_KEY,
      client_secret: process.env.TIKTOK_CLIENT_SECRET,
      code: String(req.query.code),
      grant_type: 'authorization_code',
    });
    if (!String(token.scope || '').split(',').includes('video.list')) throw new Error('TikTok did not grant video.list permission');
    await saveTikTokConnection(state.uid, token);
    res.redirect(frontend + '/designers.html?tiktok=connected#giveaway');
  } catch (error) {
    console.error('TikTok callback:', error.message);
    res.redirect(frontend + '/designers.html?tiktok=error#giveaway');
  }
});
app.get('/api/community/tiktok/status', auth, async (req, res, next) => {
  try {
    const connection = await getTikTokConnection(req.user.id);
    res.json({ connected: !!connection, expires_at: connection?.access_expires_at || null });
  } catch (error) { next(error); }
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
    const { data: previousRow, error: previousError } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (previousError) throw previousError;
    const previous = previousRow?.content || EMPTY_SITE_CONTENT;
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
        bannerUrl: validUrl(item?.bannerUrl || item?.banner_url || item?.banner) || '',
        addedAt: String(item?.addedAt || '').slice(0, 40)
      })).filter(item => item.id && item.platform && item.name && item.url) : []
    };
    if (JSON.stringify(content).length > 4500000) return fail(res, 413, 'Content is too large');

    const currentGiveawayIds = new Set(content.giveaways.map(item => String(item?.id || '')).filter(Boolean));
    const removedGiveaways = (Array.isArray(previous.giveaways) ? previous.giveaways : []).filter(item => item?.id && !currentGiveawayIds.has(String(item.id)));

    // دالة SQL تنفذ تحديث JSONB وحذف سجلات Giveaway التابعة في معاملة واحدة.
    const { error } = await supabase.rpc('lz_save_site_content', { p_content: content });
    if (error) throw error;

    // عند حذف Giveaway من الموقع تكون مشاركاته ونقاط TikTok وسجلات السحب قد حُذفت ذرياً.
    for (const giveaway of removedGiveaways) {
    }

    const collections = ['designers','works','awards','winners','streamers'];
    for (const collection of collections) {
      const keep = new Set((content[collection] || []).map(item => String(item?.id || '')).filter(Boolean));
      const removed = (Array.isArray(previous[collection]) ? previous[collection] : []).filter(item => item?.id && !keep.has(String(item.id)));
      for (const item of removed) {
        if (collection === 'streamers') await writeAudit(req, 'delete', 'streamer', item.id, { name: item.name || '', platform: item.platform || '' });
        else await writeAudit(req, 'delete', collection.slice(0, -1), item.id, { name: item.name || item.designerName || item.title || '' });
      }
      const previousIds = new Set((Array.isArray(previous[collection]) ? previous[collection] : []).map(item => String(item?.id || '')).filter(Boolean));
      for (const item of (content[collection] || []).filter(item => item?.id && !previousIds.has(String(item.id)))) {
        const entityType = collection === 'streamers' ? 'streamer' : collection.slice(0, -1);
      }
    }
    res.json({ ok: true, content, deleted_giveaways: removedGiveaways.length });
  } catch (error) { next(error); }
});

// فحص السيرفر
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'LZ EDITORS API'
  });
});

// قائمة أعضاء الإدارة لاختيار أي عضو حتى لو لم يكمل ملف المصمم بعد.
app.get('/api/admin/users', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('profiles')
      .select('id,discord_username,discord_avatar_url,onboarding_completed')
      .order('discord_username', { ascending: true }).limit(1000);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
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

    res.json(
      profiles.map(profile => ({
        ...profile,
        role:
          profile.id === process.env.OWNER_USER_ID
            ? 'owner'
            : roleMap.get(profile.id) || 'member',
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
      role: await getRole(req.user.id),
      is_primary_owner: req.user.id === process.env.OWNER_USER_ID
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
    try {
      const { data: firstBadge } = await supabase.from('lz_badges').select('id,code,name,icon').eq('code', 'first_steps').maybeSingle();
      if (firstBadge) {
        const { error: awardError } = await supabase.from('lz_user_badges').upsert({ user_id: req.user.id, badge_id: firstBadge.id, badge_key: firstBadge.code }, { onConflict: 'user_id,badge_id' });
        if (awardError) throw awardError;
        const { data: existingNotice } = await supabase.from('lz_notifications').select('id').eq('user_id', req.user.id).eq('type', 'welcome_badge').limit(1);
        if (!existingNotice?.length) await supabase.from('lz_notifications').insert({ user_id: req.user.id, title: 'أهلاً بك في LZ EDITORS!', body: `${firstBadge.icon} حصلت على شارة أول خطوة.`, type: 'welcome_badge' });
      }
    } catch (badgeError) { console.error('First badge award skipped:', badgeError); }
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

      // The primary Owner configured in OWNER_USER_ID is immutable.
      if (target === process.env.OWNER_USER_ID) {
        return fail(res, 403, 'لا يمكن تغيير رتبة المالك الأساسي المحدد في إعدادات السيرفر');
      }

      const requesterRole = await getRole(req.user.id);
      const isPrimaryOwner = req.user.id === process.env.OWNER_USER_ID;
      const isOwnerRole = (await getRole(target)) === 'owner';
      // رتبة Owner محجوزة للمالك الأساسي فقط: لا يستطيع أي Owner مُعيّن منحها أو نزعها أو تعديلها.
      if ((role === 'owner' || isOwnerRole) && !isPrimaryOwner) {
        return fail(res, 403, 'فقط المالك الأساسي يستطيع منح رتبة Owner أو سحبها أو تعديلها');
      }

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
      if (requesterRole !== 'owner' && ['owner', 'co_owner', 'manager_admin'].includes(existingTargetRole)) {
        return fail(res, 403, 'Only primary Owner may change this administrator role');
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

// Community features: badges, notifications, polls, giveaway entries and TikTok contests.
async function notifyUser(userId, title, body, type = 'general') {
  if (!uuid(userId)) return;
  const { error } = await supabase.from('lz_notifications').insert({
    user_id: userId, title: String(title || '').slice(0,120),
    body: String(body || '').slice(0,500), type: String(type || 'general').slice(0,40)
  });
  if (error) throw error;
}

app.get('/api/community/notifications', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_notifications')
      .select('id,title,body,type,read_at,created_at')
      .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(60);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.patch('/api/community/notifications/:id/read', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_notifications')
      .update({ read_at: new Date().toISOString() }).eq('id', req.params.id)
      .eq('user_id', req.user.id).select('id').maybeSingle();
    if (error) throw error;
    if (!data) return fail(res, 404, 'Notification not found');
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.get('/api/community/badges', async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_badges').select('id,code,name,description,icon').eq('active', true).order('id');
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.get('/api/community/badges/earned', async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_user_badges')
      .select('id,user_id,badge_id,created_at,badge:lz_badges(id,code,name,icon,description)')
      .order('created_at', { ascending: false }).limit(2000);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.get('/api/community/me/badges', auth, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_user_badges')
      .select('created_at,badge:lz_badges(id,code,name,description,icon)')
      .eq('user_id', req.user.id).order('created_at', { ascending: false });
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.post('/api/community/badges/award', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const target = String(req.body?.user_id || '');
    const name = String(req.body?.name || '').trim().slice(0,80);
    const description = String(req.body?.description || '').trim().slice(0,240);
    const icon = String(req.body?.icon || '🏅').slice(0,12);
    if (!uuid(target) || !name) return fail(res, 400, 'اختر عضواً واكتب اسم الشارة');
    const code = 'custom_' + Buffer.from(name.toLowerCase(), 'utf8').toString('hex').slice(0,48);

    // Avoid PostgREST ON CONFLICT inference problems on older databases that
    // only have a partial unique index for lz_badges.code.
    let { data: badge, error: lookupError } = await supabase.from('lz_badges')
      .select('id,name,icon,description').eq('code', code).maybeSingle();
    if (lookupError) throw lookupError;
    if (badge) {
      const { data: updatedBadge, error: updateBadgeError } = await supabase.from('lz_badges')
        .update({ name, description, icon, active: true }).eq('id', badge.id)
        .select('id,name,icon,description').single();
      if (updateBadgeError) throw updateBadgeError;
      badge = updatedBadge;
    } else {
      const { data: insertedBadge, error: insertBadgeError } = await supabase.from('lz_badges')
        .insert({ code, name, description, icon, active: true })
        .select('id,name,icon,description').single();
      if (insertBadgeError) throw insertBadgeError;
      badge = insertedBadge;
    }

    // Award idempotently. If an older schema lacks the expected unique index,
    // fall back to an existence check followed by insert.
    const { data: existingAward, error: awardLookupError } = await supabase.from('lz_user_badges')
      .select('id').eq('user_id', target).eq('badge_id', badge.id).maybeSingle();
    if (awardLookupError) throw awardLookupError;
    if (!existingAward) {
      const { error: awardInsertError } = await supabase.from('lz_user_badges')
        .insert({ user_id: target, badge_id: badge.id, badge_key: code, awarded_by: req.user.id });
      if (awardInsertError && awardInsertError.code !== '23505') throw awardInsertError;
    }
    try { await notifyUser(target, 'حصلت على شارة جديدة!', `${icon} ${name}${description ? ' — ' + description : ''}`, 'badge'); }
    catch (noticeError) { console.error('Badge awarded, but notification was skipped:', noticeError); }
    res.json({ ok: true, badge });
  } catch (error) { next(error); }
});

app.delete('/api/community/badges/award', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const target = String(req.body?.user_id || '');
    const badgeId = String(req.body?.badge_id || '');
    if (!uuid(target) || !uuid(badgeId)) return fail(res, 400, 'اختر العضو والشارة بشكل صحيح');
    const { data, error } = await supabase.from('lz_user_badges').delete()
      .eq('user_id', target).eq('badge_id', badgeId).select('id').maybeSingle();
    if (error) throw error;
    if (!data) return fail(res, 404, 'هذه الشارة غير ممنوحة لهذا العضو');
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// Public portfolio feed: fetch entries and profiles separately so the feed
// still works on Supabase projects where PostgREST has no cached FK relation.
app.get('/api/community/contests/public-entries', async (_req, res, next) => {
  try {
    const { data: entries, error } = await supabase.from('lz_contest_entries')
      .select('id,contest_id,user_id,video_url,likes_count,created_at')
      .order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    const userIds = [...new Set((entries || []).map(row => row.user_id).filter(Boolean))];
    let profiles = [];
    if (userIds.length) {
      const result = await supabase.from('profiles').select('id,discord_username,discord_avatar_url').in('id', userIds);
      if (result.error) throw result.error;
      profiles = result.data || [];
    }
    const profileById = new Map(profiles.map(profile => [String(profile.id), profile]));
    res.set('Cache-Control', 'no-store');
    res.json((entries || []).map(entry => ({ ...entry, profile: profileById.get(String(entry.user_id)) || null })));
  } catch (error) { next(error); }
});

app.get('/api/community/polls', async (_req, res, next) => {
  try {
    const { data: polls, error } = await supabase.from('lz_polls')
      .select('id,question,ends_at,active,created_at,options:lz_poll_options(id,label,option_text)')
      .eq('active', true).order('created_at', { ascending: false }).limit(30);
    if (error) throw error;
    const ids = (polls || []).map(p => p.id);
    let votes = [];
    if (ids.length) {
      const result = await supabase.from('lz_poll_votes').select('poll_id,option_id').in('poll_id', ids);
      if (result.error) throw result.error;
      votes = result.data || [];
    }
    res.json((polls || []).filter(p => !p.ends_at || new Date(p.ends_at) > new Date()).map(p => ({ ...p, options: (p.options || []).map(o => ({ ...o, label: o.label || o.option_text || '', votes: votes.filter(v => v.option_id === o.id).length })), total_votes: votes.filter(v => v.poll_id === p.id).length })));
  } catch (error) { next(error); }
});
app.post('/api/community/polls', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const question = String(req.body?.question || '').trim().slice(0,240);
    const options = Array.isArray(req.body?.options) ? [...new Set(req.body.options.map(x => String(x || '').trim().slice(0,100)).filter(Boolean))].slice(0,8) : [];
    const endsAt = req.body?.ends_at ? new Date(req.body.ends_at).toISOString() : null;
    if (!question || options.length < 2) return fail(res, 400, 'اكتب السؤال وخيارين على الأقل');
    const { data: poll, error } = await supabase.from('lz_polls').insert({ id: crypto.randomUUID(), title: question, question, ends_at: endsAt, created_by: req.user.id }).select('id,question,ends_at,active,created_at').single();
    if (error) throw error;
    const { error: optionError } = await supabase.from('lz_poll_options').insert(options.map(label => ({ poll_id: poll.id, label, option_text: label })));
    if (optionError) {
      // Avoid leaving an empty poll if option insertion fails.
      const { error: cleanupError } = await supabase.from('lz_polls').delete().eq('id', poll.id);
      if (cleanupError) console.error('Poll cleanup failed:', cleanupError);
      throw optionError;
    }
    // Notifications are supplementary: a missing notification column/table must not
    // make an otherwise successfully-created poll appear to fail.
    try {
      const { data: profiles, error: profilesError } = await supabase.from('profiles').select('id').eq('onboarding_completed', true).limit(1000);
      if (profilesError) throw profilesError;
      if ((profiles || []).length) {
        const notices = profiles.map(profile => ({ user_id: profile.id, title: 'تصويت جديد في LZ EDITORS', body: question, type: 'poll' }));
        const { error: noticeError } = await supabase.from('lz_notifications').insert(notices);
        if (noticeError) throw noticeError;
      }
    } catch (noticeError) { console.error('Poll created, but notifications were skipped:', noticeError); }
    res.status(201).json({ ...poll, options });
  } catch (error) { next(error); }
});
app.post('/api/community/polls/:id/vote', auth, requireOnboarding, async (req, res, next) => {
  try {
    const { data: poll, error: pollError } = await supabase.from('lz_polls').select('id,active,ends_at').eq('id', req.params.id).maybeSingle();
    if (pollError) throw pollError;
    if (!poll || !poll.active || (poll.ends_at && new Date(poll.ends_at) <= new Date())) return fail(res, 409, 'انتهى التصويت أو تم إغلاقه');
    const optionId = Number(req.body?.option_id);
    const { data: option, error: optionError } = await supabase.from('lz_poll_options').select('id').eq('id', optionId).eq('poll_id', poll.id).maybeSingle();
    if (optionError) throw optionError;
    if (!option) return fail(res, 400, 'خيار التصويت غير صحيح');
    const { error } = await supabase.from('lz_poll_votes').insert({ poll_id: poll.id, option_id: option.id, user_id: req.user.id });
    if (error?.code === '23505') return fail(res, 409, 'لقد صوتت في هذا الاستطلاع من قبل');
    if (error) throw error;
    res.json({ ok: true });
  } catch (error) { next(error); }
});

app.post('/api/community/giveaways/:id/join', auth, requireOnboarding, async (req, res, next) => {
  try {
    const { data: contentRow, error: contentError } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (contentError) throw contentError;
    const giveaway = (contentRow?.content?.giveaways || []).find(g => String(g.id) === String(req.params.id));
    if (!giveaway || (giveaway.end && giveaway.end < new Date().toISOString().slice(0,10))) return fail(res, 404, 'المسابقة غير متاحة');
    const { error } = await supabase.from('lz_giveaway_entries').insert({ giveaway_id: String(giveaway.id), user_id: req.user.id });
    if (error?.code === '23505') return fail(res, 409, 'أنت مسجل في هذه المسابقة بالفعل');
    if (error) throw error;
    await notifyUser(req.user.id, 'تم تسجيل مشاركتك', `تم تسجيلك في ${giveaway.title}`, 'giveaway');
    res.json({ ok: true });
  } catch (error) { next(error); }
});
app.get('/api/community/giveaway-winners', async (_req, res, next) => {
  try {
    const { data: draws, error } = await supabase.from('lz_giveaway_draws').select('id,giveaway_id,winner_user_id,entries_count,created_at').order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    const ids = [...new Set((draws || []).map(row => row.winner_user_id))];
    const { data: profiles, error: profileError } = ids.length ? await supabase.from('profiles').select('id,discord_username,discord_avatar_url').in('id', ids) : { data: [], error: null };
    if (profileError) throw profileError;
    const byId = new Map((profiles || []).map(profile => [profile.id, profile]));
    res.json((draws || []).map(draw => ({ ...draw, profile: byId.get(draw.winner_user_id) || null })));
  } catch (error) { next(error); }
});
app.get('/api/community/giveaways/:id/entries', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_giveaway_entries').select('user_id,created_at,profile:profiles(discord_username,discord_avatar_url)').eq('giveaway_id', String(req.params.id)).order('created_at');
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.post('/api/community/giveaways/:id/draw', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const { data: entries, error } = await supabase.from('lz_giveaway_entries').select('user_id').eq('giveaway_id', String(req.params.id));
    if (error) throw error;
    if (!entries?.length) return fail(res, 409, 'لا توجد مشاركات لاختيار فائز');
    const winner = entries[crypto.randomInt(entries.length)];
    const { data: profile } = await supabase.from('profiles').select('discord_username').eq('id', winner.user_id).maybeSingle();
    const { error: drawError } = await supabase.from('lz_giveaway_draws').insert({ giveaway_id: String(req.params.id), winner_user_id: winner.user_id, drawn_by: req.user.id, entries_count: entries.length });
    if (drawError) throw drawError;
    const { data: winnerBadge } = await supabase.from('lz_badges').select('id,code').eq('code', 'contest_winner').maybeSingle();
    if (winnerBadge) await supabase.from('lz_user_badges').upsert({ user_id: winner.user_id, badge_id: winnerBadge.id, badge_key: winnerBadge.code, awarded_by: req.user.id }, { onConflict: 'user_id,badge_id' });
    await notifyUser(winner.user_id, 'مبروك! فزت في Giveaway', 'تم اختيارك فائزاً في إحدى مسابقات LZ EDITORS، وحصلت على شارة بطل المسابقة.', 'winner');
    res.json({ user_id: winner.user_id, username: profile?.discord_username || 'عضو', total_entries: entries.length });
  } catch (error) { next(error); }
});

// TikTok video contest: members submit their own public TikTok video URL.
app.post('/api/community/contests/:id/entries', auth, requireOnboarding, async (req, res, next) => {
  try {
    const raw = String(req.body?.video_url || '').trim();
    let url;
    try { url = new URL(raw); } catch { return fail(res, 400, 'رابط فيديو TikTok غير صحيح'); }
    const host = url.hostname.toLowerCase();
    const isTikTok = host === 'tiktok.com' || host.endsWith('.tiktok.com');
    const hasVideoPath = /\/@[A-Za-z0-9._]+\/video\/\d+/.test(url.pathname);
    const isShortShare = host === 'vm.tiktok.com' || host === 'vt.tiktok.com';
    if (url.protocol !== 'https:' || !isTikTok || (!hasVideoPath && !isShortShare)) return fail(res, 400, 'أرسل رابط فيديو TikTok عاماً وصحيحاً');
    const { data: row, error: contentError } = await supabase.from('lz_site_content').select('content').eq('id', 1).maybeSingle();
    if (contentError) throw contentError;
    const contest = (row?.content?.giveaways || []).find(g => String(g.id) === String(req.params.id) && g.type === 'tiktok_contest');
    if (!contest || (contest.end && contest.end < new Date().toISOString().slice(0,10))) return fail(res, 404, 'مسابقة الفيديو غير متاحة');
    // لا نفرض ربط TikTok OAuth لقبول رابط المشاركة؛ يكفي رابط TikTok عام.
    // تبقى مزامنة الإعجابات الرسمية منفصلة وتتطلب ربط الحساب والصلاحيات المناسبة.
    url.hash = '';
    const { data, error } = await supabase.from('lz_contest_entries').insert({ contest_id: String(contest.id), user_id: req.user.id, video_url: url.href, likes_count: 0, baseline_likes_count: 0, last_observed_likes_count: 0, likes_updated_at: new Date().toISOString(), likes_source: 'pending_sync' }).select('id,video_url,likes_count,created_at').single();
    if (error?.code === '23505') return fail(res, 409, 'هذا الفيديو مسجل بالفعل في المسابقة');
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) { next(error); }
});
app.get('/api/community/contests/entries', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_contest_entries').select('id,contest_id,user_id,video_url,likes_count,likes_updated_at,created_at,profile:profiles(discord_username)').order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.get('/api/community/contests/:id/entries', async (req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_contest_entries').select('id,user_id,video_url,likes_count,likes_updated_at,likes_source,created_at,profile:profiles(discord_username,discord_avatar_url)').eq('contest_id', String(req.params.id)).order('likes_count', { ascending: false }).limit(300);
    if (error) throw error;
    res.json(data || []);
  } catch (error) { next(error); }
});
app.patch('/api/community/contests/entries/:entryId/likes', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const observed = Number(req.body?.current_likes_count);
    if (!Number.isSafeInteger(observed) || observed < 0 || observed > 1000000000) return fail(res, 400, 'إجمالي الإعجابات غير صالح');
    const { data: existing, error: readError } = await supabase.from('lz_contest_entries').select('baseline_likes_count').eq('id', req.params.entryId).maybeSingle();
    if (readError) throw readError;
    if (!existing) return fail(res, 404, 'المشاركة غير موجودة');
    const points = Math.max(0, observed - Number(existing.baseline_likes_count || 0));
    const { data, error } = await supabase.from('lz_contest_entries').update({ likes_count: points, last_observed_likes_count: observed, likes_updated_at: new Date().toISOString(), likes_source: 'admin_verified' }).eq('id', req.params.entryId).select('id,likes_count,likes_updated_at').single();
    if (error) throw error;
    res.json(data);
  } catch (error) { next(error); }
});


// إدارة استطلاعات المجتمع: حذف الاستطلاع يحذف الخيارات والأصوات التابعة عبر ON DELETE CASCADE.
app.get('/api/community/admin/polls', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data, error } = await supabase.from('lz_polls').select('id,question,ends_at,active,created_at,options:lz_poll_options(id,label,option_text)').order('created_at', { ascending: false }).limit(100);
    if (error) throw error;
    res.json((data || []).map(poll => ({ ...poll, options: (poll.options || []).map(option => ({ ...option, label: option.label || option.option_text || '' })) })));
  } catch (error) { next(error); }
});
app.delete('/api/community/polls/:id', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const { data: poll, error: readError } = await supabase.from('lz_polls').select('id,question').eq('id', req.params.id).maybeSingle();
    if (readError) throw readError;
    if (!poll) return fail(res, 404, 'Poll not found');
    const { error } = await supabase.from('lz_polls').delete().eq('id', poll.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (error) { next(error); }
});

// معالجة الأخطاء
app.use((error, _req, res, _next) => {
  console.error('Backend error:', error);
  if (error?.type === 'entity.too.large' || error?.status === 413) {
    return res.status(413).json({ error: 'حجم البيانات كبير. قلّل حجم صورة المسابقة وحاول مجدداً.' });
  }
  const code = error?.code;
  if (code === '42703' || code === 'PGRST204' || code === 'PGRST200' || code === 'PGRST201') {
    return res.status(500).json({ error: 'قاعدة البيانات ناقصها عمود أو تحديث. شغّل migration.sql في Supabase SQL Editor ثم أعد تشغيل السيرفر.' });
  }
  if (code === '23505') {
    return res.status(409).json({ error: 'يوجد سجل مكرر. راجع user_id في جداول lz_user_roles و lz_user_bans.' });
  }
  const safeMessage = typeof error?.message === 'string' ? error.message.slice(0, 220) : 'Unknown backend error';
  res.status(500).json({ error: `Server error: ${safeMessage}`, code: code || 'INTERNAL_ERROR' });
});

const port = Number(process.env.PORT) || 3000;

app.listen(port, () => {
  console.log(`LZ EDITORS API listening on port ${port}`);
  if (tiktokConfigReady()) { setTimeout(syncTikTokContestLikes, 15000); setInterval(syncTikTokContestLikes, 60 * 1000); }
});
