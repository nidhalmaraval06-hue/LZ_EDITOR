'use strict';

// LZ EDITORS Backend — Node.js 20+
require('dotenv').config();

const express = require('express');
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

// Serve only the intended HTML pages. Never expose the entire project folder.
const pages = [
  'login-dashboard.html',
  'login-designers.html',
  'dashboard.html',
  'designers.html'
];

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'login-dashboard.html'));
});

pages.forEach(page => {
  app.get('/' + page, (_req, res) => {
    res.sendFile(path.join(__dirname, page));
  });
});

// Serve the logo only; keep server.js, .env and other project files private.
app.get('/logo.svg', (_req, res) => {
  res.type('image/svg+xml').sendFile(path.join(__dirname, 'logo.svg'));
});
app.get('/logo.png', (_req, res) => res.sendFile(path.join(__dirname, 'logo.png')));
app.get('/manifest.webmanifest', (_req, res) => res.type('application/manifest+json').sendFile(path.join(__dirname, 'manifest.webmanifest')));
app.get('/sw.js', (_req, res) => { res.set('Service-Worker-Allowed', '/'); res.set('Cache-Control', 'no-cache'); res.sendFile(path.join(__dirname, 'sw.js')); });

app.use(express.json({ limit: '32kb' }));

const origins = process.env.FRONTEND_ORIGIN
  .split(',')
  .map(value => value.trim())
  .filter(Boolean);

app.use(cors({
  origin: origins,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  optionsSuccessStatus: 204
}));

app.use('/api', rateLimit({
  windowMs: 60_000,
  limit: 90,
  standardHeaders: 'draft-7',
  legacyHeaders: false
}));

const roles = [
  'member',
  'owner',
  'co_owner',
  'manager_admin',
  'admin'
];

const adminRoles = new Set(['owner', 'co_owner', 'manager_admin']);
const appealDiscordId = '1565737674357342228';

const uuid = value =>
  typeof value === 'string' &&
  /^[a-f\d]{8}-[a-f\d]{4}-[1-8][a-f\d]{3}-[89ab][a-f\d]{3}-[a-f\d]{12}$/i.test(value);

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

const fail = (res, status, message, extra = {}) =>
  res.status(status).json({ error: message, ...extra });

// Verify Supabase access token
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
    next();
  } catch (error) {
    next(error);
  }
}

async function requireNotBanned(req, res, next) {
  try {
    const { data: ban, error } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').eq('user_id', req.user.id).maybeSingle();
    if (error) throw error;
    if (ban && (!ban.expires_at || new Date(ban.expires_at).getTime() > Date.now())) return fail(res, 403, 'هذا الحساب محظور من LZ EDITORS', { code: 'USER_BANNED', ban, appeal_discord_id: appealDiscordId });
    next();
  } catch (error) { next(error); }
}

// Get user's role
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
    const { data: ban, error: banError } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').eq('user_id', req.user.id).maybeSingle();
    if (banError) throw banError;
    if (ban && (!ban.expires_at || new Date(ban.expires_at).getTime() > Date.now())) return fail(res, 403, 'هذا الحساب محظور', { code: 'USER_BANNED', ban });
    const role = await getRole(req.user.id);

    if (!adminRoles.has(role)) {
      return fail(res, 403, 'Not allowed');
    }

    next();
  } catch (error) {
    next(error);
  }
}

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'LZ EDITORS API'
  });
});

// Public designers
app.get('/api/designers', async (_req, res, next) => {
  try {
    const { data, error } = await supabase
      .from('profiles')
      .select(
        'id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
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

    res.json(
      profiles.map(profile => ({
        ...profile,
        role:
          profile.id === process.env.OWNER_USER_ID
            ? 'owner'
            : roleMap.get(profile.id) || 'member'
      }))
    );
  } catch (error) {
    next(error);
  }
});

// All registered profiles for manager-only ban targeting.
app.get('/api/admin/users', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data: profiles, error } = await supabase.from('profiles').select('id,username,display_name,discord_username,discord_avatar_url,onboarding_completed').order('created_at', { ascending: false }).limit(1000);
    if (error) throw error;
    const ids = (profiles || []).map(p => p.id);
    let roleMap = new Map();
    if (ids.length) {
      const { data: assigned, error: roleError } = await supabase.from('lz_user_roles').select('user_id,role').in('user_id', ids);
      if (roleError) throw roleError;
      roleMap = new Map((assigned || []).map(r => [r.user_id, r.role]));
    }
    res.json((profiles || []).map(p => ({ ...p, role: p.id === process.env.OWNER_USER_ID ? 'owner' : (roleMap.get(p.id) || 'member') })));
  } catch (error) { next(error); }
});

// Current user
app.get('/api/me', auth, async (req, res, next) => {
  try {
    const { data: ban, error: banError } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').eq('user_id', req.user.id).maybeSingle();
    if (banError) throw banError;
    if (ban && (!ban.expires_at || new Date(ban.expires_at).getTime() > Date.now())) return fail(res, 403, 'هذا الحساب محظور من LZ EDITORS', { code: 'USER_BANNED', ban, appeal_discord_id: appealDiscordId });
    const { data, error } = await supabase
      .from('profiles')
      .select(
        'id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
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

// Update TikTok profile
app.put('/api/me/profile', auth, requireNotBanned, async (req, res, next) => {
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
        'id,discord_username,discord_avatar_url,tiktok_url,onboarding_completed'
      )
      .single();

    if (error) throw error;

    res.json(data);
  } catch (error) {
    next(error);
  }
});

// Public messages
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

// Send message
app.post('/api/messages', auth, requireNotBanned, async (req, res, next) => {
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

// Delete message
app.delete('/api/messages/:id', auth, requireNotBanned, async (req, res, next) => {
  try {
    // community_messages.id is BIGINT, not a UUID.
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

// Assign roles
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

      if (
        target === process.env.OWNER_USER_ID ||
        role === 'owner'
      ) {
        return fail(res, 403, 'Owner cannot be reassigned');
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

// Ban management: only Owner, Co Owner and Manager Admin can ban/unban.
app.get('/api/bans', auth, requireOwnerOrCoOwner, async (_req, res, next) => {
  try {
    const { data: bans, error } = await supabase.from('lz_user_bans').select('user_id,reason,expires_at,banned_by,created_at').order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    const ids = [...new Set((bans || []).flatMap(x => [x.user_id, x.banned_by].filter(Boolean)))];
    let profiles = new Map();
    if (ids.length) {
      const { data, error: profileError } = await supabase.from('profiles').select('id,discord_username,discord_avatar_url').in('id', ids);
      if (profileError) throw profileError;
      profiles = new Map((data || []).map(x => [x.id, x]));
    }
    res.json((bans || []).map(b => ({ ...b, profile: profiles.get(b.user_id) || null, banned_by_profile: profiles.get(b.banned_by) || null, active: !b.expires_at || new Date(b.expires_at).getTime() > Date.now() })));
  } catch (error) { next(error); }
});

app.post('/api/bans', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const userId = req.body?.user_id;
    const reason = String(req.body?.reason || '').trim().slice(0, 500);
    const expiresAt = req.body?.expires_at || null;
    if (!uuid(userId) || !reason) return fail(res, 400, 'Valid user and ban reason required');
    if (userId === process.env.OWNER_USER_ID || userId === req.user.id) return fail(res, 403, 'Cannot ban Owner or yourself');
    if (expiresAt && (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now())) return fail(res, 400, 'Invalid expiry date');
    const { data: profile, error: profileError } = await supabase.from('profiles').select('id').eq('id', userId).maybeSingle();
    if (profileError) throw profileError;
    if (!profile) return fail(res, 404, 'User not found');
    const { data, error } = await supabase.from('lz_user_bans').upsert({ user_id: userId, reason, expires_at: expiresAt, banned_by: req.user.id }, { onConflict: 'user_id' }).select().single();
    if (error) throw error;
    res.status(201).json(data);
  } catch (error) { next(error); }
});

app.delete('/api/bans/:userId', auth, requireOwnerOrCoOwner, async (req, res, next) => {
  try {
    const userId = req.params.userId;
    if (!uuid(userId)) return fail(res, 400, 'Invalid user ID');
    if (userId === process.env.OWNER_USER_ID) return fail(res, 403, 'Cannot unban Owner');
    const { error } = await supabase.from('lz_user_bans').delete().eq('user_id', userId);
    if (error) throw error;
    res.json({ ok: true, user_id: userId });
  } catch (error) { next(error); }
});

// Appeals are stored in Supabase; opening the supplied Discord profile is still required without a bot.
app.post('/api/ban-appeals', auth, async (req, res, next) => {
  try {
    const message = String(req.body?.message || '').trim();
    if (message.length < 10 || message.length > 1500) return fail(res, 400, 'Appeal must be 10–1500 characters');
    const { data: ban, error: banError } = await supabase.from('lz_user_bans').select('created_at,expires_at').eq('user_id', req.user.id).maybeSingle();
    if (banError) throw banError;
    if (!ban || (ban.expires_at && new Date(ban.expires_at).getTime() <= Date.now())) return fail(res, 409, 'No active ban');
    const { data, error } = await supabase.from('lz_ban_appeals').insert({ user_id: req.user.id, ban_created_at: ban.created_at, message, destination_discord_id: appealDiscordId }).select('id,created_at').single();
    if (error) throw error;
    res.status(201).json({ ...data, destination_discord_id: appealDiscordId });
  } catch (error) { next(error); }
});

// Error handler
app.use((error, _req, res, _next) => {
  console.error('Backend error:', error);

  res.status(500).json({
    error: 'Server error. Check backend logs.'
  });
});

const port = Number(process.env.PORT) || 3000;

app.listen(port, () => {
  console.log(`LZ EDITORS API listening on port ${port}`);
});
