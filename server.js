
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


app.disable('x-powered-by');
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
  'developer',
  'head_admin',
  'admin',
  'moderator',
  'helper',
  'top_1',
  'top_2'
];

const adminRoles = new Set(['owner', 'co_owner']);

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

const fail = (res, status, message) =>
  res.status(status).json({ error: message });

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

// Current user
app.get('/api/me', auth, async (req, res, next) => {
  try {
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

// Delete message
app.delete('/api/messages/:id', auth, async (req, res, next) => {
  try {
    if (!uuid(req.params.id)) {
      return fail(res, 400, 'Invalid message ID');
    }

    const { data: message, error: readError } = await supabase
      .from('community_messages')
      .select('user_id')
      .eq('id', req.params.id)
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
      .eq('id', req.params.id);

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
        role === 'co_owner'
      ) {
        return fail(
          res,
          403,
          'Only Owner may assign Co Owner'
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
