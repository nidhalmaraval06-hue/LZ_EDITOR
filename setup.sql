-- Run in Supabase SQL Editor after checking your existing profiles table.
-- Assumes public.profiles exists with id uuid, discord_username, discord_avatar_url,
-- tiktok_url, onboarding_completed. Do not run if your schema differs.
create table if not exists public.lz_user_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in
    ('member','owner','co_owner','developer','head_admin','admin','moderator','helper','top_1','top_2'))
);
alter table public.lz_user_roles enable row level security;
-- No public policies: only the server's private service role accesses this table.
create table if not exists public.community_messages (
 id uuid primary key default gen_random_uuid(),
 user_id uuid not null references auth.users(id) on delete cascade,
 author_name text not null,
 author_avatar text,
 text text not null check (char_length(text) between 1 and 500),
 created_at timestamptz not null default now()
);
alter table public.community_messages enable row level security;
-- Existing RLS policies on community_messages remain unchanged.
