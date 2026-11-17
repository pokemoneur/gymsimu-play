-- GymSimu account profiles and private save slots.
-- Run this only in the separate GymSimu Supabase project.

create table if not exists public.gym_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text,
  role text not null default 'player' check (role in ('player', 'developer', 'admin')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.gym_saves (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  slot smallint not null check (slot between 1 and 3),
  title text not null default 'Save slot',
  game_state jsonb not null,
  access_code_hash text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, slot)
);

create index if not exists gym_saves_user_updated_idx on public.gym_saves(user_id, updated_at desc);

create or replace function public.gym_profile_on_signup()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.gym_profiles(user_id, email, display_name, role)
  values (
    new.id,
    coalesce(new.email, ''),
    nullif(new.raw_user_meta_data ->> 'display_name', ''),
    case when lower(coalesce(new.email, '')) = 'charlesniagnebiz@gmail.com' then 'admin' else 'player' end
  )
  on conflict (user_id) do update
    set email = excluded.email,
        display_name = coalesce(excluded.display_name, public.gym_profiles.display_name),
        updated_at = now();
  return new;
end;
$$;

drop trigger if exists gym_profile_after_signup on auth.users;
create trigger gym_profile_after_signup
  after insert or update of email, raw_user_meta_data on auth.users
  for each row execute function public.gym_profile_on_signup();

create or replace function public.gym_touch_updated_at()
returns trigger language plpgsql set search_path = '' as $$
begin new.updated_at = now(); return new; end;
$$;
drop trigger if exists gym_profiles_touch on public.gym_profiles;
create trigger gym_profiles_touch before update on public.gym_profiles
  for each row execute function public.gym_touch_updated_at();
drop trigger if exists gym_saves_touch on public.gym_saves;
create trigger gym_saves_touch before update on public.gym_saves
  for each row execute function public.gym_touch_updated_at();

alter table public.gym_profiles enable row level security;
alter table public.gym_saves enable row level security;

drop policy if exists "Players read own profile" on public.gym_profiles;
create policy "Players read own profile" on public.gym_profiles
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists "Players read own saves" on public.gym_saves;
create policy "Players read own saves" on public.gym_saves
  for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "Players create own saves" on public.gym_saves;
create policy "Players create own saves" on public.gym_saves
  for insert to authenticated with check (user_id = (select auth.uid()));
drop policy if exists "Players update own saves" on public.gym_saves;
create policy "Players update own saves" on public.gym_saves
  for update to authenticated using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));
drop policy if exists "Players delete own saves" on public.gym_saves;
create policy "Players delete own saves" on public.gym_saves
  for delete to authenticated using (user_id = (select auth.uid()));

revoke all on public.gym_profiles, public.gym_saves from anon;
grant select on public.gym_profiles to authenticated;
grant select, insert, update, delete on public.gym_saves to authenticated;

-- No public directory, admin role changes, or developer-code gate is exposed here.
-- Those require a server-side admin function and a privately configured secret.
