-- Admin directory, developer PIN gate, and account access control.
create extension if not exists pgcrypto with schema extensions;
alter table public.gym_profiles add column if not exists is_disabled boolean not null default false;

create table if not exists public.gym_admin_controls (
  user_id uuid primary key references auth.users(id) on delete cascade,
  pin_hash text not null,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  updated_at timestamptz not null default now()
);
create table if not exists public.gym_admin_audit (
  id bigint generated always as identity primary key,
  actor_id uuid not null references auth.users(id),
  target_id uuid references auth.users(id) on delete set null,
  action text not null,
  detail jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.gym_admin_controls enable row level security;
alter table public.gym_admin_audit enable row level security;
revoke all on public.gym_admin_controls, public.gym_admin_audit from anon, authenticated;

create or replace function public.gym_admin_verify_dev_pin(p_pin text, p_setup boolean default false)
returns boolean language plpgsql security definer set search_path = '' as $$
declare v_uid uuid := auth.uid(); v_hash text; v_fail integer; v_locked timestamptz;
begin
  if v_uid is null or not exists (select 1 from public.gym_profiles p where p.user_id=v_uid and p.role='admin' and not p.is_disabled) then return false; end if;
  select c.pin_hash,c.failed_attempts,c.locked_until into v_hash,v_fail,v_locked from public.gym_admin_controls c where c.user_id=v_uid for update;
  if v_hash is null then
    if p_setup and length(p_pin)=6 then
      insert into public.gym_admin_controls(user_id,pin_hash) values(v_uid,extensions.crypt(p_pin,extensions.gen_salt('bf')))
      on conflict(user_id) do nothing;
      insert into public.gym_admin_audit(actor_id,action) values(v_uid,'developer_pin_created');
      return true;
    end if;
    return false;
  end if;
  if v_locked is not null and v_locked>now() then return false; end if;
  if extensions.crypt(p_pin,v_hash)=v_hash then
    update public.gym_admin_controls set failed_attempts=0,locked_until=null,updated_at=now() where user_id=v_uid;
    return true;
  end if;
  v_fail:=coalesce(v_fail,0)+1;
  update public.gym_admin_controls set failed_attempts=v_fail,locked_until=case when v_fail>=5 then now()+interval '15 minutes' else null end,updated_at=now() where user_id=v_uid;
  return false;
end;
$$;

create or replace function public.gym_admin_list_users(p_pin text)
returns table(user_id uuid,email text,display_name text,role text,is_disabled boolean,created_at timestamptz,save_count bigint)
language plpgsql security definer set search_path = '' as $$
begin
  if not public.gym_admin_verify_dev_pin(p_pin,false) then raise exception 'Developer code is incorrect or temporarily locked.'; end if;
  insert into public.gym_admin_audit(actor_id,action) values(auth.uid(),'account_directory_viewed');
  return query select p.user_id,p.email,p.display_name,p.role,p.is_disabled,p.created_at,count(s.id)::bigint
    from public.gym_profiles p left join public.gym_saves s on s.user_id=p.user_id group by p.user_id order by p.created_at desc;
end;
$$;

create or replace function public.gym_admin_set_user_access(p_pin text,p_target uuid,p_enabled boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.gym_admin_verify_dev_pin(p_pin,false) then raise exception 'Developer code is incorrect or temporarily locked.'; end if;
  if p_target=auth.uid() and not p_enabled then raise exception 'You cannot disable your own admin account.'; end if;
  update public.gym_profiles set is_disabled=not p_enabled,updated_at=now() where user_id=p_target;
  if not found then raise exception 'Account not found.'; end if;
  insert into public.gym_admin_audit(actor_id,target_id,action,detail) values(auth.uid(),p_target,'account_access_changed',jsonb_build_object('enabled',p_enabled));
end;
$$;

create or replace function public.gym_admin_set_role(p_pin text,p_target uuid,p_role text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not public.gym_admin_verify_dev_pin(p_pin,false) then raise exception 'Developer code is incorrect or temporarily locked.'; end if;
  if p_role not in ('player','developer','admin') then raise exception 'Role must be player, developer, or admin.'; end if;
  if p_target=auth.uid() and p_role<>'admin' then raise exception 'You cannot remove your own admin role.'; end if;
  update public.gym_profiles set role=p_role,updated_at=now() where user_id=p_target;
  if not found then raise exception 'Account not found.'; end if;
  insert into public.gym_admin_audit(actor_id,target_id,action,detail) values(auth.uid(),p_target,'account_role_changed',jsonb_build_object('role',p_role));
end;
$$;

revoke all on function public.gym_admin_verify_dev_pin(text,boolean) from public,anon;
revoke all on function public.gym_admin_list_users(text) from public,anon;
revoke all on function public.gym_admin_set_user_access(text,uuid,boolean) from public,anon;
revoke all on function public.gym_admin_set_role(text,uuid,text) from public,anon;
grant execute on function public.gym_admin_verify_dev_pin(text,boolean) to authenticated;
grant execute on function public.gym_admin_list_users(text) to authenticated;
grant execute on function public.gym_admin_set_user_access(text,uuid,boolean) to authenticated;
grant execute on function public.gym_admin_set_role(text,uuid,text) to authenticated;

drop policy if exists "Players read own saves" on public.gym_saves;
create policy "Players read own saves" on public.gym_saves for select to authenticated using (user_id=(select auth.uid()) and exists(select 1 from public.gym_profiles p where p.user_id=(select auth.uid()) and not p.is_disabled));
drop policy if exists "Players create own saves" on public.gym_saves;
create policy "Players create own saves" on public.gym_saves for insert to authenticated with check (user_id=(select auth.uid()) and exists(select 1 from public.gym_profiles p where p.user_id=(select auth.uid()) and not p.is_disabled));
drop policy if exists "Players update own saves" on public.gym_saves;
create policy "Players update own saves" on public.gym_saves for update to authenticated using (user_id=(select auth.uid()) and exists(select 1 from public.gym_profiles p where p.user_id=(select auth.uid()) and not p.is_disabled)) with check (user_id=(select auth.uid()) and exists(select 1 from public.gym_profiles p where p.user_id=(select auth.uid()) and not p.is_disabled));
drop policy if exists "Players delete own saves" on public.gym_saves;
create policy "Players delete own saves" on public.gym_saves for delete to authenticated using (user_id=(select auth.uid()) and exists(select 1 from public.gym_profiles p where p.user_id=(select auth.uid()) and not p.is_disabled));
