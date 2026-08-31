-- Helpers run as SECURITY DEFINER so they can read profiles without
-- re-entering the policies that call them. search_path is pinned so a
-- caller cannot shadow public with their own schema.

create or replace function current_branch()
returns uuid
language sql
stable
security definer
set search_path = public
as $$
  select branch_id from profiles where id = auth.uid();
$$;

create or replace function current_user_role()
returns user_role
language sql
stable
security definer
set search_path = public
as $$
  select role from profiles where id = auth.uid();
$$;

create or replace function is_manager_or_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(current_user_role() in ('manager', 'admin'), false);
$$;

-- These are read-only lookups keyed to auth.uid(); safe for end users to call.
-- Any function that writes, or that bypasses RLS to move data in bulk, should
-- have EXECUTE revoked from anon and authenticated.
