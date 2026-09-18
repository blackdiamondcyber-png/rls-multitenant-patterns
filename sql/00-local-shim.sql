-- Supabase provides the auth schema, auth.uid(), the anon and authenticated
-- roles, and the default grants that go with them. This file recreates just
-- enough of that to run the schema, the policies and the tests on a plain
-- Postgres, locally or in CI.
--
-- Do not run this on Supabase. It already has all of it.
--
-- The point of the shim is that nothing else in the repo changes: the helpers
-- and policies that follow are the same text that runs in production.

create schema if not exists auth;

create table if not exists auth.users (
  id uuid primary key
);

-- Supabase puts the verified JWT in a request-scoped GUC and reads the subject
-- out of it. Same contract here, so a test can impersonate a user by setting
-- request.jwt.claims and nothing in the policy files needs to know.
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select nullif(current_setting('request.jwt.claims', true)::jsonb ->> 'sub', '')::uuid;
$$;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
end $$;

grant usage on schema public, auth to anon, authenticated;
grant execute on function auth.uid() to anon, authenticated;

-- Applies to the tables 01-schema.sql is about to create, which is what makes
-- row level security meaningful: a signed-in user reaches the tables through
-- grants and is then filtered by the policies. The table owner is not, which
-- is why the tests switch role before asserting anything.
alter default privileges in schema public
  grant select, insert, update, delete on tables to authenticated;
alter default privileges in schema public
  grant usage, select on sequences to authenticated;
