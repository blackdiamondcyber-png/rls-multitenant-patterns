-- Bulk import. SECURITY DEFINER so a batch load can write straight into
-- accounts without a signed-in session or a role RLS applies to. That is also
-- exactly why the EXECUTE grant on this function matters more than on any of
-- the read-only helpers in 02-helpers.sql: getting the grant wrong here does
-- not just widen a read, it lets anyone insert rows.
create or replace function public.bulk_import(p_rows jsonb)
returns int
language plpgsql
security definer
set search_path = public
as $$
declare
  n int;
begin
  insert into accounts (name, branch_id)
  select r ->> 'name', (r ->> 'branch_id')::uuid
  from jsonb_array_elements(p_rows) as r;

  get diagnostics n = row_count;
  return n;
end;
$$;

-- Postgres grants EXECUTE on every new function to PUBLIC by default, and
-- anon and authenticated both inherit PUBLIC, so revoking from just those two
-- roles leaves the function callable through the PUBLIC grant underneath.
-- Revoke PUBLIC itself, then the two named roles for clarity, and leave the
-- function to the service role only.
revoke execute on function public.bulk_import(jsonb) from public, anon, authenticated;

grant execute on function public.bulk_import(jsonb) to service_role;
