-- Assertions that bulk_import's EXECUTE grant lands where it should, and a
-- demonstration of the PUBLIC gap it is there to close.
-- Run against a scratch database, after 00 through 04.

begin;

do $$
begin
  if has_function_privilege('anon', 'public.bulk_import(jsonb)', 'execute') then
    raise exception 'anon can execute bulk_import; the PUBLIC grant was not fully revoked';
  end if;

  if has_function_privilege('authenticated', 'public.bulk_import(jsonb)', 'execute') then
    raise exception 'authenticated can execute bulk_import; the PUBLIC grant was not fully revoked';
  end if;

  if not has_function_privilege('service_role', 'public.bulk_import(jsonb)', 'execute') then
    raise exception 'service_role cannot execute bulk_import; the grant is missing';
  end if;

  -- Same shape as bulk_import, built only to prove the PUBLIC point in
  -- isolation: revoke from anon and authenticated but leave PUBLIC alone,
  -- and show that anon can still execute it through the inherited grant.
  create function public.bulk_import_throwaway(p_rows jsonb)
  returns int
  language plpgsql
  security definer
  set search_path = public
  as $f$
  declare
    n int;
  begin
    insert into accounts (name, branch_id)
    select r ->> 'name', (r ->> 'branch_id')::uuid
    from jsonb_array_elements(p_rows) as r;
    get diagnostics n = row_count;
    return n;
  end;
  $f$;

  revoke execute on function public.bulk_import_throwaway(jsonb) from anon, authenticated;

  if not has_function_privilege('anon', 'public.bulk_import_throwaway(jsonb)', 'execute') then
    raise exception 'anon lost execute after revoking from anon and authenticated only; the PUBLIC grant should still cover it, which is the whole point';
  end if;

  drop function public.bulk_import_throwaway(jsonb);

  raise notice 'all import privilege assertions passed';
end $$;

rollback;
