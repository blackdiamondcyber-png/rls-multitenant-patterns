-- Assertions against the policies. Raises on first failure.
-- Run against a scratch database. Seeds two branches, three users.

begin;

do $$
declare
  b1 uuid; b2 uuid;
  rep1 uuid := '11111111-1111-1111-1111-111111111111';
  rep2 uuid := '22222222-2222-2222-2222-222222222222';
  mgr1 uuid := '33333333-3333-3333-3333-333333333333';
  acct_r1 uuid; acct_r2 uuid; visible int; touched int; reassigned_to uuid;
begin
  insert into branches (name) values ('North') returning id into b1;
  insert into branches (name) values ('South') returning id into b2;

  -- Supabase owns auth.users and profiles.id is a foreign key into it, so
  -- the fixture users have to exist there before a profile can reference them.
  insert into auth.users (id) values (rep1), (rep2), (mgr1)
    on conflict (id) do nothing;

  insert into profiles (id, full_name, role, branch_id) values
    (rep1, 'Rep One',  'rep',     b1),
    (rep2, 'Rep Two',  'rep',     b1),
    (mgr1, 'Manager',  'manager', b1);

  insert into accounts (name, branch_id, assigned_to) values ('Acct A', b1, rep1) returning id into acct_r1;
  insert into accounts (name, branch_id, assigned_to) values ('Acct B', b1, rep2) returning id into acct_r2;
  insert into accounts (name, branch_id, assigned_to) values ('Acct C', b2, null);

  -- Everything above ran as the table owner, who bypasses row level security
  -- so the fixtures can be seeded. Everything below runs as a signed-in user,
  -- which is the only condition under which the policies apply at all. Without
  -- this line every assertion below passes for the wrong reason.
  perform set_config('role', 'authenticated', true);

  -- Rep One sees both accounts in their branch, not the other branch's.
  perform set_config('request.jwt.claims', json_build_object('sub', rep1)::text, true);
  select count(*) into visible from accounts;
  if visible <> 2 then
    raise exception 'rep should see 2 branch accounts, saw %', visible;
  end if;

  -- USING decides which existing rows you may touch, and a row it filters out
  -- is not an error. The UPDATE simply matches nothing. This is the quiet half
  -- of the split and the half people get wrong, because it fails silently in an
  -- application that does not check the row count.
  update accounts set is_customer = true where id = acct_r2;
  get diagnostics touched = row_count;
  if touched <> 0 then
    raise exception 'rep updated another rep''s account; USING failed';
  end if;

  -- WITH CHECK decides what the row may look like afterwards, and that one does
  -- raise. Rep One may edit their own account but may not hand it to Rep Two.
  begin
    update accounts set assigned_to = rep2 where id = acct_r1;
    raise exception 'rep gave away their own account; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  -- Rep One can edit their own account.
  update accounts set is_customer = true where id = acct_r1;
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'rep should have updated their own account, touched %', touched;
  end if;

  -- Manager can reassign within the branch.
  perform set_config('request.jwt.claims', json_build_object('sub', mgr1)::text, true);
  update accounts set assigned_to = rep1 where id = acct_r2;
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'manager should have reassigned the account, touched %', touched;
  end if;

  select assigned_to into reassigned_to from accounts where id = acct_r2;
  if reassigned_to <> rep1 then
    raise exception 'account should be assigned to rep1, was %', reassigned_to;
  end if;

  raise notice 'all RLS assertions passed';
end $$;

rollback;
