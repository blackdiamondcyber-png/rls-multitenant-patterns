-- Assertions against the policies. Raises on first failure.
-- Run against a scratch database. Seeds two branches, three users.

begin;

do $$
declare
  b1 uuid; b2 uuid;
  rep1 uuid := '11111111-1111-1111-1111-111111111111';
  rep2 uuid := '22222222-2222-2222-2222-222222222222';
  mgr1 uuid := '33333333-3333-3333-3333-333333333333';
  acct_r1 uuid; acct_r2 uuid; visible int;
begin
  insert into branches (name) values ('North') returning id into b1;
  insert into branches (name) values ('South') returning id into b2;

  insert into profiles (id, full_name, role, branch_id) values
    (rep1, 'Rep One',  'rep',     b1),
    (rep2, 'Rep Two',  'rep',     b1),
    (mgr1, 'Manager',  'manager', b1);

  insert into accounts (name, branch_id, assigned_to) values ('Acct A', b1, rep1) returning id into acct_r1;
  insert into accounts (name, branch_id, assigned_to) values ('Acct B', b1, rep2) returning id into acct_r2;
  insert into accounts (name, branch_id, assigned_to) values ('Acct C', b2, null);

  -- Rep One sees both accounts in their branch, not the other branch's.
  perform set_config('request.jwt.claims', json_build_object('sub', rep1)::text, true);
  select count(*) into visible from accounts;
  if visible <> 2 then
    raise exception 'rep should see 2 branch accounts, saw %', visible;
  end if;

  -- Rep One cannot reassign Rep Two's account to themselves.
  begin
    update accounts set assigned_to = rep1 where id = acct_r2;
    raise exception 'rep reassigned another rep''s account; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  -- Rep One can edit their own account.
  update accounts set is_customer = true where id = acct_r1;

  -- Manager can reassign within the branch.
  perform set_config('request.jwt.claims', json_build_object('sub', mgr1)::text, true);
  update accounts set assigned_to = rep1 where id = acct_r2;

  raise notice 'all RLS assertions passed';
end $$;

rollback;
