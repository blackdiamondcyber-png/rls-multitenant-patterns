-- Coverage for the policies tests/rls-tests.sql does not reach: role
-- immutability on profiles_update_self, and the actual visibility/insert
-- rules for activity, profiles_select and branches. Same style as
-- tests/rls-tests.sql: seed as the table owner, switch to authenticated,
-- impersonate by setting request.jwt.claims, raise on the first failure.
-- Run against a scratch database, after 00 through 04.

begin;

do $$
declare
  b1 uuid; b2 uuid;
  rep1   uuid := 'a1111111-1111-1111-1111-111111111111';
  rep2   uuid := 'a2222222-2222-2222-2222-222222222222';
  rep3   uuid := 'a3333333-3333-3333-3333-333333333333';
  mgr1   uuid := 'a4444444-4444-4444-4444-444444444444';
  admin1 uuid := 'a5555555-5555-5555-5555-555555555555';
  acct_r1 uuid; acct_r2 uuid; acct_b2 uuid;
  act_rep1 uuid; act_rep2 uuid; act_mgr1 uuid; act_rep3 uuid;
  touched int; visible int; seen_role user_role; seen_name text;
begin
  insert into branches (name) values ('Coverage North') returning id into b1;
  insert into branches (name) values ('Coverage South') returning id into b2;

  insert into auth.users (id) values (rep1), (rep2), (rep3), (mgr1), (admin1)
    on conflict (id) do nothing;

  insert into profiles (id, full_name, role, branch_id) values
    (rep1,   'Coverage Rep One',   'rep',     b1),
    (rep2,   'Coverage Rep Two',   'rep',     b1),
    (rep3,   'Coverage Rep Three', 'rep',     b2),
    (mgr1,   'Coverage Manager',   'manager', b1),
    (admin1, 'Coverage Admin',     'admin',   b1);

  insert into accounts (name, branch_id, assigned_to) values ('Coverage Acct 1', b1, rep1) returning id into acct_r1;
  insert into accounts (name, branch_id, assigned_to) values ('Coverage Acct 2', b1, rep2) returning id into acct_r2;
  insert into accounts (name, branch_id, assigned_to) values ('Coverage Acct 3', b2, rep3) returning id into acct_b2;

  -- Activity fixture, seeded as the table owner like everything else above.
  -- One row per user, so the select tests below can tell whose rows a role
  -- can and cannot see.
  insert into activity (account_id, user_id, kind) values (acct_r1, rep1, 'call') returning id into act_rep1;
  insert into activity (account_id, user_id, kind) values (acct_r2, rep2, 'call') returning id into act_rep2;
  insert into activity (account_id, user_id, kind) values (acct_r1, mgr1, 'visit') returning id into act_mgr1;
  insert into activity (account_id, user_id, kind) values (acct_b2, rep3, 'call') returning id into act_rep3;

  -- Same reasoning as tests/rls-tests.sql: everything above ran as the table
  -- owner, who bypasses row level security. Everything below runs as
  -- `authenticated`, or the assertions below pass for the wrong reason.
  perform set_config('role', 'authenticated', true);

  ------------------------------------------------------------------------
  -- profiles_update_self: role immutability
  --   using (id = auth.uid())
  --   with check (id = auth.uid() and role = current_user_role())
  ------------------------------------------------------------------------

  perform set_config('request.jwt.claims', json_build_object('sub', rep1)::text, true);

  -- A rep may not promote themselves, even on their own row. WITH CHECK
  -- compares the new row's role against current_user_role(), which reads
  -- profiles fresh, so the attempted new value never matches and the write
  -- is rejected the same way accounts_update rejects a self-reassignment.
  begin
    update profiles set role = 'admin' where id = rep1;
    raise exception 'rep changed their own role; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  select role into seen_role from profiles where id = rep1;
  if seen_role <> 'rep' then
    raise exception 'rep1 role should still be rep after the rejected update, was %', seen_role;
  end if;

  -- The same row, a column WITH CHECK does not restrict: still writable.
  update profiles set full_name = 'Coverage Rep One (edited)' where id = rep1;
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'rep should be able to edit their own profile, touched %', touched;
  end if;

  -- USING is id = auth.uid(): a rep cannot touch another user's profile row
  -- at all. There is no WITH CHECK error here, the row is simply not
  -- matched, so this is the quiet half and has to be checked by row count.
  update profiles set full_name = 'Hijacked' where id = rep2;
  get diagnostics touched = row_count;
  if touched <> 0 then
    raise exception 'rep updated another user''s profile; USING failed';
  end if;

  select full_name into seen_name from profiles where id = rep2;
  if seen_name <> 'Coverage Rep Two' then
    raise exception 'rep2 profile should be untouched, was %', seen_name;
  end if;

  ------------------------------------------------------------------------
  -- profiles_select: branch-scoped roster
  --   using (current_user_role() = 'admin' or branch_id = current_branch())
  ------------------------------------------------------------------------

  -- Rep One's branch (North) holds 4 profiles: both reps, the manager and
  -- the admin. Rep Three is in the other branch and must not show up.
  select count(*) into visible from profiles;
  if visible <> 4 then
    raise exception 'rep should see 4 branch profiles, saw %', visible;
  end if;

  select count(*) into visible from profiles where id = rep3;
  if visible <> 0 then
    raise exception 'rep should not see a profile from another branch, saw %', visible;
  end if;

  -- Admin reads every profile regardless of branch.
  perform set_config('request.jwt.claims', json_build_object('sub', admin1)::text, true);
  select count(*) into visible from profiles;
  if visible <> 5 then
    raise exception 'admin should see all 5 profiles, saw %', visible;
  end if;

  ------------------------------------------------------------------------
  -- activity_select: own rows always, branch rows only for manager/admin
  --   using (
  --     current_user_role() = 'admin'
  --     or user_id = auth.uid()
  --     or (is_manager_or_admin() and account's branch = current_branch())
  --   )
  ------------------------------------------------------------------------

  -- Rep One is not a manager, so branch membership buys them nothing here,
  -- unlike accounts_select. They see only the row user_id = auth.uid()
  -- matches, not Rep Two's activity even though it is the same branch.
  perform set_config('request.jwt.claims', json_build_object('sub', rep1)::text, true);
  select count(*) into visible from activity;
  if visible <> 1 then
    raise exception 'rep should see only their own activity row, saw %', visible;
  end if;

  select count(*) into visible from activity where id = act_rep2;
  if visible <> 0 then
    raise exception 'rep should not see a branch-mate''s activity, saw %', visible;
  end if;

  -- The manager sees their own row plus every row whose account is in their
  -- branch (North): that is Rep One, Rep Two and their own, three rows. The
  -- fourth row belongs to Rep Three's account in the other branch and must
  -- stay invisible, which is what would break if the branch check were ever
  -- dropped from the manager clause.
  perform set_config('request.jwt.claims', json_build_object('sub', mgr1)::text, true);
  select count(*) into visible from activity;
  if visible <> 3 then
    raise exception 'manager should see 3 branch activity rows, saw %', visible;
  end if;

  select count(*) into visible from activity where id = act_rep3;
  if visible <> 0 then
    raise exception 'manager should not see another branch''s activity, saw %', visible;
  end if;

  ------------------------------------------------------------------------
  -- activity_insert
  --   with check (
  --     user_id = auth.uid()
  --     and exists (select 1 from accounts a where a.id = account_id
  --                 and a.branch_id = current_branch())
  --   )
  -- Branch membership of the account is what gates this, not assignment,
  -- so a rep can log activity against a branch-mate's account.
  ------------------------------------------------------------------------

  perform set_config('request.jwt.claims', json_build_object('sub', rep1)::text, true);

  insert into activity (account_id, user_id, kind) values (acct_r2, rep1, 'note');
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'rep should be able to log activity on a branch-mate''s account, inserted %', touched;
  end if;

  -- Another branch's account: rejected by the exists() branch check.
  begin
    insert into activity (account_id, user_id, kind) values (acct_b2, rep1, 'note');
    raise exception 'rep logged activity against another branch''s account; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  -- Logging as somebody else: rejected by user_id = auth.uid().
  begin
    insert into activity (account_id, user_id, kind) values (acct_r1, rep2, 'note');
    raise exception 'rep logged activity as another user; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  ------------------------------------------------------------------------
  -- branches_select: open to every signed-in user, not branch-scoped
  --   using (auth.uid() is not null)
  ------------------------------------------------------------------------

  select count(*) into visible from branches;
  if visible <> 2 then
    raise exception 'rep should see all branches regardless of their own branch, saw %', visible;
  end if;

  ------------------------------------------------------------------------
  -- branches_write: admin-only, both halves of the split
  --   using (current_user_role() = 'admin')
  --   with check (current_user_role() = 'admin')
  ------------------------------------------------------------------------

  -- Rep: USING filters the row out, so the update touches nothing. No error.
  update branches set name = 'Hijacked branch' where id = b1;
  get diagnostics touched = row_count;
  if touched <> 0 then
    raise exception 'rep updated a branch; USING failed';
  end if;

  select name into seen_name from branches where id = b1;
  if seen_name <> 'Coverage North' then
    raise exception 'branch name should be untouched by a rep, was %', seen_name;
  end if;

  -- Manager: WITH CHECK rejects the insert outright, this is not just a rep
  -- restriction, "admin-only" has to mean managers are blocked too.
  perform set_config('request.jwt.claims', json_build_object('sub', mgr1)::text, true);
  begin
    insert into branches (name) values ('Manager tried this');
    raise exception 'manager created a branch; WITH CHECK failed';
  exception when insufficient_privilege then
    null; -- expected
  end;

  -- Admin: both operations succeed.
  perform set_config('request.jwt.claims', json_build_object('sub', admin1)::text, true);

  insert into branches (name) values ('Coverage East');
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'admin should be able to create a branch, inserted %', touched;
  end if;

  update branches set name = 'Coverage North (renamed)' where id = b1;
  get diagnostics touched = row_count;
  if touched <> 1 then
    raise exception 'admin should be able to rename a branch, touched %', touched;
  end if;

  raise notice 'all RLS coverage assertions passed';
end $$;

rollback;
