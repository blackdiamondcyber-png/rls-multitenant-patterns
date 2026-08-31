-- ACCOUNTS
-- Read: anyone in the branch sees the whole branch. Admins see everything.
create policy accounts_select on accounts
for select using (
  current_user_role() = 'admin'
  or branch_id = current_branch()
);

-- Insert: you may create an account in your own branch. A rep may only create
-- one assigned to themselves; a manager may assign to anyone.
create policy accounts_insert on accounts
for insert with check (
  current_user_role() = 'admin'
  or (
    branch_id = current_branch()
    and (is_manager_or_admin() or assigned_to = auth.uid())
  )
);

-- Update: the split that matters.
--   USING      -> which existing rows you may touch
--   WITH CHECK -> what the row may look like afterwards
-- A rep can edit their own accounts but cannot hand one to someone else,
-- and cannot pull an unassigned account to themselves without a manager.
create policy accounts_update on accounts
for update
using (
  current_user_role() = 'admin'
  or (branch_id = current_branch() and (is_manager_or_admin() or assigned_to = auth.uid()))
)
with check (
  current_user_role() = 'admin'
  or (branch_id = current_branch() and (is_manager_or_admin() or assigned_to = auth.uid()))
);

-- Delete: managers and admins only. Reps do not delete accounts.
create policy accounts_delete on accounts
for delete using (
  current_user_role() = 'admin'
  or (is_manager_or_admin() and branch_id = current_branch())
);

-- ACTIVITY
-- Reps see and write their own activity. Managers see the branch.
create policy activity_select on activity
for select using (
  current_user_role() = 'admin'
  or user_id = auth.uid()
  or (
    is_manager_or_admin()
    and exists (select 1 from accounts a where a.id = activity.account_id and a.branch_id = current_branch())
  )
);

create policy activity_insert on activity
for insert with check (
  user_id = auth.uid()
  and exists (select 1 from accounts a where a.id = account_id and a.branch_id = current_branch())
);

-- PROFILES
-- Everyone reads their branch roster. Nobody edits their own role.
create policy profiles_select on profiles
for select using (
  current_user_role() = 'admin'
  or branch_id = current_branch()
);

create policy profiles_update_self on profiles
for update
using (id = auth.uid())
with check (id = auth.uid() and role = current_user_role());

-- BRANCHES: readable by all signed-in users, writable by admins only.
create policy branches_select on branches for select using (auth.uid() is not null);
create policy branches_write  on branches for all
  using (current_user_role() = 'admin')
  with check (current_user_role() = 'admin');
