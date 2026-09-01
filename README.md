# Row-Level Security Patterns for Multi-Tenant Field Sales Apps

Postgres row-level security policies for the problem I kept hitting: a shared
database where every field rep should see the whole map but only act on the
accounts assigned to them, managers should see their branch, and nobody should
be able to reassign an account to themselves.

I built and shipped a territory platform on this pattern. Roughly 22,000
account records, three regional offices, ~77 users, one database. This repo is
the reusable core of that work with the business specifics stripped out.

## The problem

Field sales apps have an awkward access shape. Reps need broad read access,
because you cannot prospect a territory you cannot see, but narrow write access. The
naive approaches both fail:

**Filtering in the application layer.** One forgotten `.eq('assigned_to', userId)`
and a rep can write to another rep's account. The check lives in dozens of
places and has to be right in all of them.

**Locking reads to assigned rows only.** Now the map is empty except for what
the rep already owns, which defeats the point of a prospecting tool.

Row-level security moves the rule into the database, where it holds no matter
which client, script, or migration touches the table.

## The shape of the solution

Three roles, three different policy shapes:

| Role | Read | Write |
|------|------|-------|
| Rep | All accounts in their branch | Only accounts assigned to them |
| Manager | All accounts in their branch | All accounts in their branch |
| Admin | Everything | Everything |

The key move is splitting `USING` from `WITH CHECK`. `USING` decides which
existing rows you can see and touch. `WITH CHECK` decides what a row is allowed
to look like *after* you write it. Reps get a permissive `USING` and a strict
`WITH CHECK`, which is what stops a rep from reassigning an account to
themselves. The row would fail the check on its way in.

## Files

| File | What it holds |
|------|---------------|
| `sql/01-schema.sql` | Tables: profiles, branches, accounts, activity |
| `sql/02-helpers.sql` | `current_branch()` and `current_role()` lookups |
| `sql/03-policies.sql` | The policies themselves, one per role per operation |
| `tests/rls-tests.sql` | Assertions that prove each policy does what it claims |

## Things I got wrong the first time

**Helper functions need `SECURITY DEFINER` and a pinned `search_path`.**
A helper that reads `profiles` to find your branch will recurse forever if
`profiles` itself has RLS and the helper runs as the caller. Marking it
`SECURITY DEFINER` breaks the loop. Pinning `search_path` stops a caller from
shadowing `public` with their own schema and changing what the function reads.

**`ENABLE ROW LEVEL SECURITY` with no policy denies everything.**
That is the correct default and it is also how you lock a staging table by
accident and spend an afternoon on it.

**Batch import functions bypass everything.**
ETL helpers written as `SECURITY DEFINER` skip RLS by design. If they are also
executable by the `anon` role, the entire policy set is decorative. Revoke
execute from `anon` and `authenticated`; leave it to the service role.

```sql
REVOKE EXECUTE ON FUNCTION public.bulk_import(jsonb) FROM anon, authenticated;
```

**Test the policies, not the app.**
The tests in `tests/` set a role and a user id, then assert on what a query
returns. They catch the case where a schema change silently widens access,
which reading the policy file will not.

## Running it

Any Postgres 14+ instance, or Supabase.

```bash
psql "$DATABASE_URL" -f sql/01-schema.sql
psql "$DATABASE_URL" -f sql/02-helpers.sql
psql "$DATABASE_URL" -f sql/03-policies.sql
psql "$DATABASE_URL" -f tests/rls-tests.sql
```

The test file raises an exception on the first failed assertion.

## License

MIT. Take what is useful.
