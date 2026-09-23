# Row-Level Security Patterns for Multi-Tenant Field Sales Apps

[![tests](https://github.com/blackdiamondcyber-png/rls-multitenant-patterns/actions/workflows/ci.yml/badge.svg)](https://github.com/blackdiamondcyber-png/rls-multitenant-patterns/actions/workflows/ci.yml)

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
| `sql/04-import.sql` | `bulk_import`, locked to the service role only |
| `tests/rls-tests.sql` | Assertions that prove each policy does what it claims |
| `tests/import-tests.sql` | Assertions that the bulk_import grant is where it should be |

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
REVOKE EXECUTE ON FUNCTION public.bulk_import(jsonb) FROM PUBLIC, anon, authenticated;
```

Postgres grants EXECUTE on every new function to PUBLIC by default, and both
`anon` and `authenticated` inherit PUBLIC, so revoking from those two roles
alone does nothing: the function is still reachable through the inherited
grant. `tests/import-tests.sql` proves both halves of that, the closed grant on
`bulk_import` and the still-open one on a throwaway function where only the
named roles were revoked.

**Test the policies, not the app.**
The tests in `tests/` set a role and a user id, then assert on what a query
returns. They catch the case where a schema change silently widens access,
which reading the policy file will not.

## Running it

On Supabase, which already provides the `auth` schema, `auth.uid()` and the
`anon` and `authenticated` roles:

```bash
psql "$DATABASE_URL" -f sql/01-schema.sql
psql "$DATABASE_URL" -f sql/02-helpers.sql
psql "$DATABASE_URL" -f sql/03-policies.sql
psql "$DATABASE_URL" -f sql/04-import.sql
psql "$DATABASE_URL" -f tests/rls-tests.sql
psql "$DATABASE_URL" -f tests/import-tests.sql
```

On a plain Postgres 14+, run `sql/00-local-shim.sql` first. It creates those
Supabase objects and the default grants that go with them, and nothing else, so
the helper and policy files are the same text in both cases.

The test file raises an exception on the first failed assertion. CI runs the
shim and then this sequence against `postgres:16` on every push.

One detail worth copying if you write your own: the test switches to the
`authenticated` role before it asserts anything. The table owner bypasses row
level security, so a suite that seeds and asserts as the same role will pass no
matter what the policies say.

### No Postgres installed?

Run a throwaway `postgres:16` container and point psql at it:

```bash
docker run --rm -d --name rls-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:16
for f in sql/00-local-shim.sql sql/01-schema.sql sql/02-helpers.sql sql/03-policies.sql sql/04-import.sql tests/rls-tests.sql tests/import-tests.sql; do
  PGPASSWORD=postgres psql -v ON_ERROR_STOP=1 -h localhost -U postgres -f "$f" || break
done
```

Give the container a few seconds to accept connections before running the loop.

## License

MIT. Take what is useful.

More of my work: [erik-pearson-portfolio.vercel.app](https://erik-pearson-portfolio.vercel.app). Contact: [LinkedIn](https://www.linkedin.com/in/erikpearson2).
