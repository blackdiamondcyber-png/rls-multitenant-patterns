-- Schema: multi-tenant field sales, generic
-- Branch is the tenant boundary. Reps belong to one branch.

create table if not exists branches (
  id          uuid primary key default gen_random_uuid(),
  name        text not null unique,
  created_at  timestamptz not null default now()
);

create type user_role as enum ('rep', 'manager', 'admin');

create table if not exists profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text not null,
  role        user_role not null default 'rep',
  branch_id   uuid references branches(id),
  active      boolean not null default true,
  created_at  timestamptz not null default now()
);

create table if not exists accounts (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  branch_id     uuid not null references branches(id),
  assigned_to   uuid references profiles(id),
  latitude      double precision,
  longitude     double precision,
  is_customer   boolean not null default false,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

create table if not exists activity (
  id          uuid primary key default gen_random_uuid(),
  account_id  uuid not null references accounts(id) on delete cascade,
  user_id     uuid not null references profiles(id),
  kind        text not null,
  note        text,
  occurred_at timestamptz not null default now()
);

create index if not exists accounts_branch_idx      on accounts (branch_id);
create index if not exists accounts_assigned_idx    on accounts (assigned_to);
create index if not exists accounts_geo_idx         on accounts (latitude, longitude);
create index if not exists activity_account_idx     on activity (account_id);
create index if not exists activity_user_time_idx   on activity (user_id, occurred_at desc);

alter table branches enable row level security;
alter table profiles enable row level security;
alter table accounts enable row level security;
alter table activity enable row level security;
