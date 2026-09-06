-- 001_initial_schema.sql — Fincrypt v1 schema.
-- Written once; NEVER edited after apply (checksum-verified by the runner).
-- All later changes are new files (002_*.sql, ...). Dormant-track tables
-- (plaid_tokens etc.) arrive as their own migrations.

create extension if not exists citext;

create table users (
  id uuid primary key default gen_random_uuid(),
  email citext not null unique,
  opaque_record bytea not null,          -- OPAQUE server record; NO password hash
  kdf_salt bytea not null,
  kdf_params jsonb not null,             -- Argon2id m/t/p + version (upgrade path)
  wrapped_dek bytea not null,            -- nonce||ciphertext packed (KEK-AES-GCM)
  wrapped_dek_recovery bytea not null,   -- BIP39-recovery wrap
  email_verified boolean not null default false,  -- no mailer in v1; flow deferred
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table accounts (                  -- manual accounts; first-class
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  account_key uuid not null,             -- client-generated random grouping key (NOT a hash of any external ID); real name/balance live inside ciphertext
  encrypted_blob bytea not null,         -- name, currency, opening balance, institution note
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz                 -- tombstone
);

create table vaults (                    -- settings/preferences only
  user_id uuid primary key references users(id) on delete cascade,
  encrypted_blob bytea not null,
  blob_version int not null default 1,
  last_modified_at timestamptz not null default now()
);

create table encrypted_transactions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  account_key uuid not null,             -- references the client-generated account grouping key
  encrypted_blob bytea not null,         -- source field inside: 'manual'|'scan'|'csv'|'plaid'
  transfer_group uuid,                   -- set when both legs of a transfer exist (pairing done client-side)
  tx_date date not null,                 -- deterministic, for range queries/sort only
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz                 -- tombstone: blob zeroed on delete, row kept
);
create index on encrypted_transactions (user_id, tx_date desc);
create index on encrypted_transactions (user_id, created_at desc);  -- cursor pagination

create table encrypted_attachments (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  encrypted_blob bytea not null,         -- DEK-encrypted image/PDF incl. original filename
  mime text not null,
  stored_name text not null,             -- random name; original filename encrypted INSIDE the blob
  created_at timestamptz not null default now()
);

create table encrypted_chat_messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  encrypted_blob bytea not null,         -- role+content encrypted client-side
  created_at timestamptz not null default now()
);

create table audit_log (
  id bigserial primary key,
  user_id uuid references users(id) on delete set null,
  action text not null,                  -- login|vault_sync|ai_query|scan|import
  ip_address inet, user_agent text,
  created_at timestamptz not null default now()
);