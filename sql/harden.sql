-- Hardening, run by scripts/02-harden.sh as postgres with -v pii_key=.. -v hash_key=..
-- Each block maps to a check in sql/audit-checks.sql.
\set ON_ERROR_STOP on
begin;

-- ---- Undo the bad habits (C08, C09, C10, C13) ---------------------------------------------
alter role app nosuperuser;
revoke all on all tables in schema core from public, app;
revoke create, usage on schema core from public;
revoke execute on all functions in schema core from public;   -- functions are executable by PUBLIC by default
drop owned by teller1;
drop role teller1;                                            -- shared logins can't be audited to a person
drop function core.customer_count(int);

-- ---- Roles: groups hold the rights, logins hold nothing but membership ----------------------
create role app_rw      nologin;    -- the application
create role teller      nologin;    -- branch staff, their own branch only
create role kyc_officer nologin;    -- may see a national ID, and every look is logged
create role audit_reader nologin;   -- internal audit, read only on the audit schema
create role auditor     nologin;    -- not for people: pgaudit.role, see below
grant app_rw to app;
create role teller_male login in role teller;
create role teller_addu login in role teller;
create role kyc1        login in role kyc_officer;
create role auditor1    login in role audit_reader;

-- The app gets no direct UPDATE. It can read, and move money only through core.transfer.
grant usage on schema core to app_rw, teller, kyc_officer;
grant select on core.accounts, core.txns, core.branches to app_rw;
alter function core.transfer(bigint, bigint, numeric) security definer set search_path = pg_catalog, core;
grant execute on function core.transfer(bigint, bigint, numeric) to app_rw;

-- Tellers: names and phones of customers, and accounts. No national ID column at all.
grant select (id, branch_id, full_name, phone) on core.customers to teller;
grant select on core.accounts, core.branches to teller;

-- ---- Row level security: a teller sees their own branch (C11) -------------------------------
create schema sec;
revoke all on schema sec from public;
create table sec.staff (login name primary key, branch_id int not null references core.branches);
insert into sec.staff values ('teller_male', 1), ('teller_addu', 3);
create function sec.my_branch() returns int
language sql stable security definer set search_path = pg_catalog, sec
as $$ select branch_id from sec.staff where login = session_user $$;
grant usage on schema sec to teller;
grant execute on function sec.my_branch() to teller;

alter table core.customers enable row level security;
alter table core.customers force row level security;
alter table core.accounts  enable row level security;
alter table core.accounts  force row level security;
create policy teller_own_branch on core.customers for select to teller using (branch_id = sec.my_branch());
create policy teller_own_branch on core.accounts  for select to teller using (branch_id = sec.my_branch());
create policy app_all on core.accounts for select to app_rw using (true);

-- ---- National ID encrypted at rest with pgcrypto (C12) --------------------------------------
-- national_id_enc: PGP symmetric encryption. The key is never stored in the database; the
--   KYC app passes it per call. A stolen backup holds ciphertext only.
-- national_id_hash: keyed HMAC, so staff can find a customer by ID without decrypting anything.
--   That key lives in sec.settings, readable only by the owner.
create extension pgcrypto schema sec;
create table sec.settings (name text primary key, value text not null);
insert into sec.settings values ('nid_hash_key', :'hash_key');

alter table core.customers add column national_id_enc bytea, add column national_id_hash bytea;
update core.customers
   set national_id_enc  = sec.pgp_sym_encrypt(national_id, :'pii_key', 'cipher-algo=aes256'),
       national_id_hash = sec.hmac(national_id, :'hash_key', 'sha256');
alter table core.customers alter national_id_enc set not null, alter national_id_hash set not null;
alter table core.customers drop column national_id;
create unique index customers_nid_hash_idx on core.customers (national_id_hash);

-- ---- Audit trail: append only, written by triggers (C16) ------------------------------------
create schema audit;
revoke all on schema audit from public;
create table audit.change_log (
  id       bigserial primary key,
  at       timestamptz not null default clock_timestamp(),
  db_user  name not null default session_user,
  tbl      text not null,
  op       text not null,
  row_id   bigint,
  old_row  jsonb,
  new_row  jsonb
);
create table audit.pii_access (
  id          bigserial primary key,
  at          timestamptz not null default clock_timestamp(),
  db_user     name not null default session_user,
  customer_id bigint not null,
  reason      text not null
);
grant usage on schema audit to audit_reader;
grant select on all tables in schema audit to audit_reader;

create function audit.log_change() returns trigger
language plpgsql security definer set search_path = pg_catalog, audit as $$
begin
  insert into audit.change_log (tbl, op, row_id, old_row, new_row)
  values (tg_table_name, tg_op,
          case when tg_op = 'DELETE' then old.id else new.id end,
          case when tg_op <> 'INSERT' then to_jsonb(old) end,
          case when tg_op <> 'DELETE' then to_jsonb(new) end);
  return null;
end $$;
create trigger accounts_audit after insert or update or delete on core.accounts
  for each row execute function audit.log_change();

-- Teller lookup by national ID: hashes the input, answers only inside their branch.
create function core.find_customer(p_nid text) returns bigint
language sql stable security definer set search_path = pg_catalog, core, sec as $$
  select c.id from core.customers c
  where c.national_id_hash = sec.hmac(p_nid, (select value from sec.settings where name = 'nid_hash_key'), 'sha256')
    and c.branch_id = sec.my_branch()
$$;
grant execute on function core.find_customer(text) to teller;

-- KYC reveal: needs the key, needs a reason, and leaves a row in audit.pii_access every time.
create function core.reveal_national_id(p_customer bigint, p_key text, p_reason text) returns text
language plpgsql security definer set search_path = pg_catalog, core, sec, audit as $$
declare v text;
begin
  if coalesce(trim(p_reason), '') = '' then raise exception 'a reason is required'; end if;
  insert into audit.pii_access (customer_id, reason) values (p_customer, p_reason);
  select sec.pgp_sym_decrypt(national_id_enc, p_key) into v from core.customers where id = p_customer;
  return v;
end $$;
revoke execute on function core.reveal_national_id(bigint, text, text) from public;
grant execute on function core.reveal_national_id(bigint, text, text) to kyc_officer;

-- ---- pgaudit object audit: any read of customers is logged, by anyone (C14) ------------------
-- pgaudit.role = 'auditor'. Whatever auditor is granted on, pgaudit logs.
grant select on core.customers to auditor;
grant select, update, delete on core.accounts to auditor;

commit;
