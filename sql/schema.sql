-- A small bank: five branches, 10,000 customers, 20,000 accounts, 100,000 transactions.
create schema core;

create table core.branches (id int primary key, name text not null);
insert into core.branches values (1, 'Male'), (2, 'Hulhumale'), (3, 'Addu'), (4, 'Fuvahmulah'), (5, 'Kulhudhuffushi');

create table core.customers (
  id          bigint primary key,
  branch_id   int  not null references core.branches,
  full_name   text not null,
  national_id text not null unique,     -- plain text for now. 02-harden.sh encrypts it.
  phone       text not null
);
insert into core.customers
select i, 1 + i % 5, 'Customer ' || i, 'A' || lpad((100000 + i)::text, 6, '0'), '7' || lpad(i::text, 6, '0')
from generate_series(1, 10000) i;

create table core.accounts (
  id          bigint primary key,
  customer_id bigint not null references core.customers,
  branch_id   int    not null references core.branches,
  status      text   not null default 'active',
  balance     numeric(14,2) not null default 0
);
insert into core.accounts
select i, 1 + (i - 1) % 10000, 1 + ((i - 1) % 10000 + 1) % 5, 'active', round((random() * 50000)::numeric, 2)
from generate_series(1, 20000) i;

create table core.txns (
  id         bigserial primary key,
  account_id bigint not null references core.accounts,
  posted_at  timestamptz not null default now(),
  amount     numeric(14,2) not null
);
insert into core.txns (account_id, posted_at, amount)
select 1 + (random() * 19999)::int, now() - random() * interval '90 days', round(((random() - 0.5) * 2000)::numeric, 2)
from generate_series(1, 100000);

create or replace function core.transfer(p_from bigint, p_to bigint, p_amount numeric)
returns void language plpgsql as $$
begin
  perform 1 from core.accounts where id in (p_from, p_to) order by id for update;
  update core.accounts set balance = balance - p_amount where id = p_from;
  update core.accounts set balance = balance + p_amount where id = p_to;
  insert into core.txns (account_id, amount) values (p_from, -p_amount), (p_to, p_amount);
end $$;

analyze;
