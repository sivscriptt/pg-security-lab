-- The bad habits. Every line here is something the audit check should catch.

-- The app logs in as a superuser "because it was easier".
create role app login superuser password 'app123';

-- One shared login for every teller, with full rights on every table.
create role teller1 login password 'teller1';
grant usage on schema core to teller1;
grant all on all tables in schema core to teller1;

-- Anyone who can connect can read everything and create objects in the schema.
grant usage, create on schema core to public;
grant select on all tables in schema core to public;

-- A SECURITY DEFINER helper with no search_path. A caller who can create objects
-- can shadow a function it calls and run code as the owner.
create function core.customer_count(p_branch int) returns bigint
language sql security definer as $$ select count(*) from core.customers where branch_id = p_branch $$;
