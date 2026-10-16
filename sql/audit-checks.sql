-- Security checklist. One row per check: id, what it checks, pass or fail, and the detail
-- an auditor would ask for. Run as a superuser (pg_hba_file_rules and pg_authid need it).
with s as (select name, setting from pg_settings),
login_roles as (select * from pg_authid where rolcanlogin),
secdef as (
  select p.oid::regprocedure::text fn
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where p.prosecdef and n.nspname not in ('pg_catalog', 'information_schema')
    and not exists (select 1 from unnest(coalesce(p.proconfig, '{}')) c where c like 'search_path=%')
),
public_grants as (
  select c.oid::regclass::text tbl, a.privilege_type
  from pg_class c join pg_namespace n on n.oid = c.relnamespace,
       aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
  where n.nspname = 'core' and c.relkind = 'r' and a.grantee = 0
)
select * from (values
  ('C01', 'TLS is on',
   (select setting from s where name = 'ssl') = 'on',
   'ssl = ' || (select setting from s where name = 'ssl')),
  ('C02', 'TLS 1.2 or newer only',
   (select setting from s where name = 'ssl') = 'on'
     and (select setting from s where name = 'ssl_min_protocol_version') in ('TLSv1.2', 'TLSv1.3'),
   'ssl_min_protocol_version = ' || (select setting from s where name = 'ssl_min_protocol_version')),
  ('C03', 'New passwords are hashed with SCRAM',
   (select setting from s where name = 'password_encryption') = 'scram-sha-256',
   'password_encryption = ' || (select setting from s where name = 'password_encryption')),
  ('C04', 'No login role has an MD5 password',
   not exists (select 1 from login_roles where rolpassword like 'md5%'),
   coalesce('md5: ' || (select string_agg(rolname, ', ' order by rolname) from login_roles where rolpassword like 'md5%'), 'none')),
  ('C05', 'Every login role has a password',
   not exists (select 1 from login_roles where rolpassword is null),
   coalesce('no password: ' || (select string_agg(rolname, ', ' order by rolname) from login_roles where rolpassword is null), 'all set')),
  ('C06', 'No trust lines in pg_hba.conf',
   not exists (select 1 from pg_hba_file_rules where auth_method = 'trust'),
   coalesce('trust on lines ' || (select string_agg(line_number::text, ', ') from pg_hba_file_rules where auth_method = 'trust'), 'none')),
  ('C07', 'TCP logins must use TLS',
   not exists (select 1 from pg_hba_file_rules where type = 'host' and auth_method <> 'reject'),
   coalesce('plain host lines ' || (select string_agg(line_number::text, ', ') from pg_hba_file_rules where type = 'host' and auth_method <> 'reject'), 'hostssl only')),
  ('C08', 'Only postgres is a superuser',
   not exists (select 1 from pg_roles where rolsuper and rolname <> 'postgres'),
   coalesce('also superuser: ' || (select string_agg(rolname, ', ') from pg_roles where rolsuper and rolname <> 'postgres'), 'postgres only')),
  ('C09', 'PUBLIC cannot create objects in core',
   not has_schema_privilege('public', 'core', 'create'),
   case when has_schema_privilege('public', 'core', 'create') then 'PUBLIC has CREATE' else 'revoked' end),
  ('C10', 'PUBLIC has no rights on core tables',
   not exists (select 1 from public_grants),
   coalesce((select count(distinct tbl) || ' tables readable by PUBLIC' from public_grants having count(*) > 0), 'none')),
  ('C11', 'Row level security forced on customers and accounts',
   (select bool_and(relrowsecurity and relforcerowsecurity) from pg_class where oid in ('core.customers'::regclass, 'core.accounts'::regclass)),
   (select string_agg(relname || case when relrowsecurity and relforcerowsecurity then ' on' else ' off' end, ', ' order by relname)
      from pg_class where oid in ('core.customers'::regclass, 'core.accounts'::regclass))),
  ('C12', 'National ID is not stored in plain text',
   not exists (select 1 from information_schema.columns where table_schema = 'core' and table_name = 'customers' and column_name = 'national_id'),
   case when exists (select 1 from information_schema.columns where table_schema = 'core' and table_name = 'customers' and column_name = 'national_id')
        then 'core.customers.national_id is text' else 'encrypted with pgcrypto' end),
  ('C13', 'SECURITY DEFINER functions pin search_path',
   not exists (select 1 from secdef),
   coalesce('unpinned: ' || (select string_agg(fn, ', ') from secdef), 'all pinned')),
  ('C14', 'pgaudit loaded, logging DDL and role changes',
   (select setting from s where name = 'shared_preload_libraries') like '%pgaudit%'
     and coalesce(current_setting('pgaudit.log', true), '') ~ 'ddl' and coalesce(current_setting('pgaudit.log', true), '') ~ 'role',
   'pgaudit.log = ' || coalesce(nullif(current_setting('pgaudit.log', true), ''), 'not loaded')),
  ('C15', 'Connections and disconnections are logged',
   (select setting from s where name = 'log_connections') = 'on' and (select setting from s where name = 'log_disconnections') = 'on',
   'log_connections = ' || (select setting from s where name = 'log_connections') || ', log_disconnections = ' || (select setting from s where name = 'log_disconnections')),
  ('C16', 'Change log exists and is append only',
   to_regclass('audit.change_log') is not null and not exists (
     select 1 from pg_roles r where not r.rolsuper and r.rolname !~ '^pg_' and (
       has_table_privilege(r.oid, 'audit.change_log', 'update') or has_table_privilege(r.oid, 'audit.change_log', 'delete')
       or has_table_privilege(r.oid, 'audit.change_log', 'truncate'))),
   case when to_regclass('audit.change_log') is null then 'no change log table' else 'only superusers can change it' end)
) as checks(id, title, pass, detail)
order by id;
