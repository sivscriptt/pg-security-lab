# pg-security-lab

Most of the security work in DBA job posts is access control, encryption and supporting
audits. I wanted to practise all three on one server. So the lab starts from a server set
up the quick way, runs an audit checklist against it, fixes every finding, and then tries
to get around each fix.

It runs PostgreSQL 17 with pgaudit (built from source) and pgcrypto on my laptop.

## The starting point

`01-init.sh` builds the kind of server I've seen plenty of:

- trust logins and MD5 passwords
- no TLS
- the app logs in as a superuser
- one shared login for every teller
- everyone can read every table and create objects in the schema
- a SECURITY DEFINER function with no search_path
- national ID numbers stored as plain text

## The checklist

`audit-check.sh` runs 16 checks and prints PASS or FAIL, with the detail an auditor would
ask for. It exits 1 if anything fails, so it could gate a pipeline.

    Before: 1 passed, 15 failed
    After:  16 passed, 0 failed

Checks: TLS on and 1.2+, SCRAM passwords, no MD5 hashes left, no trust lines, TCP must
use TLS, only one superuser, nothing granted to PUBLIC, row level security on, national
ID encrypted, SECURITY DEFINER functions pin search_path, pgaudit loaded, connections
logged, and the change log is append only.

## The fixes

`02-harden.sh`:

- **Logins.** SCRAM for every password, new random passwords, and a pg_hba.conf that
  only allows TLS over TCP. A private CA signs the server certificate, so clients can
  use `verify-full`.
- **Roles.** Group roles hold the rights, and logins only hold membership. The app can't
  UPDATE balances at all. It can only call `core.transfer`.
- **Row level security.** A teller only sees customers and accounts in their own branch.
- **Encryption.** National IDs are encrypted with pgcrypto. The key is never stored in
  the database, so a stolen backup is only ciphertext. A keyed hash still lets tellers
  find a customer by ID without decrypting anything.
- **Audit trail.** Triggers write every account change to `audit.change_log`, which
  nobody except a superuser can edit. Every time someone decrypts an ID, a row goes into
  `audit.pii_access`, and it needs a reason.
- **pgaudit.** Logs all DDL and role changes, plus every read of the customers table by
  anyone.

## Proving it

The checklist only reads settings. `03-prove.sh` logs in as each user over the network
and tries things that should fail. 25 tests, all passing:

    PASS  TCP without TLS is refused                  no encryption
    PASS  teller_male sees only branch 1              1|2000
    PASS  A teller can't read the encrypted ID column permission denied
    PASS  kyc1 can reveal an ID with the key and a reason
    PASS  ...and the look is logged in audit.pii_access
    PASS  app can't UPDATE balances directly          permission denied
    PASS  Even audit can't edit the change log        permission denied
    PASS  The password in CREATE ROLE is redacted     password <REDACTED>
    ...

The last one surprised me. I expected to have to keep passwords out of the log myself,
but pgaudit already replaces them with `<REDACTED>`.

## Running it

    ./scripts/01-init.sh               # the insecure server
    ./scripts/audit-check.sh before
    ./scripts/02-harden.sh
    ./scripts/audit-check.sh after
    ./scripts/03-prove.sh
    ./scripts/teardown.sh

## What's missing

- The decryption key is passed as a function argument, so it shows in
  pg_stat_activity while the call runs. A real setup would keep it in a key vault or
  encrypt in the app.
- The certificates are self-signed by a lab CA, not a real one.
- Encrypting 10,000 IDs takes about 20 seconds because pgcrypto derives the key for
  every row. That's fine once, but too slow for a big migration.
