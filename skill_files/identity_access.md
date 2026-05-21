# Identity and Access Domain

Checks 6, 7, 8, 9. Execute each check's SQL independently via `snowflake_sql_execute`. Use `DELETED_ON IS NULL` for GRANTS_TO_ROLES and GRANTS_TO_USERS views; use `DELETED_ON IS NULL` for USERS view.

---

## Check 6: Privilege Distribution — Overprivileged Roles

**Risk type:** Access  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES`

### Step 1: Identify admin roles (built-in + custom inheritors)

Trace the role hierarchy to find custom roles that inherit from admin roles.

```sql
WITH RECURSIVE admin_hierarchy AS (
  -- Seed: built-in admin roles
  SELECT GRANTEE_NAME AS role_name, GRANTEE_NAME AS inherited_from, 0 AS depth
  FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
  WHERE GRANTED_ON = 'ROLE'
    AND GRANTEE_NAME IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'ORGADMIN')
    AND DELETED_ON IS NULL
  GROUP BY GRANTEE_NAME

  UNION ALL

  -- Recurse: roles that have been granted an admin role
  SELECT gr.GRANTEE_NAME, ah.role_name AS inherited_from, ah.depth + 1
  FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES gr
  JOIN admin_hierarchy ah ON gr.NAME = ah.role_name
  WHERE gr.GRANTED_ON = 'ROLE'
    AND gr.DELETED_ON IS NULL
    AND ah.depth < 10
)
SELECT DISTINCT role_name, inherited_from
FROM admin_hierarchy
WHERE role_name NOT IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'ORGADMIN');
```

### Step 2: Find non-admin roles with critical/notable privileges

```sql
SELECT
  GRANTEE_NAME AS role_name,
  PRIVILEGE,
  GRANTED_ON,
  NAME AS granted_on_name,
  CASE
    WHEN PRIVILEGE IN ('MANAGE GRANTS', 'CREATE USER', 'CREATE ROLE') THEN 'CRITICAL'
    WHEN PRIVILEGE IN ('CREATE DATABASE', 'CREATE WAREHOUSE', 'MONITOR USAGE') THEN 'NOTABLE'
  END AS risk_level
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES
WHERE PRIVILEGE IN (
    'MANAGE GRANTS', 'CREATE USER', 'CREATE ROLE',
    'CREATE DATABASE', 'CREATE WAREHOUSE', 'MONITOR USAGE'
  )
  AND GRANTEE_NAME NOT IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'ORGADMIN')
  AND DELETED_ON IS NULL
ORDER BY risk_level, GRANTEE_NAME;
```

### Step 3: Combine

Merge results from Step 1 (custom roles inheriting admin) and Step 2 (roles with dangerous privileges). Flag the risk — do not judge intent. List: role name, privilege, why flagged.

- Critical (Red-level): `MANAGE GRANTS`, `CREATE USER`, `CREATE ROLE`, inherits from admin role
- Notable (Amber-level): `CREATE DATABASE`, `CREATE WAREHOUSE`, `MONITOR USAGE`

### Scoring

| Condition | Score |
|-----------|-------|
| Only built-in admin roles hold critical privileges | **Green** |
| 1-2 custom roles hold critical privileges | **Amber** |
| 3+ custom roles hold critical privileges OR unexpected admin inheritance | **Red** |
| No overprivileged roles found (empty) | **Green** — "No overprivileged roles found" |

---

## Check 7: Humans with Powerful Roles

**Risk type:** Access  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`, `SNOWFLAKE.ACCOUNT_USAGE.USERS`

### Step 1: Get users with powerful roles

Powerful roles = ACCOUNTADMIN, SECURITYADMIN, SYSADMIN, ORGADMIN + custom roles inheriting from them (use admin_hierarchy from Check 6).

```sql
SELECT
  gu.GRANTEE_NAME AS user_name,
  gu.ROLE AS role_name,
  u.HAS_PASSWORD,
  u.HAS_RSA_PUBLIC_KEY,
  CASE
    WHEN u.HAS_PASSWORD = TRUE AND (u.HAS_RSA_PUBLIC_KEY = FALSE OR u.HAS_RSA_PUBLIC_KEY IS NULL)
      THEN 'Likely Human'
    WHEN u.HAS_RSA_PUBLIC_KEY = TRUE
      THEN 'Likely Service Account'
    ELSE 'Unknown'
  END AS account_type
FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS gu
JOIN SNOWFLAKE.ACCOUNT_USAGE.USERS u
  ON gu.GRANTEE_NAME = u.NAME
  AND u.DELETED_ON IS NULL
WHERE gu.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'ORGADMIN')
  AND gu.DELETED_ON IS NULL
ORDER BY account_type, gu.ROLE;
```

### Step 2: Flag all users — let user decide

Report ALL users with powerful roles. Label each as "Likely Human" or "Likely Service Account". Do not filter — the user decides what is appropriate.

### Scoring

Count only "Likely Human" users:

| Condition | Score |
|-----------|-------|
| 0 likely humans on powerful roles | **Green** |
| 1-2 likely humans | **Amber** |
| 3+ likely humans | **Red** |
| Empty (no users with powerful roles) | **Green** |

---

## Check 8: Inactive Users and MFA Disabled

**Risk type:** Security  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.USERS`

### Step 1: Find inactive users (no login in 90 days)

```sql
SELECT
  NAME AS user_name,
  LAST_SUCCESS_LOGIN,
  DATEDIFF('day', LAST_SUCCESS_LOGIN, CURRENT_TIMESTAMP()) AS days_inactive,
  CREATED_ON,
  HAS_PASSWORD,
  HAS_RSA_PUBLIC_KEY
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE DELETED_ON IS NULL
  AND (LAST_SUCCESS_LOGIN IS NULL OR LAST_SUCCESS_LOGIN < DATEADD('day', -90, CURRENT_TIMESTAMP()))
ORDER BY LAST_SUCCESS_LOGIN ASC NULLS FIRST;
```

### Step 2: Find users without MFA or with MFA bypass

```sql
SELECT
  NAME AS user_name,
  HAS_MFA,
  BYPASS_MFA_UNTIL,
  HAS_PASSWORD,
  HAS_RSA_PUBLIC_KEY,
  LAST_SUCCESS_LOGIN,
  CASE
    WHEN HAS_MFA = FALSE THEN 'MFA Disabled'
    WHEN BYPASS_MFA_UNTIL IS NOT NULL AND BYPASS_MFA_UNTIL > CURRENT_TIMESTAMP() THEN 'MFA Bypass Active'
    ELSE 'MFA OK'
  END AS mfa_status
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE DELETED_ON IS NULL
  AND (HAS_MFA = FALSE OR (BYPASS_MFA_UNTIL IS NOT NULL AND BYPASS_MFA_UNTIL > CURRENT_TIMESTAMP()))
ORDER BY mfa_status, NAME;
```

Report total counts for context (e.g., "8 of 8 users lack MFA").

### Scoring

Count combined (inactive users + users without MFA). Flag MFA bypass as Amber separately.

| Condition | Score |
|-----------|-------|
| 0 inactive or MFA-less users | **Green** |
| 1-2 found OR MFA bypass configured | **Amber** |
| 3+ found | **Red** |
| Empty | **Green** |

---

## Check 9: Cross-ref Access Risk — Inactive Users with Powerful Roles

**Risk type:** Access  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.USERS`, `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`

Join inactive users (90+ days no login) with powerful role holders.

```sql
SELECT
  u.NAME AS user_name,
  u.LAST_SUCCESS_LOGIN,
  DATEDIFF('day', u.LAST_SUCCESS_LOGIN, CURRENT_TIMESTAMP()) AS days_inactive,
  gu.ROLE AS powerful_role
FROM SNOWFLAKE.ACCOUNT_USAGE.USERS u
JOIN SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS gu
  ON u.NAME = gu.GRANTEE_NAME
  AND gu.DELETED_ON IS NULL
WHERE u.DELETED_ON IS NULL
  AND (u.LAST_SUCCESS_LOGIN IS NULL OR u.LAST_SUCCESS_LOGIN < DATEADD('day', -90, CURRENT_TIMESTAMP()))
  AND gu.ROLE IN ('ACCOUNTADMIN', 'SECURITYADMIN', 'SYSADMIN', 'ORGADMIN')
ORDER BY days_inactive DESC NULLS FIRST;
```

### Scoring

| Condition | Score |
|-----------|-------|
| 0 found | **Green** |
| 1 found | **Amber** |
| 2+ found | **Red** |
| Empty | **Green** |
