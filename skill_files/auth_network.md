# Auth and Network Domain

Checks 10, 11, 12. Execute each check's SQL independently via `snowflake_sql_execute`. Check 12 is a cross-reference of Check 10 and Check 11 results.

---

## Check 10: Failed Login Patterns

**Risk type:** Security  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`

### Step 1: Count failed logins in last 30 days

```sql
SELECT COUNT(*) AS failed_login_count
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE IS_SUCCESS = 'NO'
  AND EVENT_TIMESTAMP >= DATEADD('day', -30, CURRENT_TIMESTAMP());
```

### Step 2: Detect patterns

```sql
SELECT
  USER_NAME,
  CLIENT_IP,
  ERROR_MESSAGE,
  COUNT(*) AS failure_count,
  MIN(EVENT_TIMESTAMP) AS first_failure,
  MAX(EVENT_TIMESTAMP) AS last_failure
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE IS_SUCCESS = 'NO'
  AND EVENT_TIMESTAMP >= DATEADD('day', -30, CURRENT_TIMESTAMP())
GROUP BY USER_NAME, CLIENT_IP, ERROR_MESSAGE
ORDER BY failure_count DESC;
```

### Step 3: Identify suspicious patterns

Classify the failure pattern as **suspicious** or **operational noise**:

**Suspicious** (score Red):
- Same IP targets multiple different users (credential stuffing)
- Failures spread across many different IPs for one user (distributed brute force)
- Sustained high-volume failures with password-related errors (INCORRECT_USERNAME_PASSWORD)

**Operational noise** (score Amber even if 11+ failures):
- Failures concentrated on a single user or small number of known users
- Benign error types only: OAUTH_ACCESS_TOKEN_EXPIRED, TOTP_INVALID_CODE_REMAINING_ATTEMPTS, SECOND_FACTOR_AUTHENTICATION_REQUIRED
- Single IP or small number of known IPs

### Scoring

| Condition | Score |
|-----------|-------|
| 0 failures | **Green** |
| 1-10 failures, no suspicious pattern | **Amber** |
| 11+ failures, operational noise pattern (single user, known IPs, benign errors only) | **Amber** — "High volume but benign — no credential stuffing or brute-force indicators detected" |
| Any suspicious pattern detected (credential stuffing, distributed brute force, password attacks) | **Red** |
| Empty | **Green** — "No failed logins in last 30 days" |

---

## Check 11: Network Policy Existence and Application

**Risk type:** Exposure  
**Sources:** `SHOW NETWORK POLICIES`, `SHOW PARAMETERS`

### Step 1: Check if any network policy exists

```sql
SHOW NETWORK POLICIES;
```

If this returns rows, at least one network policy exists.

### Step 2: Check if a network policy is applied at account level

```sql
SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT;
```

Check the `value` column. If non-empty, a policy is applied at account level.

### Step 3: Handle privilege failures

If either SHOW command fails due to insufficient privileges, mark **Amber** with: "Skipped — insufficient privileges to check network policies."

### Scoring

| Condition | Score |
|-----------|-------|
| Policy exists AND applied to account | **Green** |
| Policy exists but NOT applied to account | **Amber** |
| No policy exists | **Red** |
| SHOW command fails (privilege issue) | **Amber** — "Skipped — insufficient privileges to check network policies" |

---

## Check 12: Cross-ref Exposure Risk — Failed Logins + No Network Policy

**Risk type:** Exposure  
**Sources:** Check 10 results + Check 11 results (from `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY`, `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES`, `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS`)

This is a cross-reference check. Use the results from Check 10 (failed login count) and Check 11 (network policy status). No additional SQL needed — evaluate from prior results.

The framing: "You are being probed AND the door is unlocked."

### Evaluation logic

```
failed_logins = (Check 10 failed_login_count > 0)
policy_applied = (Check 11 = Green)

If Check 10 = Green (no failed logins):
  → Check 12 = Green (automatically)

If failed_logins AND policy_applied:
  → Amber — "Probing detected but mitigated by network policy"

If failed_logins AND NOT policy_applied:
  → Red — "Failed login attempts detected with no network policy applied"

If NOT failed_logins AND NOT policy_applied:
  → Green (no active threat, but Check 11 already flags the missing policy)
```

### Scoring

| Condition | Score |
|-----------|-------|
| Network policy applied OR no failed logins | **Green** |
| Failed logins exist but network policy is applied | **Amber** — "Probing detected but mitigated" |
| Failed logins exist AND no network policy applied | **Red** — "Active probing with no network protection" |
| Check 10 = Green (no failed logins) | **Green** (automatic) |
| Empty | **Green** |
