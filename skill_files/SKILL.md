---
name: health-check
description: "Run a 12-check data governance health check with RAG scoring across data protection, identity and access, and auth and network domains."
---

# Governance Health Check

A 12-check data governance health check for Snowflake. Audits data protection, identity/access, and auth/network controls using ACCOUNT_USAGE views. Outputs a RAG (Red/Amber/Green) scored report with findings and remediation SQL.

## Tools Used

- `snowflake_sql_execute` — run the 12 checks
- `read` — load sub-files from `.cortex/skills/governance-health-check/`
- `ask_user_question` — Phase 0 scoping

## Architecture

```
SKILL.md (this file)        — orchestrator: Phase 0, execution flow, scoring, output
data_protection.md          — Checks 1, 2, 3, 4, 5
identity_access.md          — Checks 6, 7, 8, 9
auth_network.md             — Checks 10, 11, 12
```

Each sub-file contains embedded SQL. Load each with `read`, then execute the SQL checks defined in it.

---

## Workflow

### Phase 0: Environment Discovery


Execute these steps sequentially. Stop on failure where indicated.

**Step 1: Warehouse check**

```sql
SELECT CURRENT_WAREHOUSE();
```

If null, **STOP**: "No warehouse set. Run `USE WAREHOUSE <your_warehouse>;` first."

**Step 2: Role detection**

```sql
SELECT CURRENT_ROLE();
```

Capture the current role name.

**Step 3: Test ACCOUNT_USAGE access**

```sql
SELECT 1 FROM SNOWFLAKE.ACCOUNT_USAGE.USERS LIMIT 1;
```

- If role = `ACCOUNTADMIN`, proceed with full access.
- If role != `ACCOUNTADMIN` but query succeeds, proceed with warning: "Running as `<role>`. Some checks may return incomplete results. ACCOUNTADMIN recommended."
- If query fails, **STOP**: "Your current role does not have access to SNOWFLAKE.ACCOUNT_USAGE. Run `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <your_role>;` or switch to ACCOUNTADMIN."

**Step 4: Test each source**

Test all 8 sources with `SELECT 1 FROM <source> LIMIT 1` (use `SHOW NETWORK POLICIES` for source 8). Replace `<current_role>` below with the role detected in Step 2.

If a source query **fails with a privilege error**, skip checks that depend on it. Mark skipped checks as **Amber** with the source-specific grant SQL:

| # | Source | On failure, show this grant |
|---|--------|----------------------------|
| 1 | `SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT` | `GRANT DATABASE ROLE SNOWFLAKE.DATA_PRIVACY_VIEWER TO ROLE <current_role>;` |
| 2 | `SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 3 | `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 4 | `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 5 | `SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_USERS` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 6 | `SNOWFLAKE.ACCOUNT_USAGE.USERS` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 7 | `SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY` | `GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE <current_role>;` |
| 8 | `SHOW NETWORK POLICIES` | `GRANT CREATE NETWORK POLICY ON ACCOUNT TO ROLE <current_role>;` |

Skip message format: "Skipped — current role lacks access. Fix: `<grant SQL from table above>`"

If a source query **succeeds but returns 0 rows**, that is not an error — it means the object/data does not exist yet. Do NOT skip the check. Instead, proceed with the check and include a source-specific explanation in the findings:

| Source | 0-row message |
|--------|---------------|
| `CLASSIFICATION_RESULT` | "No classification has been run. Run SYSTEM\$CLASSIFY to identify PII columns." |
| `POLICY_REFERENCES` | "No masking or row access policies exist. Create policies using CREATE MASKING POLICY." |
| `TAG_REFERENCES` | "No tags have been applied. Create and apply tags using CREATE TAG and ALTER TABLE." |
| `SHOW NETWORK POLICIES` | "No network policies exist. Create one using CREATE NETWORK POLICY." |
| `GRANTS_TO_ROLES` | No message needed — 0 critical privileges found scores Green. |
| `GRANTS_TO_USERS` | No message needed — evaluated alongside GRANTS_TO_ROLES. |
| `USERS` | No message needed — evaluated for inactive/MFA status. |
| `LOGIN_HISTORY` | No message needed — 0 failed logins scores Green. |

Report coverage: "Health check ran X of 12 checks at Y% coverage. Z checks skipped due to insufficient privileges."

**Step 5: Scope databases for classification (Check 1 only)**

Ask the user: "Which databases should I scope for PII classification? (Check 1 only — all other checks are account-wide.)"

Validate database names exist:

```sql
SHOW DATABASES;
```

If invalid names provided, warn and ask again. If zero tables found in scoped databases, skip classification check and note: "No tables found in specified databases."

**Step 6: Detect account size**

```sql
SELECT
  (SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.USERS WHERE DELETED_ON IS NULL) AS total_users,
  (SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES WHERE DELETED IS NULL AND TABLE_TYPE = 'BASE TABLE') AS total_tables;
```

If <10 users AND <20 tables: add note in report — "Small account detected — thresholds calibrated for larger environments."

---

### Phase 1: Execute Checks

**Step 1: Data Protection domain**

Read `.cortex/skills/governance-health-check/data_protection.md` and execute the SQL checks defined in it (Checks 1, 2, 3, 4, 5).

**Step 2: Identity and Access domain**

Read `.cortex/skills/governance-health-check/identity_access.md` and execute the SQL checks defined in it (Checks 6, 7, 8, 9).

**Step 3: Auth and Network domain**

Read `.cortex/skills/governance-health-check/auth_network.md` and execute the SQL checks defined in it (Checks 10, 11, 12).

---

### Phase 2: Score and Report

#### RAG Scoring Rules

**Per check:**
- **Red** = Critical finding, immediate action required
- **Amber** = Partial coverage or minor gap
- **Green** = No issues found

**Per domain** (worst check wins):
- Data Protection = worst of Checks 1, 2, 3, 4, 5
- Identity and Access = worst of Checks 6, 7, 8, 9
- Auth and Network = worst of Checks 10, 11, 12

**Overall:**
- **Green** = all 3 domains Green
- **Amber** = at least 1 domain Amber, none Red
- **Red** = any domain Red

#### Empty-State Defaults

| Check | Empty means | Default score |
|-------|-------------|---------------|
| 1 | No classification run | **Red** |
| 2 | No policies applied | **Red** |
| 3 | No tags applied | **Red** |
| 4 | No unmasked PII | **Green** (but **Amber** if no classification data) |
| 5 | No untagged PII | **Green** (but **Amber** if no classification data) |
| 6 | No overprivileged roles | **Green** |
| 7 | No humans on admin roles | **Green** |
| 8 | No inactive/MFA-less users | **Green** |
| 9 | No risky combo | **Green** |
| 10 | No failed logins | **Green** |
| 11 | No network policies | **Red** |
| 12 | No failed-login + no-policy combo | **Green** |

---

## Error Handling

- If a check fails, **retry once**. If it fails again, skip it and continue.
- Mark skipped checks as **Amber** with reason.
- Report coverage % at the top of the report.
- If persistent connection failure, **STOP**: "Unable to connect to Snowflake. Check your session and try again."

---

## Output Format

### 1. Executive Summary (printed in conversation)

One paragraph: overall RAG score, how many domains have findings, top 1-2 priorities.

### 2. Detailed Report (saved to file)

Save to **project root** (working directory), NOT inside the skill folder. Filename: `health_check_report_YYYY-MM-DD_HH-MM.md`

Report structure:

Use inline HTML spans for RAG scores so they render as colored badges in the PDF.
The CSS file at `.cortex/skills/governance-health-check/report-style.css` styles these spans.

RAG score markup:
- Red: `<span class="red">RED</span>`
- Amber: `<span class="amber">AMBER</span>`
- Green: `<span class="green">GREEN</span>`

Wrap sections in styled `<div>` elements for PDF rendering (these are invisible in plain markdown viewers).

```markdown
# Data Governance Health Check Report

<div class="confidential">

**CONFIDENTIAL**: This report contains security posture information. Do not share outside your security or governance team.

</div>

<div class="metadata">

**Generated:** YYYY-MM-DD HH:MM UTC

**Role:** <current_role>

**Coverage:** X of 12 checks ran (Y%)

**Data sourced from ACCOUNT_USAGE views, which may have up to 3 hours of latency.**

</div>

## Overall Score: <span class="red">RED</span>

[Executive summary paragraph — describe the key gaps found across all three domains.]

**Top priorities:**

- [Highest priority action item]
- [Second priority action item]

### Scorecard

| # | Check | Domain | Score |
|---|-------|--------|-------|
| 1 | PII Classification Coverage | Data Protection | <span class="red">RED</span> |
| 2 | Masking & Row Access Policy Coverage | Data Protection | <span class="red">RED</span> |
| 3 | Tag Coverage | Data Protection | <span class="red">RED</span> |
| 4 | PII Classified but Unmasked | Data Protection | <span class="amber">AMBER</span> |
| 5 | PII Classified but Untagged | Data Protection | <span class="amber">AMBER</span> |
| 6 | Privilege Distribution — Overprivileged Roles | Identity & Access | <span class="amber">AMBER</span> |
| 7 | Humans with Powerful Roles | Identity & Access | <span class="amber">AMBER</span> |
| 8 | Inactive Users & MFA Disabled | Identity & Access | <span class="green">GREEN</span> |
| 9 | Inactive Users with Powerful Roles | Identity & Access | <span class="green">GREEN</span> |
| 10 | Failed Login Patterns | Auth & Network | <span class="amber">AMBER</span> |
| 11 | Network Policy Existence & Application | Auth & Network | <span class="amber">AMBER</span> |
| 12 | Failed Logins + No Network Policy | Auth & Network | <span class="amber">AMBER</span> |

(Populate using actual check names and RAG scores from the run. The example above is illustrative.)

---

<div class="domain-red">

## Data Protection <span class="red">RED</span>

### Check 1: PII Classification Coverage <span class="red">RED</span>
**Summary:** X of Y tables classified (Z%)
**Findings:**
- [Specific table/column names that triggered the finding]
**What this means:** [1-sentence plain English explanation]
**Remediation:**
```sql
[Exact SQL command to fix]
```

### Check 2: ...
[Same format for each check]

### Check 3: ...
### Check 4: ...
### Check 5: ...

</div>

---

<div class="domain-amber">

## Identity and Access <span class="amber">AMBER</span>

### Check 6: ...
### Check 7: ...
### Check 8: ...
### Check 9: ...

</div>

---

<div class="domain-green">

## Auth and Network <span class="green">GREEN</span>

### Check 10: ...
### Check 11: ...
### Check 12: ...

</div>

---

## Prioritized Recommendations

Ranked by risk (Red items first, then Amber):

1. <span class="red">RED</span> [Highest priority recommendation]
2. <span class="amber">AMBER</span> [Second priority]
...
```

**Important:** Choose the correct `domain-red`, `domain-amber`, or `domain-green` div class based on the domain's worst check score. The examples above show one of each for illustration.

### Markdown Formatting Rules (critical for PDF rendering)

These rules MUST be followed or the PDF will render incorrectly:

1. **Escape `$` in prose text.** Pandoc's TeX math parser treats `$` as a math delimiter. In prose text (outside ``` code blocks), always escape as `\$`. Example: write `SYSTEM\$CLASSIFY`, not `SYSTEM$CLASSIFY`. Inside fenced code blocks, `$` is safe and should NOT be escaped.

2. **Blank line between each sub-section.** Each `**Summary:**`, `**Findings:**`, `**What this means:**`, and `**Remediation:**` label must be preceded by a blank line. Without blank lines, markdown renders them as a single continuous paragraph in the PDF. Correct:
   ```
   **Summary:** 0 of 5 tables classified

   **Findings:**
   - No classification run

   **What this means:** ...

   **Remediation:**
   ```

3. **Blank lines around `<div>` tags.** Pandoc requires blank lines before and after `<div>` and `</div>` tags for the content inside to be parsed as markdown.

### 3. PDF Conversion

After generating the .md report, convert it to PDF. The skill must automatically install missing dependencies — do not ask the user to install them manually.

**Step 1: Detect platform**

```bash
uname -s
```

This returns `Darwin` (macOS) or `Linux`.

**Step 2: Ensure pandoc is installed**

```bash
which pandoc
```

If pandoc is NOT found:
- **macOS**: Run `brew install pandoc`. If `brew` is not available, try `conda install -y -c conda-forge pandoc`.
- **Linux**: Run `sudo apt-get install -y pandoc`. If apt is not available, try `conda install -y -c conda-forge pandoc`.
- If all install attempts fail, skip to Step 5 (fallback).

**Step 3: Ensure weasyprint is installed**

```bash
which weasyprint
```

If weasyprint is NOT found:
- Try `pip install weasyprint`
- If that fails, try `pip3 install weasyprint`
- If both fail, skip to Step 5 (fallback).

**Step 4: Generate PDF**

```bash
pandoc health_check_report_YYYY-MM-DD_HH-MM.md \
  -o health_check_report_YYYY-MM-DD_HH-MM.pdf \
  --pdf-engine=weasyprint \
  --css=.cortex/skills/governance-health-check/report-style.css
```

If the command succeeds, report: "PDF saved to `health_check_report_YYYY-MM-DD_HH-MM.pdf`."

**Step 5: Fallback (only if install failed)**

If pandoc or weasyprint could not be installed, skip PDF generation and tell the user:

> PDF generation skipped — missing dependencies. Install them and convert manually:
> ```
> brew install pandoc          # macOS (or: sudo apt-get install pandoc)
> pip install weasyprint
> pandoc health_check_report_YYYY-MM-DD_HH-MM.md -o health_check_report_YYYY-MM-DD_HH-MM.pdf --pdf-engine=weasyprint --css=.cortex/skills/governance-health-check/report-style.css
> ```

### Each finding must include:

1. RAG score
2. Summary count (e.g., "8 of 12 PII columns unmasked")
3. Specific items: exact table names, column names, user names, role names
4. Plain English: what is wrong and why it matters (1 sentence)
5. Remediation SQL: exact command to fix it

---

## Stopping Points

- **Phase 0 Step 1**: If no warehouse set — STOP with remediation
- **Phase 0 Step 3**: If ACCOUNT_USAGE inaccessible — STOP with remediation
- **Phase 0 Step 5**: Confirm scoped databases before proceeding
- **Check 1**: If no classification data, ask user about running SYSTEM$CLASSIFY

**Resume rule:** On approval, proceed directly to next step without re-asking.

---

## Notes

- All queries filter deleted objects with `WHERE DELETED IS NULL` (or `DELETED_ON IS NULL`) where applicable.
- Each check runs its own SQL independently — no state is passed between checks.
- Use fully qualified table names.
- ACCOUNT_USAGE latency is up to 3 hours depending on view.
