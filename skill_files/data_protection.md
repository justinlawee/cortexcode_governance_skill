# Data Protection Domain

Checks 1, 2, 3, 4, 5. Execute each check's SQL independently via `snowflake_sql_execute`. Replace `<SCOPED_DBS>` with the comma-separated list of database names from Phase 0.

---

## Check 1: PII Classification Coverage

**Risk type:** Compliance  
**Sources:** `SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT`

### Step 1: Query classification results

```sql
SELECT
  TABLE_CATALOG AS database_name,
  TABLE_SCHEMA AS schema_name,
  TABLE_NAME AS table_name,
  COLUMN_NAME,
  CLASSIFICATION_TAG_NAME,
  CLASSIFICATION_TAG_VALUE,
  CLASSIFICATION_TIMESTAMP
FROM SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT
WHERE TABLE_CATALOG IN (<SCOPED_DBS>)
ORDER BY CLASSIFICATION_TIMESTAMP DESC;
```

### Step 2: Count classified vs total tables

```sql
SELECT COUNT(DISTINCT TABLE_CATALOG || '.' || TABLE_SCHEMA || '.' || TABLE_NAME) AS classified_tables
FROM SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT
WHERE TABLE_CATALOG IN (<SCOPED_DBS>);
```

```sql
SELECT COUNT(*) AS total_tables
FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
WHERE TABLE_CATALOG IN (<SCOPED_DBS>)
  AND TABLE_SCHEMA != 'INFORMATION_SCHEMA'
  AND TABLE_TYPE = 'BASE TABLE'
  AND DELETED IS NULL;
```

### Step 3: Check staleness

From the first query, capture `MAX(CLASSIFICATION_TIMESTAMP)`. If older than 90 days, add warning:
> Classification data is X days old and may not reflect current table contents. Consider re-running SYSTEM$CLASSIFY.

### Step 4: Handle empty state

If CLASSIFICATION_RESULT returns 0 rows:
- Ask user: "No classification data found. Would you like to run SYSTEM$CLASSIFY on the scoped databases? Note: this uses compute and may take time on large databases."
- If user declines, mark **Red** with recommendation: "Run SYSTEM$CLASSIFY to identify PII columns."
- If user accepts, run for each scoped database/schema:
  ```sql
  SELECT SYSTEM$CLASSIFY('<database>.<schema>.<table>', {'auto_tag': true});
  ```

### Scoring

| Condition | Score |
|-----------|-------|
| >80% of tables classified | **Green** |
| 50-80% classified | **Amber** |
| <50% classified | **Red** |
| No classification ever run | **Red** — "No classification ever run" |

---

<!-- This check is account-wide. It does not use the database scope from Step 5. -->
## Check 2: Masking and Row Access Policy Coverage

**Risk type:** Security  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES`

### Step 1: Count masking policies applied

```sql
SELECT
  REF_DATABASE_NAME,
  REF_SCHEMA_NAME,
  REF_ENTITY_NAME AS table_name,
  REF_COLUMN_NAME AS column_name,
  POLICY_NAME
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'MASKING_POLICY'
  AND POLICY_STATUS = 'ACTIVE'
ORDER BY REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME;
```

```sql
SELECT COUNT(DISTINCT REF_DATABASE_NAME || '.' || REF_SCHEMA_NAME || '.' || REF_ENTITY_NAME || '.' || REF_COLUMN_NAME) AS masked_columns
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'MASKING_POLICY'
  AND POLICY_STATUS = 'ACTIVE';
```

### Step 2: Count row access policies applied

```sql
SELECT
  REF_DATABASE_NAME,
  REF_SCHEMA_NAME,
  REF_ENTITY_NAME AS table_name,
  POLICY_NAME
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'ROW_ACCESS_POLICY'
  AND POLICY_STATUS = 'ACTIVE'
ORDER BY REF_DATABASE_NAME, REF_SCHEMA_NAME, REF_ENTITY_NAME;
```

```sql
SELECT COUNT(DISTINCT REF_DATABASE_NAME || '.' || REF_SCHEMA_NAME || '.' || REF_ENTITY_NAME) AS tables_with_rap
FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES
WHERE POLICY_KIND = 'ROW_ACCESS_POLICY'
  AND POLICY_STATUS = 'ACTIVE';
```

### Step 3: Evaluate against classification

Report masking and row access policies **separately**.

- If no classification data exists (Check 1 = Red/no data): report only counts — "X masking policies and Y row access policies exist" — and mark **Amber** with message: "Cannot evaluate coverage against sensitive columns — no classification data."
- If classification data exists: compare masked columns against classified-as-sensitive columns to compute coverage %.

### Scoring

| Condition | Score |
|-----------|-------|
| All sensitive columns masked | **Green** |
| >50% masked OR no classification data to evaluate | **Amber** |
| <50% masked or none | **Red** |
| No policies applied anywhere | **Red** — "No policies applied anywhere" |

---

<!-- This check is account-wide. It does not use the database scope from Step 5. -->
## Check 3: Tag Coverage

**Risk type:** Compliance  
**Sources:** `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES`

### Part A: PII tables tagged

```sql
SELECT DISTINCT
  cr.TABLE_CATALOG || '.' || cr.TABLE_SCHEMA || '.' || cr.TABLE_NAME AS pii_table,
  CASE WHEN tr.OBJECT_NAME IS NOT NULL THEN 'Tagged' ELSE 'Not Tagged' END AS tag_status
FROM SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT cr
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
  ON cr.TABLE_CATALOG = tr.OBJECT_DATABASE
  AND cr.TABLE_SCHEMA = tr.OBJECT_SCHEMA
  AND cr.TABLE_NAME = tr.OBJECT_NAME
  AND tr.DOMAIN = 'TABLE'
  AND tr.OBJECT_DELETED IS NULL
WHERE cr.TABLE_CATALOG IN (<SCOPED_DBS>);
```

### Part B: General tag adoption

```sql
SELECT
  COUNT(DISTINCT tr.OBJECT_DATABASE || '.' || tr.OBJECT_SCHEMA || '.' || tr.OBJECT_NAME) AS tagged_tables,
  (SELECT COUNT(*) FROM SNOWFLAKE.ACCOUNT_USAGE.TABLES
   WHERE TABLE_CATALOG != 'SNOWFLAKE'
     AND TABLE_SCHEMA != 'INFORMATION_SCHEMA'
     AND TABLE_TYPE = 'BASE TABLE'
     AND DELETED IS NULL) AS total_tables
FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
WHERE tr.DOMAIN = 'TABLE'
  AND tr.OBJECT_DATABASE != 'SNOWFLAKE'
  AND tr.OBJECT_DELETED IS NULL;
```

### Handle no classification data

If no classification data exists and Check 1 = Red, score based on Part B only. Mark **Amber** with: "Cannot evaluate PII tagging — no classification data. General tag adoption: X%."

### Scoring

| Condition | Score |
|-----------|-------|
| All PII tables tagged AND general adoption >50% | **Green** |
| PII tables tagged but general <50%, OR partial PII tagging, OR no classification data | **Amber** |
| PII tables have no tags OR zero tags anywhere | **Red** |
| No tags applied anywhere | **Red** — "No tags applied anywhere" |

---

<!-- This check is account-wide. It does not use the database scope from Step 5. -->
## Check 4: Cross-ref Security Risk — PII Classified but Unmasked

**Risk type:** Security  
**Sources:** `SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT`, `SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES`

```sql
SELECT
  cr.TABLE_CATALOG || '.' || cr.TABLE_SCHEMA || '.' || cr.TABLE_NAME AS table_name,
  cr.COLUMN_NAME,
  cr.CLASSIFICATION_TAG_VALUE AS pii_type
FROM SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT cr
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES pr
  ON cr.TABLE_CATALOG = pr.REF_DATABASE_NAME
  AND cr.TABLE_SCHEMA = pr.REF_SCHEMA_NAME
  AND cr.TABLE_NAME = pr.REF_ENTITY_NAME
  AND cr.COLUMN_NAME = pr.REF_COLUMN_NAME
  AND pr.POLICY_KIND = 'MASKING_POLICY'
  AND pr.POLICY_STATUS = 'ACTIVE'
WHERE pr.REF_COLUMN_NAME IS NULL
  AND cr.TABLE_CATALOG IN (<SCOPED_DBS>)
ORDER BY cr.TABLE_CATALOG, cr.TABLE_SCHEMA, cr.TABLE_NAME;
```

### Scoring

| Condition | Score |
|-----------|-------|
| 0 unmasked PII columns | **Green** |
| 1-5 unmasked PII columns | **Amber** |
| No classification data exists | **Amber** — "Cannot evaluate — no classification data" |
| 6+ unmasked PII columns | **Red** |

Report each unmasked column with table name, column name, and PII type.

---

<!-- This check is account-wide. It does not use the database scope from Step 5. -->
## Check 5: Cross-ref Compliance Risk — PII Classified but Untagged

**Risk type:** Compliance  
**Sources:** `SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT`, `SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES`

```sql
SELECT
  cr.TABLE_CATALOG || '.' || cr.TABLE_SCHEMA || '.' || cr.TABLE_NAME AS table_name,
  cr.COLUMN_NAME,
  cr.CLASSIFICATION_TAG_VALUE AS pii_type
FROM SNOWFLAKE.DATA_PRIVACY.CLASSIFICATION_RESULT cr
LEFT JOIN SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES tr
  ON cr.TABLE_CATALOG = tr.OBJECT_DATABASE
  AND cr.TABLE_SCHEMA = tr.OBJECT_SCHEMA
  AND cr.TABLE_NAME = tr.OBJECT_NAME
  AND cr.COLUMN_NAME = tr.COLUMN_NAME
  AND tr.OBJECT_DELETED IS NULL
WHERE tr.COLUMN_NAME IS NULL
  AND cr.TABLE_CATALOG IN (<SCOPED_DBS>)
ORDER BY cr.TABLE_CATALOG, cr.TABLE_SCHEMA, cr.TABLE_NAME;
```

### Scoring

| Condition | Score |
|-----------|-------|
| 0 untagged PII columns | **Green** |
| 1-5 untagged PII columns | **Amber** |
| No classification data exists | **Amber** — "Cannot evaluate — no classification data" |
| 6+ untagged PII columns | **Red** |

Report each untagged column with table name, column name, and PII type.
