# QA — Quality Assurance between Bronze and Silver

**QA = Quality Assurance** (contrôle qualité des données).

In our pipeline, **[Python parsing + QA]** is the processing step between Bronze and Silver where we transform raw JSON into structured, validated data.

| Operation | Example in our project |
|---|---|
| **Parsing** | Extract `cve_id`, package names and affected-version ranges from OSV JSON |
| **Schema validation** | Check that expected fields exist and have valid types |
| **Integrity checks** | Verify that CycloneDX dependency references (`bom-ref`) point to existing components |
| **Identifier normalization** | Standardize CVE IDs, GHSA IDs and Maven package identifiers |
| **Duplicate detection** | Identify repeated records and conflicting source information |
| **Quarantine** | Separate invalid or unsupported records for investigation rather than silently discarding them |

## Where does QA happen?

```text
BRONZE
Raw JSON snapshots
       |
       v
Python Parsing + QA
       |
       | Validate, normalize,
       | deduplicate, reject/quarantine
       v
SILVER
Clean, structured entities
       |
       v
GOLD
Derived knowledge: exposure,
dependency paths, evidence
```

For example, if a CycloneDX dependency references a library that doesn't exist in the inventory, QA should flag the inconsistency instead of allowing an unreliable dependency graph into Silver.

**Important:** QA isn't necessarily a single operation between Bronze and Silver. We also perform quality checks inside Silver (uniqueness, referential integrity) and Gold (correct exposure calculations, provenance, consistency).

In our future stack, we'll implement QA through **Python validation, dbt tests and automated pipeline checks orchestrated by Airflow**.
