SELECT sbom_sha256,bom_ref,vulnerability_id,COUNT(*) AS n
FROM {{ ref('mart_application_findings') }}
GROUP BY sbom_sha256,bom_ref,vulnerability_id HAVING COUNT(*)>1
