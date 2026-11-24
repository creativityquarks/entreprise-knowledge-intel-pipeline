SELECT CONCAT('app:',application_id) AS node_id, 'Application' AS node_type,
       application_name AS label, CAST(NULL AS STRING) AS source_sha256
FROM {{ source('silver', 'applications') }}
UNION DISTINCT
SELECT CONCAT('component:',c.source_sha256,':',c.bom_ref),
       'ComponentVersion',
       CONCAT(c.component_name,COALESCE(CONCAT('@',c.component_version),'')),
       c.source_sha256
FROM {{ source('silver', 'sbom_components') }} c
JOIN {{ ref('int_current_sboms') }} s ON c.source_sha256=s.source_sha256
UNION DISTINCT
SELECT CONCAT('vuln:',vulnerability_id), 'Vulnerability', vulnerability_id,
       CAST(NULL AS STRING)
FROM {{ ref('mart_application_findings') }}
