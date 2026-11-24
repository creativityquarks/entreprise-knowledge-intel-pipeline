-- Application -> inventory root; component -> component; component -> vulnerability.
SELECT CONCAT('app:',s.application_id) AS source_id,
       'HAS_INVENTORY' AS relation,
       CONCAT('component:',s.source_sha256,':',s.root_bom_ref) AS target_id,
       s.source_sha256 AS sbom_sha256,
       CAST(NULL AS STRING) AS osv_query_sha256
FROM {{ ref('int_current_sboms') }} s
UNION DISTINCT
SELECT CONCAT('component:',d.source_sha256,':',d.parent_bom_ref),
       'DEPENDS_ON',
       CONCAT('component:',d.source_sha256,':',d.child_bom_ref),
       d.source_sha256,CAST(NULL AS STRING)
FROM {{ source('silver','sbom_dependencies') }} d
JOIN {{ ref('int_current_sboms') }} s ON d.source_sha256=s.source_sha256
UNION DISTINCT
SELECT CONCAT('component:',source_sha256,':',bom_ref),
       'AFFECTED_BY',CONCAT('vuln:',vulnerability_id),
       source_sha256,query_sha256
FROM {{ source('silver','component_findings') }} f
JOIN {{ ref('int_current_sboms') }} s
  ON f.source_sha256=s.source_sha256
