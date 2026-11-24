SELECT
  s.application_id, a.application_name,
  f.bom_ref, f.component_name, f.package_name, f.component_version,
  f.vulnerability_id,
  'KNOWN_VULNERABILITY' AS finding_status,
  'UNRATED' AS severity_label,
  CONCAT('https://osv.dev/vulnerability/', f.vulnerability_id) AS advisory_url,
  f.source_sha256 AS sbom_sha256, f.query_sha256 AS osv_query_sha256,
  s.source_uri AS sbom_gcs_uri,
  s.first_seen AS inventory_first_seen
FROM {{ ref('int_current_sboms') }} s
JOIN {{ source('silver', 'component_findings') }} f
  ON f.source_sha256 = s.source_sha256
 AND f.application_id = s.application_id
JOIN {{ source('silver', 'applications') }} a
  ON a.application_id = s.application_id
