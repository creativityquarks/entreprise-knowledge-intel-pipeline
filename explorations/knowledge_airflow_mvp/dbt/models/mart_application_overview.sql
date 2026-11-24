SELECT
  a.application_id,
  a.application_name,
  COUNT(DISTINCT CONCAT(f.bom_ref, '|', f.vulnerability_id)) AS finding_count,
  COUNT(DISTINCT f.bom_ref) AS affected_components,
  CASE WHEN COUNT(f.vulnerability_id) > 0
       THEN 'KNOWN_VULNERABILITY'
       ELSE 'NO_MATCH_IN_QUERIED_OSV' END AS risk_flag,
  CASE WHEN COUNT(f.vulnerability_id) > 0
       THEN 'UNRATED' ELSE 'NONE' END AS severity_label
FROM {{ source('silver', 'applications') }} a
LEFT JOIN {{ ref('mart_application_findings') }} f
  ON a.application_id = f.application_id
GROUP BY a.application_id, a.application_name
