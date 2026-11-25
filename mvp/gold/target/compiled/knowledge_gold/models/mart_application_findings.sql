-- OSV's exact-version matching is evidence of a known match, not exploitability.
WITH latest_vulns AS (
 SELECT *, ROW_NUMBER() OVER (PARTITION BY osv_id ORDER BY modified_at DESC,retrieved_at DESC,source_sha256 DESC) AS rn
 FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`vulnerabilities`
)
SELECT s.application_id,root.name AS application_name,
       s.release_tag,s.git_commit,s.commit_at,
       c.bom_ref,c.name AS component_name,
       q.package_name,c.version AS component_version,
       f.vulnerability_id,'KNOWN_VULNERABILITY' AS finding_status,
       'UNRATED' AS severity_label,
       'https://osv.dev/vulnerability/' || f.vulnerability_id AS advisory_url,
       s.sbom_sha256,q.osv_query_sha256,
       CAST(NULL AS STRING) AS sbom_gcs_uri,
       s.inventory_first_seen,
       CAST(NULL AS FLOAT64) AS v2_cvss_score,
       v.published_at AS v2_published_at,
       p.path_text AS v2_dependency_path,
       v.summary AS v2_vulnerability_summary,
       q.queried_at AS evaluated_at,
       CASE WHEN v.osv_id IS NULL THEN 'PENDING' ELSE 'AVAILABLE' END AS advisory_enrichment,
       CASE WHEN p.bom_ref IS NULL THEN 'PATH_UNKNOWN' ELSE 'PATH_AVAILABLE' END AS dependency_path_status,
       v.source_sha256 AS advisory_sha256, v.modified_at AS advisory_modified_at,
       v.retrieved_at AS advisory_retrieved_at
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` root
 ON root.source_sha256=s.sbom_sha256 AND root.bom_ref=s.root_component_ref
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` c
 ON c.source_sha256=s.sbom_sha256 AND NOT c.is_root
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`component_queries` q
 ON q.source_sha256=c.source_sha256 AND q.bom_ref=c.bom_ref AND q.status='SUCCESS'
 AND q.component_version=c.version
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`component_findings` f
 ON f.source_sha256=q.source_sha256 AND f.bom_ref=q.bom_ref AND f.osv_query_sha256=q.osv_query_sha256
LEFT JOIN latest_vulns v ON v.osv_id=f.vulnerability_id AND v.rn=1
LEFT JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`int_component_paths` p
 ON p.sbom_sha256=c.source_sha256 AND p.bom_ref=c.bom_ref