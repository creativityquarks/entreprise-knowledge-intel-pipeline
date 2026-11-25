-- Counts are per release inventory, never pooled across different versions.
WITH aggregated AS (
 SELECT sbom_sha256, COUNT(*) AS finding_count,
        COUNT(DISTINCT bom_ref) AS affected_components
 FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_findings` GROUP BY sbom_sha256
), path_coverage AS (
 SELECT c.source_sha256 AS sbom_sha256, COUNT(p.bom_ref) AS components_with_path
 FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` c
 LEFT JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`int_component_paths` p ON p.sbom_sha256=c.source_sha256 AND p.bom_ref=c.bom_ref
 WHERE NOT c.is_root
 GROUP BY c.source_sha256
), coverage AS (
 SELECT s.sbom_sha256,
        COUNT(c.bom_ref) AS components_to_query,
        SUM(CASE WHEN q.status='SUCCESS' AND q.component_version=c.version THEN 1 ELSE 0 END) AS components_queried,
        SUM(CASE WHEN q.status='FAILED' THEN 1 ELSE 0 END) AS failed_queries,
        SUM(CASE WHEN q.status='SKIPPED' THEN 1 ELSE 0 END) AS skipped_queries,
        SUM(CASE WHEN c.bom_ref IS NOT NULL AND q.bom_ref IS NULL THEN 1 ELSE 0 END) AS missing_queries,
        MIN(q.queried_at) AS first_evaluated_at, MAX(q.queried_at) AS last_evaluated_at
 FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s
 LEFT JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` c
  ON c.source_sha256=s.sbom_sha256 AND NOT c.is_root
 LEFT JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`component_queries` q
  ON q.source_sha256=c.source_sha256 AND q.bom_ref=c.bom_ref
 GROUP BY s.sbom_sha256
)
SELECT s.application_id, root.name AS application_name, s.release_tag,
       s.git_commit,s.commit_at,s.repository_url,s.generated_at,
       COALESCE(a.finding_count,0) AS finding_count,
       COALESCE(a.affected_components,0) AS affected_components,
       CASE WHEN co.components_to_query=0 OR co.components_queried < co.components_to_query THEN 'QUERY_INCOMPLETE'
            WHEN COALESCE(a.finding_count,0)>0 THEN 'KNOWN_VULNERABILITY'
            ELSE 'NO_MATCH_IN_QUERIED_OSV' END AS risk_flag,
       CASE WHEN COALESCE(a.finding_count,0)>0 THEN 'UNRATED' WHEN co.components_to_query=0 OR co.components_queried < co.components_to_query THEN 'UNKNOWN' ELSE 'N/A' END AS severity_label,
       s.sbom_sha256 AS inventory_snapshot_sha256,
       co.components_to_query, co.components_queried,co.failed_queries,co.skipped_queries,co.missing_queries,
       co.first_evaluated_at,co.last_evaluated_at,
       COALESCE(pc.components_with_path,0) AS components_with_dependency_path,
       co.components_to_query-COALESCE(pc.components_with_path,0) AS components_without_dependency_path
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` root
 ON root.source_sha256=s.sbom_sha256 AND root.bom_ref=s.root_component_ref
LEFT JOIN aggregated a ON a.sbom_sha256=s.sbom_sha256
LEFT JOIN coverage co ON co.sbom_sha256=s.sbom_sha256

LEFT JOIN path_coverage pc ON pc.sbom_sha256=s.sbom_sha256