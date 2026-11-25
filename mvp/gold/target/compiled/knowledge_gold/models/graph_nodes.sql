-- Keep release-inventory node IDs separate; vulnerability IDs may be shared.
SELECT 'app:' || s.sbom_sha256 AS node_id, 'Application' AS node_type,
       root.name || ' [' || s.release_tag || ']' AS label, s.sbom_sha256 AS source_sha256
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s
JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` root
 ON root.source_sha256=s.sbom_sha256 AND root.bom_ref=s.root_component_ref
UNION DISTINCT
SELECT 'component:' || c.source_sha256 || ':' || c.bom_ref,
       'ComponentVersion', c.name || '@' || COALESCE(c.version,'unknown'), c.source_sha256
FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_components` c
JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s ON s.sbom_sha256=c.source_sha256
WHERE c.bom_ref IS NOT NULL
UNION DISTINCT
SELECT 'vuln:' || f.vulnerability_id, 'Vulnerability', f.vulnerability_id, CAST(NULL AS STRING)
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_findings` f