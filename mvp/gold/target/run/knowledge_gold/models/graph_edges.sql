
  
    

    create or replace table `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_edges`
      
    
    

    OPTIONS()
    as (
      SELECT 'app:' || s.sbom_sha256 AS source_id, 'HAS_INVENTORY' AS relation,
       'component:' || s.sbom_sha256 || ':' || s.root_component_ref AS target_id,
       s.sbom_sha256 AS sbom_sha256, CAST(NULL AS STRING) AS osv_query_sha256
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s
UNION DISTINCT
SELECT 'component:' || d.source_sha256 || ':' || d.parent_bom_ref,
       'DEPENDS_ON', 'component:' || d.source_sha256 || ':' || d.child_bom_ref,
       d.source_sha256, CAST(NULL AS STRING)
FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`sbom_dependencies` d
JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s ON s.sbom_sha256=d.source_sha256
UNION DISTINCT
SELECT 'component:' || f.sbom_sha256 || ':' || f.bom_ref,
       'AFFECTED_BY','vuln:' || f.vulnerability_id,
       f.sbom_sha256, f.osv_query_sha256
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_findings` f
    );
  