SELECT sbom_sha256,bom_ref,vulnerability_id,COUNT(*) AS n
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_findings`
GROUP BY sbom_sha256,bom_ref,vulnerability_id HAVING COUNT(*)>1