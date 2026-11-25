SELECT application_id,release_tag,COUNT(*) AS n
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
GROUP BY application_id,release_tag HAVING COUNT(*)>1