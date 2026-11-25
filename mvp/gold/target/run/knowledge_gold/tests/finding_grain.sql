
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  SELECT sbom_sha256,bom_ref,vulnerability_id,COUNT(*) AS n
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_findings`
GROUP BY sbom_sha256,bom_ref,vulnerability_id HAVING COUNT(*)>1
  
  
      
    ) dbt_internal_test