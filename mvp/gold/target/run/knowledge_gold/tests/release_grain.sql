
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  SELECT application_id,release_tag,COUNT(*) AS n
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
GROUP BY application_id,release_tag HAVING COUNT(*)>1
  
  
      
    ) dbt_internal_test