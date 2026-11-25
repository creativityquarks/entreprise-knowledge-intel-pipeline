
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  SELECT f.* FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`component_findings` f
LEFT JOIN `ent-knowledge-intel-pipeline`.`silver_v4`.`component_queries` q
ON q.source_sha256=f.source_sha256 AND q.bom_ref=f.bom_ref
AND q.osv_query_sha256=f.osv_query_sha256 AND q.status='SUCCESS'
WHERE q.bom_ref IS NULL
  
  
      
    ) dbt_internal_test