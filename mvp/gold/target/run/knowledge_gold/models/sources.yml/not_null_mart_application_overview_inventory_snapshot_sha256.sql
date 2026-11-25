
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select inventory_snapshot_sha256
from `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
where inventory_snapshot_sha256 is null



  
  
      
    ) dbt_internal_test