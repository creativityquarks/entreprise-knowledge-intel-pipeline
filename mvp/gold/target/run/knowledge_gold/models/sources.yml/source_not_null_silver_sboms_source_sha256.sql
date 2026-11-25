
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select source_sha256
from `ent-knowledge-intel-pipeline`.`silver_v4`.`sboms`
where source_sha256 is null



  
  
      
    ) dbt_internal_test