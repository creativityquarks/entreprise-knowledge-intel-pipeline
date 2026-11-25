
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select application_id
from `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
where application_id is null



  
  
      
    ) dbt_internal_test