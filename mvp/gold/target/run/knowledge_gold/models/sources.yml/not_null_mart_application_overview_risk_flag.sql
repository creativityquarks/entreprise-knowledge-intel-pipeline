
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select risk_flag
from `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
where risk_flag is null



  
  
      
    ) dbt_internal_test