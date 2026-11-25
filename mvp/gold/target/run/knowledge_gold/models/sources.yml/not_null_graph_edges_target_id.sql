
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select target_id
from `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_edges`
where target_id is null



  
  
      
    ) dbt_internal_test