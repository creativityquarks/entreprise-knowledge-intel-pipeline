
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select source_id
from `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_edges`
where source_id is null



  
  
      
    ) dbt_internal_test