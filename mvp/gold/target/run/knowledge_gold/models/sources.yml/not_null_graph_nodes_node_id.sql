
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  
    
    



select node_id
from `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_nodes`
where node_id is null



  
  
      
    ) dbt_internal_test