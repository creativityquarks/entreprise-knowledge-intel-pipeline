
    
    select
      count(*) as failures,
      count(*) != 0 as should_warn,
      count(*) != 0 as should_error
    from (
      
    
  SELECT e.* FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_edges` e
LEFT JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_nodes` s ON s.node_id=e.source_id
LEFT JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_nodes` t ON t.node_id=e.target_id
WHERE s.node_id IS NULL OR t.node_id IS NULL
  
  
      
    ) dbt_internal_test