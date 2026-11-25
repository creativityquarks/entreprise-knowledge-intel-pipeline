
    
    

with dbt_test__target as (

  select node_id as unique_field
  from `ent-knowledge-intel-pipeline`.`gold_v4`.`graph_nodes`
  where node_id is not null

)

select
    unique_field,
    count(*) as n_records

from dbt_test__target
group by unique_field
having count(*) > 1


