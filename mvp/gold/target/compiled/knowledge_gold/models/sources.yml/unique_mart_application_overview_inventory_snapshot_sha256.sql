
    
    

with dbt_test__target as (

  select inventory_snapshot_sha256 as unique_field
  from `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
  where inventory_snapshot_sha256 is not null

)

select
    unique_field,
    count(*) as n_records

from dbt_test__target
group by unique_field
having count(*) > 1


