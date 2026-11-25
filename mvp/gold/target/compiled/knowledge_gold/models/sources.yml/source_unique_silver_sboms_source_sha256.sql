
    
    

with dbt_test__target as (

  select source_sha256 as unique_field
  from `ent-knowledge-intel-pipeline`.`silver_v4`.`sboms`
  where source_sha256 is not null

)

select
    unique_field,
    count(*) as n_records

from dbt_test__target
group by unique_field
having count(*) > 1


