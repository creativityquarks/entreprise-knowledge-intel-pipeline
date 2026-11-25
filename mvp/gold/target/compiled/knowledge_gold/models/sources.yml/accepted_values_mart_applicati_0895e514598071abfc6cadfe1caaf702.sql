
    
    

with all_values as (

    select
        risk_flag as value_field,
        count(*) as n_records

    from `ent-knowledge-intel-pipeline`.`gold_v4`.`mart_application_overview`
    group by risk_flag

)

select *
from all_values
where value_field not in (
    'QUERY_INCOMPLETE','KNOWN_VULNERABILITY','NO_MATCH_IN_QUERIED_OSV'
)


