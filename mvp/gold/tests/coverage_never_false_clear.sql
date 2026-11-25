SELECT * FROM {{ ref('mart_application_overview') }}
WHERE components_queried > components_to_query
   OR (risk_flag='NO_MATCH_IN_QUERIED_OSV' AND
       (components_to_query=0 OR components_queried <> components_to_query OR finding_count <> 0))
