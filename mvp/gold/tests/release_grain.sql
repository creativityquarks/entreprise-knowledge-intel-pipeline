SELECT application_id,release_tag,COUNT(*) AS n
FROM {{ ref('mart_application_overview') }}
GROUP BY application_id,release_tag HAVING COUNT(*)>1
