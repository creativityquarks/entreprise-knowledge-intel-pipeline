SELECT f.* FROM {{ source('silver','component_findings') }} f
LEFT JOIN {{ source('silver','component_queries') }} q
ON q.source_sha256=f.source_sha256 AND q.bom_ref=f.bom_ref
AND q.osv_query_sha256=f.osv_query_sha256 AND q.status='SUCCESS'
WHERE q.bom_ref IS NULL
