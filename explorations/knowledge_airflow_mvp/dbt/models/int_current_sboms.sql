WITH ranked AS (
  SELECT *, ROW_NUMBER() OVER (
    PARTITION BY application_id ORDER BY first_seen DESC, source_sha256 DESC
  ) AS rn
  FROM {{ source('silver', 'sboms') }}
)
SELECT row_key, source_sha256, application_id, root_bom_ref, source_uri, first_seen
FROM ranked WHERE rn = 1
