-- Breadth-first shortest paths computed in Python; no recursive path explosion.
SELECT p.sbom_sha256, p.bom_ref, p.path_text, p.hops
FROM {{ source('work','component_paths') }} p
JOIN {{ ref('int_current_sboms') }} s ON s.sbom_sha256=p.sbom_sha256
