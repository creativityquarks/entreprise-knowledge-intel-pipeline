SELECT e.* FROM {{ ref('graph_edges') }} e
LEFT JOIN {{ ref('graph_nodes') }} s ON s.node_id=e.source_id
LEFT JOIN {{ ref('graph_nodes') }} t ON t.node_id=e.target_id
WHERE s.node_id IS NULL OR t.node_id IS NULL
