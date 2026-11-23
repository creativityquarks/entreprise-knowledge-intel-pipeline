WITH RECURSIVE walk AS (
  SELECT c.inventory_run, c.bom_ref, c.component_name,
         0 AS depth, ARRAY[c.bom_ref]::TEXT[] AS visited
  FROM lab.components c
  WHERE c.component_type = 'application' AND c.inventory_run = 1

  UNION ALL

  SELECT w.inventory_run, child.bom_ref, child.component_name,
         w.depth + 1, w.visited || child.bom_ref
  FROM walk w
  JOIN lab.dependency_edges e
    ON e.inventory_run = w.inventory_run AND e.parent_ref = w.bom_ref
  JOIN lab.components child
    ON child.inventory_run = e.inventory_run AND child.bom_ref = e.child_ref
  WHERE w.depth < 20 AND NOT child.bom_ref = ANY(w.visited)
)
SELECT component_name,depth FROM walk ORDER BY depth;
