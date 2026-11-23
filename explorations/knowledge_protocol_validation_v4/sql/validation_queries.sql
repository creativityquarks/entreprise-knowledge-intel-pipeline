-- Query A: reconstruct dependency paths (recursive traversal, bounded depth).
WITH RECURSIVE walk(run_id,app,ref,path,depth) AS (
 SELECT run_id, app, 'app:' || app, 'app:' || app, 0
 FROM inventory_components WHERE bom_ref='app:' || app
 UNION ALL
 SELECT w.run_id,w.app,d.child_ref,w.path || ' > ' || d.child_ref,w.depth+1
 FROM walk w JOIN dependencies d ON d.run_id=w.run_id AND d.app=w.app AND d.parent_ref=w.ref
 WHERE w.depth < 20 AND instr(w.path, d.child_ref)=0
)
SELECT * FROM walk ORDER BY run_id,depth;

-- Query B: exposure change between runs, retaining both histories.
SELECT a.app, a.package_name, a.version AS old_version, b.version AS new_version,
       a.status AS old_status, b.status AS new_status
FROM exposures a JOIN exposures b
 ON a.app=b.app AND a.package_name=b.package_name AND a.vuln_id=b.vuln_id
WHERE a.run_id=1 AND b.run_id=2 AND (a.version<>b.version OR a.status<>b.status);

-- Query C: auditable affected paths at run 1.
SELECT e.app, e.path, e.vuln_id, e.inventory_evidence, e.advisory_evidence
FROM exposures e WHERE e.run_id=1 AND e.status='affected';

-- Query D: quality checks.
SELECT run_id, status, COUNT(*) AS n FROM exposures GROUP BY run_id,status ORDER BY run_id,status;
PRAGMA foreign_key_check;
