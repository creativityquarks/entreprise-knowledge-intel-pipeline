-- Part 2B exploration. Use psql -f sql/pg_live_queries.sql
SELECT source_name,size_bytes,left(sha256,12) AS hash FROM live.snapshots ORDER BY source_name;
SELECT cve_id,ecosystem,package_name,jsonb_array_length(ranges) AS range_count FROM live.osv_affected;
SELECT p.component_name AS parent,c.component_name AS child FROM live.sbom_edges e JOIN live.sbom_components p ON p.bom_ref=e.parent_ref JOIN live.sbom_components c ON c.bom_ref=e.child_ref;
SELECT * FROM live.advisory_aliases;
-- Public SBOM / OSV may legitimately have no matching packages.
SELECT s.component_name,s.version,s.purl,o.cve_id,o.package_name FROM live.sbom_components s JOIN live.osv_affected o ON lower(o.ecosystem)='maven' AND s.purl LIKE 'pkg:maven/%' AND (s.component_group || ':' || s.component_name)=o.package_name;
-- Controlled match: synthetic inventory + real advisory; candidate only, NOT established exposure.
SELECT c.inventory_run,c.component_name,c.installed_version,o.cve_id,o.package_name FROM lab.components c JOIN live.osv_affected o ON lower(c.ecosystem)=lower(o.ecosystem) AND c.package_name=o.package_name ORDER BY c.inventory_run;
SELECT a.cve_id,a.package_name,rng ->> 'type' AS range_type,rng -> 'events' AS events FROM live.osv_affected a CROSS JOIN LATERAL jsonb_array_elements(a.ranges) AS rng;
