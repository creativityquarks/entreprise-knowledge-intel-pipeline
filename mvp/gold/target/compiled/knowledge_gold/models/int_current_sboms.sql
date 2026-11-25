-- Latest inventory per application AND release; retain all historical releases.
WITH ranked AS (
 SELECT *, ROW_NUMBER() OVER (
   PARTITION BY sbom_id, COALESCE(release_tag, 'fixture')
   ORDER BY COALESCE(generated_at, retrieved_at) DESC, source_sha256 DESC
 ) AS rn
 FROM `ent-knowledge-intel-pipeline`.`silver_v4`.`sboms`
)
SELECT sbom_id AS application_id, source_sha256 AS sbom_sha256,
       root_component_ref, retrieved_at AS inventory_first_seen,
       COALESCE(release_tag,'fixture') AS release_tag,
       repository_url, git_commit, commit_at, generated_at
FROM ranked WHERE rn = 1