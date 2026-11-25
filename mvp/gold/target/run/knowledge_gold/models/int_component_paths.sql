
  
    

    create or replace table `ent-knowledge-intel-pipeline`.`gold_v4`.`int_component_paths`
      
    
    

    OPTIONS()
    as (
      -- Breadth-first shortest paths computed in Python; no recursive path explosion.
SELECT p.sbom_sha256, p.bom_ref, p.path_text, p.hops
FROM `ent-knowledge-intel-pipeline`.`gold_v4`.`component_paths` p
JOIN `ent-knowledge-intel-pipeline`.`gold_v4`.`int_current_sboms` s ON s.sbom_sha256=p.sbom_sha256
    );
  