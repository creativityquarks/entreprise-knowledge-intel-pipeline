"""Pure parsing and entity-key logic; no GCP or Airflow dependency."""
import hashlib
import json


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run_key(run_id: str) -> str:
    return sha256(run_id.encode())[:24]


def validate_sbom(bom: dict) -> tuple[list[dict], list[dict]]:
    if not isinstance(bom, dict) or bom.get("bomFormat") != "CycloneDX":
        raise ValueError("Not a CycloneDX object")
    if not isinstance(bom.get("components", []), list):
        raise ValueError("components must be a list")
    root = bom.get("metadata", {}).get("component")
    if not isinstance(root, dict) or not root.get("bom-ref"):
        raise ValueError("Root application must have bom-ref")
    comps = [root, *bom.get("components", [])]
    refs = [c.get("bom-ref") for c in comps]
    if any(not r for r in refs) or len(refs) != len(set(refs)):
        raise ValueError("Missing or duplicate bom-ref")
    known = set(refs)
    edges = []
    for d in bom.get("dependencies", []):
        if d.get("ref") not in known:
            raise ValueError("Unknown dependency parent")
        for child in d.get("dependsOn", []):
            if child not in known:
                raise ValueError(f"Unknown dependency child {child}")
            edges.append({"parent": d["ref"], "child": child})
    return comps, edges


def maven_queries(sboms: list[dict]) -> list[dict]:
    """Order is preserved: OSV querybatch results align by index."""
    found = set()
    queries = []
    for bom in sboms:
        comps, _ = validate_sbom(bom)
        for c in comps:
            if not (c.get("group") and c.get("name") and c.get("version")):
                continue
            if not (c.get("purl") or "").startswith("pkg:maven/"):
                continue
            ident = (f"{c['group']}:{c['name']}", c["version"])
            if ident in found:
                continue
            found.add(ident)
            queries.append({"package":{"ecosystem":"Maven","name":ident[0]},
                            "version":ident[1]})
    return queries


def as_ndjson(rows):
    return "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows)
