from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from core import validate_sbom, maven_queries, sha256, run_key

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_billing_transitive_path():
    bom = json.loads((FIXTURES/"billing.json").read_text())
    comps, edges = validate_sbom(bom)
    assert len(comps) == 3
    assert ("app:billing", "helper") in {(e['parent'],e['child']) for e in edges}
    assert ("helper", "log4j") in {(e['parent'],e['child']) for e in edges}


def test_two_version_queries():
    boms = [json.loads(p.read_text()) for p in sorted(FIXTURES.glob("*.json"))]
    queries = maven_queries(boms)
    assert len(queries) == 2
    assert {q['version'] for q in queries} == {"2.14.1", "2.17.1"}


def test_duplicate_reference_rejected():
    bom = json.loads((FIXTURES/"billing.json").read_text())
    bom['components'][1]['bom-ref'] = 'helper'
    try:
        validate_sbom(bom)
    except ValueError:
        return
    assert False, 'Duplicate must be rejected'


def test_hash_deterministic():
    assert sha256(b"hello") == sha256(b"hello")
    assert len(run_key("scheduled__2026-11-24")) == 24
