"""Shared CycloneDX inventory and Maven identity rules for capture and replay."""
from urllib.parse import unquote, parse_qsl
from schema_validation import validate_raw_schema


def inventory(doc):
    """Return top-level components indexed by bom-ref, including the root.

    Require references for all components and validate dependency endpoints.
    Flatten nested inventories without inventing dependency edges.
    """
    validate_raw_schema(doc, 'cyclonedx')
    root = doc.get('metadata', {}).get('component')
    if not root or not root.get('bom-ref'):
        raise ValueError('SBOM requires metadata.component.bom-ref')
    refs = {}
    def visit(comp):
        ref = comp.get('bom-ref')
        if not isinstance(ref, str) or not ref:
            raise ValueError(f'Missing bom-ref: {ref}')
        # Nested inventory membership is not a dependsOn relationship.
        # Identical duplicate definitions can be reused; conflicting ones fail.
        item = {k:v for k,v in comp.items() if k != 'components'}
        if ref in refs and refs[ref] != item:
            raise ValueError(f'Conflicting bom-ref: {ref}')
        refs[ref] = item
        for child in comp.get('components', []):
            visit(child)
    visit(root)
    for comp in doc.get('components', []):
        visit(comp)
    for dep in doc.get('dependencies', []):
        for ref in [dep['ref'], *dep.get('dependsOn', [])]:
            if ref not in refs:
                raise ValueError(f'Unknown dependency reference: {ref}')
    return root['bom-ref'], refs


def maven_request(comp):
    """Return exact Maven request only when PURL and explicit fields agree.

    Unsupported or ambiguous identities are not queried. No name guessing.
    """
    purl = comp.get('purl')
    if not isinstance(purl, str) or not purl.startswith('pkg:maven/'):
        return None
    coordinate = purl[len('pkg:maven/'):]
    if '#' in coordinate:
        return None
    coordinate, _, qualifiers = coordinate.partition('?')
    if qualifiers:
        try:
            pairs = parse_qsl(qualifiers, strict_parsing=True)
        except ValueError:
            return None
        # OSV identifies Maven group/artifact/version, not a file extension.
        # Classifiers and other qualifiers are deliberately left unassessed.
        if len(pairs) != 1 or pairs[0] not in [('type', 'jar'), ('type', 'pom')]:
            return None
    path, sep, version = coordinate.rpartition('@')
    parts = path.split('/')
    if not sep or len(parts) != 2:
        return None
    group, name = map(unquote, parts)
    version = unquote(version)
    if not all((group, name, version)) or ':' in group or ':' in name:
        return None
    if (comp.get('group'), comp.get('name'), comp.get('version')) != (group, name, version):
        return None
    return {'package': {'ecosystem': 'Maven', 'name': f'{group}:{name}'}, 'version': version}
