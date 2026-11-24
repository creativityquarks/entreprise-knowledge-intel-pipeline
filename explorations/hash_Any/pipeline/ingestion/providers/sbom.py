"""CycloneDX SBOM source configuration."""

SOURCES = {
    "cyclonedx_example": "https://raw.githubusercontent.com/CycloneDX/bom-examples/master/CBOM/Example-With-Dependencies/bom.json",
}


def get_url(sbom_id: str) -> str:
    return SOURCES[sbom_id]
