"""CycloneDX SBOM source configuration."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SYNTHETIC_BILLING_SBOM = ROOT / "fixtures" / "synthetic_billing_sbom.json"

SOURCES: dict[str, str] = {
    "cyclonedx_example": (
        "https://raw.githubusercontent.com/CycloneDX/bom-examples/"
        "master/CBOM/Example-With-Dependencies/bom.json"
    ),
    "synthetic_billing": SYNTHETIC_BILLING_SBOM.as_uri(),
}


def get_url(sbom_id: str) -> str:
    return SOURCES[sbom_id]
