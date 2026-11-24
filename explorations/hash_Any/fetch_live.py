
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "data" / "raw"
MANIFEST_PATH = ROOT / "data" / "manifest" / "manifest.json"

SOURCES = {
    "osv": "https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2021-44228.json",
    "sbom": "https://raw.githubusercontent.com/CycloneDX/bom-examples/master/CBOM/Example-With-Dependencies/bom.json",
}


def main():
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)

    if MANIFEST_PATH.exists():
        manifest = json.loads(MANIFEST_PATH.read_text())
    else:
        manifest = {"osv": {}, "sbom": {}}

    changed = False

    for source, url in SOURCES.items():
        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "knowledge-protocol-feasibility/0.1",
                    "Accept": "application/json",
                },
            )

            with urllib.request.urlopen(request, timeout=25) as response:
                raw = response.read(12_000_001)

                if len(raw) > 12_000_000:
                    raise ValueError("Size cap exceeded (12 MB)")

                json.loads(raw)  # Validate JSON before saving

            sha256 = hashlib.sha256(raw).hexdigest()
            source_dir = RAW_DIR / source
            file_path = source_dir / f"{sha256}.json"

            manifest.setdefault(source, {})

            if sha256 in manifest[source]:
                print(f"{source}: unchanged ({sha256[:12]})")
                continue

            source_dir.mkdir(parents=True, exist_ok=True)

            if not file_path.exists():
                file_path.write_bytes(raw)

            manifest[source][sha256] = {
                "raw_path": str(file_path.relative_to(ROOT)),
                "source_url": url,
                "first_seen_utc": datetime.now(timezone.utc).isoformat(),
            }

            changed = True
            print(f"{source}: new data ({sha256[:12]})")

        except Exception as error:
            print(f"{source}: failed ({type(error).__name__}: {error})")

    if changed:
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n")
        print("Manifest updated:", MANIFEST_PATH)
    else:
        print("Manifest unchanged")


if __name__ == "__main__":
    main()
