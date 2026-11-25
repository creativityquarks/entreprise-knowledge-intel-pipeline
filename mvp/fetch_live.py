"""CLI entry point for the modular Bronze ingestion pipeline."""
from pipeline.ingestion.ingest import main, demo, live
from pipeline.ingestion.osv_query import capture_queries, result_ids

if __name__ == '__main__':
    raise SystemExit(main())
