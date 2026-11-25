"""Shared deployment settings. Never allow demo, live or Gold/Silver overlap."""
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def settings(demo=False):
    from dotenv import load_dotenv
    load_dotenv(ROOT/'.env')
    project = os.getenv('GCP_PROJECT_ID', '')
    location = os.getenv('BQ_LOCATION', 'EU')
    keys = ('BQ_DATASET','BQ_GOLD_DATASET','BQ_DEMO_DATASET','BQ_DEMO_GOLD_DATASET')
    values = [os.getenv(k,'') for k in keys]
    if not re.fullmatch(r'[A-Za-z0-9_-]+',project) or any(not re.fullmatch(r'[A-Za-z0-9_]+',x) for x in values):
        raise ValueError('Set project and all four dataset names in .env')
    if len(set(values)) != len(values):
        raise ValueError('Live/demo and Silver/Gold datasets must all differ')
    return project, values[2 if demo else 0], values[3 if demo else 1], location
