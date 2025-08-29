import pandas as pd
import os
from ingestion.normalizer import LogNormalizer

DATA_DIR = "data/raw/"
OUT_DIR = "data/processed/"

os.makedirs(OUT_DIR, exist_ok=True)

normalizer = LogNormalizer()

unsw = pd.read_csv(f"{DATA_DIR}/UNSW-NB15.csv")
unsw_norm = normalizer.normalize_unsw(unsw)
normalizer.save_processed(unsw_norm, f"{OUT_DIR}/unsw_processed.json")

print("✅ Datasets processed & saved in data/processed/")