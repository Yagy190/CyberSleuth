import json
import pandas as pd
from typing import List

def load_and_preprocess(csv_path: str) -> pd.DataFrame:
    """Load CSV and flatten the ``details_json`` column.
    Returns a DataFrame ready for model training / inference (features only).
    """
    df = pd.read_csv(csv_path)
    # Parse JSON column safely
    def parse_details(s):
        try:
            return json.loads(s)
        except Exception:
            return {}
    details = df['details_json'].apply(parse_details).apply(pd.Series)
    df = pd.concat([df.drop(columns=['details_json']), details], axis=1)
    return df
