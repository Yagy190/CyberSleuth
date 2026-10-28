import argparse
import json
import pandas as pd
import joblib
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

def load_data(csv_path):
    df = pd.read_csv(csv_path)
    # Parse the JSON column into separate columns
    def parse_details(s):
        try:
            return json.loads(s)
        except Exception:
            return {}
    details = df['details_json'].apply(parse_details).apply(pd.Series)
    df = pd.concat([df.drop(columns=['details_json']), details], axis=1)
    return df

def main():
    parser = argparse.ArgumentParser(description='Run predictions with trained anomaly detection model')
    parser.add_argument('--model', required=True, help='Path to the trained model file (joblib)')
    parser.add_argument('--input', required=True, help='Path to input CSV file to predict')
    parser.add_argument('--output', default='predictions.csv', help='Path to write predictions CSV')
    args = parser.parse_args()

    pipeline: Pipeline = joblib.load(args.model)
    df = load_data(args.input)
    # Keep the same feature columns as training (drop same columns)
    drop_cols = ['event_id', 'scenario_id', 'timestamp', 'username', 'host', 'ground_truth', 'label_reason', 'label']
    X = df.drop(columns=[col for col in drop_cols if col in df.columns])
    preds = pipeline.predict(X)
    df['prediction'] = ['suspicious' if p == 1 else 'benign' for p in preds]
    df.to_csv(args.output, index=False)
    print(f'Predictions saved to {args.output}')

if __name__ == '__main__':
    main()
