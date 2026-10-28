import argparse
import json
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import classification_report
import joblib

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
    parser = argparse.ArgumentParser(description='Train anomaly detection model')
    parser.add_argument('--data', required=True, help='Path to CSV dataset')
    parser.add_argument('--model_out', required=True, help='Path to save trained model')
    args = parser.parse_args()

    df = load_data(args.data)
    # Create binary label: suspicious = 1, benign = 0
    df['label'] = (df['ground_truth'] == 'suspicious').astype(int)
    # Drop columns that are not useful for training
    drop_cols = ['event_id', 'scenario_id', 'timestamp', 'username', 'host', 'ground_truth', 'label_reason', 'label']
    X = df.drop(columns=drop_cols)
    y = df['label']

    # Identify categorical and numeric columns
    categorical_cols = X.select_dtypes(include=['object']).columns.tolist()
    numeric_cols = X.select_dtypes(exclude=['object']).columns.tolist()

    preprocessor = ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols),
            ('num', 'passthrough', numeric_cols)
        ])

    model = GradientBoostingClassifier()
    pipeline = Pipeline(steps=[('preprocess', preprocessor), ('clf', model)])
    pipeline.fit(X, y)

    # Simple evaluation on training set (for demonstration)
    preds = pipeline.predict(X)
    print(classification_report(y, preds, target_names=['benign', 'suspicious']))

    joblib.dump(pipeline, args.model_out)
    print(f"Model saved to {args.model_out}")

if __name__ == '__main__':
    main()
