from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import joblib
import os
import pandas as pd
from pathlib import Path

from .utils import load_and_preprocess

app = FastAPI(title="CyberSleuth Anomaly Detection Service")

MODEL_PATH = Path(__file__).parent.parent / "model.joblib"

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/train")
async def train(csv: UploadFile = File(...)):
    if not csv.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted")
    # Save uploaded CSV to a temporary location
    tmp_path = Path("./tmp")
    tmp_path.mkdir(exist_ok=True)
    csv_path = tmp_path / csv.filename
    with open(csv_path, "wb") as f:
        f.write(await csv.read())
    # Load and preprocess data
    df = load_and_preprocess(str(csv_path))
    # Create binary label
    df['label'] = (df['ground_truth'] == 'suspicious').astype(int)
    # Drop non‑feature columns
    drop_cols = ['event_id','scenario_id','timestamp','username','host','ground_truth','label_reason','label']
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    y = df['label']
    # Build pipeline
    from sklearn.compose import ColumnTransformer
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import OneHotEncoder
    from sklearn.ensemble import GradientBoostingClassifier

    cat_cols = X.select_dtypes(include=['object']).columns.tolist()
    num_cols = X.select_dtypes(exclude=['object']).columns.tolist()
    preprocessor = ColumnTransformer([
        ("cat", OneHotEncoder(handle_unknown='ignore'), cat_cols),
        ("num", "passthrough", num_cols)
    ])
    model = GradientBoostingClassifier()
    pipeline = Pipeline([('preprocess', preprocessor), ('clf', model)])
    pipeline.fit(X, y)
    # Save model
    joblib.dump(pipeline, MODEL_PATH)
    # Cleanup
    try:
        os.remove(csv_path)
    except OSError:
        pass
    return JSONResponse(content={"detail": f"Model trained and saved to {MODEL_PATH}"})

@app.post("/predict")
async def predict(csv: UploadFile = File(...)):
    if not MODEL_PATH.exists():
        raise HTTPException(status_code=500, detail="Model not found. Train first.")
    if not csv.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted")
    tmp_path = Path("./tmp")
    tmp_path.mkdir(exist_ok=True)
    csv_path = tmp_path / csv.filename
    with open(csv_path, "wb") as f:
        f.write(await csv.read())
    df = load_and_preprocess(str(csv_path))
    # Align columns with training pipeline expectations
    drop_cols = ['event_id','scenario_id','timestamp','username','host','ground_truth','label_reason','label']
    X = df.drop(columns=[c for c in drop_cols if c in df.columns])
    pipeline = joblib.load(MODEL_PATH)
    preds = pipeline.predict(X)
    df['prediction'] = ['suspicious' if p == 1 else 'benign' for p in preds]
    # Return predictions as JSON list of dicts
    result = df[['event_id', 'prediction']].to_dict(orient='records')
    # Cleanup
    try:
        os.remove(csv_path)
    except OSError:
        pass
    return JSONResponse(content={"predictions": result})
