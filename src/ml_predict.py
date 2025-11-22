# src/ml_predict.py
import joblib
import pandas as pd
from pathlib import Path
from typing import Dict, Any

from src.ml_features import extract_features as extract_features_dict

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "model"
ML_MODEL_PATH = MODEL_DIR / "phishing_url_model.pkl"
FEATURE_ORDER_PATH = MODEL_DIR / "feature_order.pkl"

_model = None
_feature_order = None

def _load_model_and_order():
    global _model, _feature_order
    if _model is None:
        if not ML_MODEL_PATH.exists():
            raise FileNotFoundError(f"Model missing: {ML_MODEL_PATH}")
        _model = joblib.load(str(ML_MODEL_PATH))
    if _feature_order is None:
        if not FEATURE_ORDER_PATH.exists():
            raise FileNotFoundError(f"Feature order missing: {FEATURE_ORDER_PATH}")
        _feature_order = joblib.load(str(FEATURE_ORDER_PATH))
    return _model, _feature_order

def _feats_to_df(feats: Dict[str, Any], feature_order: list) -> pd.DataFrame:
    # Ensure all required columns exist in the same order
    row = {k: feats.get(k, 0) for k in feature_order}
    return pd.DataFrame([row], columns=feature_order)

def predict_url(url: str, page_analysis: dict = None) -> dict:
    model, feature_order = _load_model_and_order()

    feats = extract_features_dict(url, page_analysis)
    X = _feats_to_df(feats, feature_order)

    out = {"raw_features": feats, "probability": None, "prediction": None}
    if hasattr(model, "predict_proba"):
        proba = float(model.predict_proba(X)[:,1][0])
        pred = int(proba >= 0.5)
        out["probability"] = proba
        out["prediction"] = pred
        return out
    else:
        pred = int(model.predict(X)[0])
        out["probability"] = float(pred)
        out["prediction"] = pred
        return out
