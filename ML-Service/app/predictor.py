import joblib
import numpy as np


MODEL_PATH = "model/model.joblib"
SCALER_PATH = "model/scaler.joblib"
FEATURE_ORDER_PATH = "model/feature_order.joblib"  # Optional but recommended

# Load model and scaler
model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)

# Load feature order if saved
try:
    feature_order = joblib.load(FEATURE_ORDER_PATH)
except:
    feature_order = None


def get_threat_level(prob):
    """
    Map probability to threat level (updated thresholds)
    """
    if prob >= 0.85:
        return "CRITICAL THREAT"
    elif prob >= 0.70:
        return "HIGH THREAT"
    elif prob >= 0.50:
        return "MEDIUM THREAT"
    else:
        return "LOW THREAT"


def predict_threat(features_dict):
    """
    Predict threat probability and threat level from input features
    """
    # Ensure features are in the same order as training
    if feature_order:
        values = [features_dict[f] for f in feature_order]
    else:
        values = list(features_dict.values())

    values = np.array(values).reshape(1, -1)

    # Scale features
    values_scaled = scaler.transform(values)

    # Predict probability
    if hasattr(model, "predict_proba"):
        # For classifier
        prob = model.predict_proba(values_scaled)[0][1]
    else:
        # For regressor
        prob = model.predict(values_scaled)[0]

    prob = float(prob)
    print(features_dict)
    print(prob)
    print(get_threat_level(prob))
    return {
        "threat_probability": prob,
        "threat_level": get_threat_level(prob)
    }