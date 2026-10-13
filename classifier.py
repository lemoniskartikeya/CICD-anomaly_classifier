"""
classifier.py — ML Anomaly Classifier (Starter)
Track 3: DFIR Telemetry & ML Anomaly Detection
MIT Bengaluru (MAHE) — Breaking & Hardening the CI/CD Pipeline

Trains Isolation Forest, Random Forest, and Logistic Regression classifiers
on the extracted feature matrix and evaluates with Confusion Matrix + F1 Score.

NOTE (Day 1): Dataset is small (only attack logs present). This script is
scaffolded and ready — it will produce meaningful results once 50+ benign
logs are added to data/benign_logs/.
"""

import os
import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler
import joblib


# ─── Config ──────────────────────────────────────────────────────────────────

BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
FEATURES_CSV = os.path.join(BASE_DIR, "outputs", "features.csv")
MODELS_DIR   = os.path.join(BASE_DIR, "models")
OUTPUT_DIR   = os.path.join(BASE_DIR, "outputs")

FEATURE_COLS = None   # Set to None to auto-select all numeric columns
LABEL_COL    = "label"
TEST_SIZE    = 0.25
RANDOM_STATE = 42


# ─── Helpers ──────────────────────────────────────────────────────────────────

def load_features(csv_path: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load features CSV and return X (features) and y (labels)."""
    df = pd.read_csv(csv_path)
    print(f"[+] Loaded {len(df)} samples from {csv_path}")

    # Drop non-numeric / metadata columns
    drop_cols = ["filename", LABEL_COL]
    X = df.drop(columns=[c for c in drop_cols if c in df.columns], errors="ignore")
    X = X.select_dtypes(include=[np.number]).fillna(0)
    y = df[LABEL_COL] if LABEL_COL in df.columns else None

    print(f"    Features : {list(X.columns)}")
    print(f"    Shape    : {X.shape}")
    return X, y


def evaluate(name: str, y_true, y_pred) -> None:
    """Print Confusion Matrix and Classification Report for a model."""
    print(f"\n{'='*55}")
    print(f"  Model: {name}")
    print(f"{'='*55}")
    print("\nConfusion Matrix:")
    cm = confusion_matrix(y_true, y_pred)
    print(f"  TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"  FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\nClassification Report:")
    print(classification_report(y_true, y_pred, target_names=["Benign", "Attack"]))
    f1 = f1_score(y_true, y_pred, zero_division=0)
    print(f"F1 Score (Attack class): {f1:.4f}")


# ─── Models ───────────────────────────────────────────────────────────────────

def run_isolation_forest(X_train, X_test, y_test):
    """
    Isolation Forest — unsupervised anomaly detector.
    Does NOT use labels during training (ideal for real-world unlabeled logs).
    """
    model = IsolationForest(n_estimators=100, contamination=0.2, random_state=RANDOM_STATE)
    model.fit(X_train)

    # IsolationForest returns -1 (anomaly) or 1 (normal) — map to 1/0
    raw_preds = model.predict(X_test)
    y_pred = [1 if p == -1 else 0 for p in raw_preds]

    evaluate("Isolation Forest (Unsupervised)", y_test, y_pred)
    joblib.dump(model, os.path.join(MODELS_DIR, "isolation_forest.pkl"))
    print(f"[+] Model saved: models/isolation_forest.pkl")
    return model


def run_random_forest(X_train, X_test, y_train, y_test):
    """Random Forest — supervised classifier."""
    model = RandomForestClassifier(n_estimators=100, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)

    evaluate("Random Forest (Supervised)", y_test, y_pred)

    # Feature importance
    importances = pd.Series(model.feature_importances_, index=X_train.columns)
    print("\nTop 5 Important Features:")
    print(importances.sort_values(ascending=False).head(5).to_string())

    joblib.dump(model, os.path.join(MODELS_DIR, "random_forest.pkl"))
    print(f"[+] Model saved: models/random_forest.pkl")
    return model


def run_logistic_regression(X_train, X_test, y_train, y_test):
    """Logistic Regression — simple linear baseline classifier."""
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    model = LogisticRegression(max_iter=500, random_state=RANDOM_STATE)
    model.fit(X_train_s, y_train)
    y_pred = model.predict(X_test_s)

    evaluate("Logistic Regression (Supervised)", y_test, y_pred)
    joblib.dump(model, os.path.join(MODELS_DIR, "logistic_regression.pkl"))
    joblib.dump(scaler, os.path.join(MODELS_DIR, "scaler.pkl"))
    print(f"[+] Model saved: models/logistic_regression.pkl")
    return model


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("\n" + "="*55)
    print("  TRACK 3 — DFIR ML CLASSIFIER")
    print("  Breaking & Hardening the CI/CD Pipeline")
    print("="*55)

    if not os.path.exists(FEATURES_CSV):
        print(f"[!] Feature CSV not found: {FEATURES_CSV}")
        print("    Run feature_extractor.py first.")
        return

    X, y = load_features(FEATURES_CSV)

    if y is None or len(y.unique()) < 2:
        print("\n[!] WARNING: Only one class present in labels.")
        print("    Add benign logs to data/benign_logs/ and re-run feature_extractor.py")
        print("    Skipping supervised models. Running Isolation Forest only.\n")
        run_isolation_forest(X, X, y if y is not None else pd.Series([1]*len(X)))
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"\n[+] Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # Run all three classifiers
    run_isolation_forest(X_train, X_test, y_test)
    run_random_forest(X_train, X_test, y_train, y_test)
    run_logistic_regression(X_train, X_test, y_train, y_test)

    print("\n[OK] All models trained and saved to models/")
    print("[OK] Ready for integration: drop real attack logs in data/attack_logs/ and re-run.\n")


if __name__ == "__main__":
    main()
