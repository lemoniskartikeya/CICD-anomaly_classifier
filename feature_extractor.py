"""
feature_extractor.py — CI/CD Log Feature Extraction
Track 3: DFIR Telemetry & ML Anomaly Detection
MIT Bengaluru (MAHE) — Breaking & Hardening the CI/CD Pipeline

Extracts structured numeric features from raw CI/CD build logs for use
in ML anomaly detection classifiers (Isolation Forest, Random Forest, etc.)
"""

import os
import re
import math
from collections import Counter

import pandas as pd

from entropy import shannon_entropy


# ─── Feature Definitions ─────────────────────────────────────────────────────

# High-risk commands that may indicate malicious activity
HIGH_RISK_COMMANDS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"\bnc\b",           # netcat
    r"\bbash\s+-i\b",   # interactive bash
    r"\bpython\s+-c\b", # python one-liner
    r"\bbase64\b",
    r"\bopenssl\b",
    r"\beval\b",
    r"\bchmod\s+\+x\b",
    r"\b/tmp/\b",        # writing to /tmp (common dropper pattern)
]

# Regex to detect IPv4 addresses
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

# Regex to detect external domain references (non-github, non-localhost)
SUSPICIOUS_DOMAIN_PATTERN = re.compile(
    r"https?://(?!.*github\.com)(?!localhost)(?!127\.0\.0\.1)[a-zA-Z0-9.\-]+"
)

# Regex to detect environment variable accesses
ENV_VAR_PATTERN = re.compile(r"\$(?:GITHUB_TOKEN|AWS_[A-Z_]+|ACTIONS_[A-Z_]+|SECRET[S]?[_A-Z]*)")

# Base64-looking strings (long alphanum with = padding)
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")


# ─── Extractor ────────────────────────────────────────────────────────────────

def extract_features(filepath: str, label: int = None) -> dict:
    """
    Extract numeric features from a single log file.

    Args:
        filepath: Absolute path to the .log file.
        label: 1 = attack, 0 = benign. None if unknown (for inference).

    Returns:
        Feature dictionary suitable for a Pandas DataFrame row.
    """
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    full_text = " ".join(lines)
    features = {"filename": os.path.basename(filepath)}

    # ── Entropy Features ──────────────────────────────────────────────────────
    entropies = [shannon_entropy(line.strip()) for line in lines if line.strip()]
    features["avg_line_entropy"]  = round(sum(entropies) / len(entropies), 4) if entropies else 0.0
    features["max_line_entropy"]  = round(max(entropies), 4) if entropies else 0.0
    features["high_entropy_count"] = sum(1 for e in entropies if e > 4.5)

    # ── High-Risk Command Counts ──────────────────────────────────────────────
    for pattern in HIGH_RISK_COMMANDS:
        # Use a clean name for the column
        col = re.sub(r"[\\b\s\+\^$.()?*]", "", pattern).strip("_").lower()
        col = f"cmd_{col[:20]}"
        features[col] = len(re.findall(pattern, full_text))

    # ── Network Indicators ────────────────────────────────────────────────────
    features["external_ip_count"]     = len(IP_PATTERN.findall(full_text))
    features["suspicious_url_count"]  = len(SUSPICIOUS_DOMAIN_PATTERN.findall(full_text))
    features["base64_string_count"]   = len(BASE64_PATTERN.findall(full_text))

    # ── Env Var Access ────────────────────────────────────────────────────────
    features["env_var_access_count"]  = len(ENV_VAR_PATTERN.findall(full_text))

    # ── General Stats ─────────────────────────────────────────────────────────
    features["total_lines"]           = len(lines)
    features["error_line_count"]      = sum(1 for l in lines if "ERROR" in l or "error" in l)
    features["run_step_count"]        = sum(1 for l in lines if "[RUN]" in l)

    # ── Label ─────────────────────────────────────────────────────────────────
    if label is not None:
        features["label"] = label  # 1 = attack, 0 = benign

    return features


def build_dataframe(attack_dir: str, benign_dir: str) -> pd.DataFrame:
    """
    Build the full labeled feature DataFrame from attack and benign log folders.

    Args:
        attack_dir: Path to folder with attack .log files.
        benign_dir: Path to folder with benign .log files.

    Returns:
        Labeled Pandas DataFrame ready for ML training.
    """
    rows = []

    for log_file in sorted(os.listdir(attack_dir)):
        if log_file.endswith(".log"):
            path = os.path.join(attack_dir, log_file)
            rows.append(extract_features(path, label=1))

    for log_file in sorted(os.listdir(benign_dir)):
        if log_file.endswith(".log"):
            path = os.path.join(benign_dir, log_file)
            rows.append(extract_features(path, label=0))

    df = pd.DataFrame(rows)
    print(f"[+] Dataset shape: {df.shape}")
    print(f"    Attack samples : {(df['label'] == 1).sum()}")
    print(f"    Benign samples : {(df['label'] == 0).sum()}")
    return df


if __name__ == "__main__":
    base       = os.path.dirname(os.path.abspath(__file__))
    attack_dir = os.path.join(base, "data", "attack_logs")
    benign_dir = os.path.join(base, "data", "benign_logs")
    output_csv = os.path.join(base, "outputs", "features.csv")

    df = build_dataframe(attack_dir, benign_dir)
    df.to_csv(output_csv, index=False)

    print(f"\n[+] Features saved to: {output_csv}")
    print("\n-- Feature Matrix Preview ------------------------------")
    print(df.to_string(max_cols=10, max_rows=20))
