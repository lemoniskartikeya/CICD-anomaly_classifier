"""
entropy.py — Shannon Entropy Calculator
Track 3: DFIR Telemetry & ML Anomaly Detection
MIT Bengaluru (MAHE) — Breaking & Hardening the CI/CD Pipeline

High entropy lines in build logs indicate obfuscated data (base64 tokens,
encoded payloads, cryptographic strings) which are key attack indicators.
"""

import math
import os
import sys
from collections import Counter


def shannon_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a given string.
    Higher entropy = more randomness = more suspicious (e.g., base64, tokens).

    Args:
        text: The string to calculate entropy for.

    Returns:
        Entropy value in bits (float). Range: 0.0 (uniform) to ~6.0+ (highly random).
    """
    if not text:
        return 0.0

    freq = Counter(text)
    length = len(text)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)


def analyze_log_file(filepath: str) -> dict:
    """
    Analyze a single log file and return per-line entropy stats.

    Args:
        filepath: Path to the .log file.

    Returns:
        Dictionary with filename, per-line entropy, max, avg entropy.
    """
    results = {
        "file": os.path.basename(filepath),
        "lines": [],
        "max_entropy": 0.0,
        "avg_entropy": 0.0,
        "high_entropy_lines": [],  # lines with entropy > 4.5 (suspicious threshold)
    }

    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    entropies = []
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        ent = shannon_entropy(stripped)
        entropies.append(ent)
        results["lines"].append({"line_no": i, "entropy": ent, "content": stripped[:120]})
        if ent > 4.5:
            results["high_entropy_lines"].append({"line_no": i, "entropy": ent, "content": stripped[:120]})

    if entropies:
        results["max_entropy"] = round(max(entropies), 4)
        results["avg_entropy"] = round(sum(entropies) / len(entropies), 4)

    return results


def analyze_directory(dirpath: str) -> list:
    """
    Analyze all .log files in a directory.

    Args:
        dirpath: Path to directory containing log files.

    Returns:
        List of result dicts, one per log file.
    """
    all_results = []
    log_files = [f for f in os.listdir(dirpath) if f.endswith(".log")]

    if not log_files:
        print(f"[!] No .log files found in {dirpath}")
        return all_results

    for filename in sorted(log_files):
        filepath = os.path.join(dirpath, filename)
        result = analyze_log_file(filepath)
        all_results.append(result)

    return all_results


def print_report(results: list) -> None:
    """Pretty-print entropy analysis results to terminal."""
    print("\n" + "=" * 60)
    print("  SHANNON ENTROPY REPORT — CI/CD Log Analysis")
    print("=" * 60)

    for r in results:
        print(f"\n[FILE] {r['file']}")
        print(f"   Avg Entropy : {r['avg_entropy']} bits")
        print(f"   Max Entropy : {r['max_entropy']} bits")
        print(f"   [!] High-Entropy Lines (>4.5 bits): {len(r['high_entropy_lines'])}")
        for hl in r["high_entropy_lines"]:
            print(f"      Line {hl['line_no']:>3} [{hl['entropy']}]: {hl['content'][:80]}")

    print("\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    # Default: analyze both attack and benign log folders
    base = os.path.dirname(os.path.abspath(__file__))

    folders = {
        "ATTACK LOGS": os.path.join(base, "data", "attack_logs"),
        "BENIGN LOGS": os.path.join(base, "data", "benign_logs"),
    }

    for label, folder in folders.items():
        if not os.path.exists(folder):
            print(f"[!] Folder not found: {folder}")
            continue
        print(f"\n{'='*60}\n  Analyzing: {label}\n{'='*60}")
        results = analyze_directory(folder)
        print_report(results)
