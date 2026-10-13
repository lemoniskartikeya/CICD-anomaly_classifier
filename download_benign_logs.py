"""
download_benign_logs.py — GitHub Actions Log Downloader
Track 3: DFIR Telemetry & ML Anomaly Detection
MIT Bengaluru (MAHE) — Breaking & Hardening the CI/CD Pipeline

Downloads raw build logs from public GitHub repos to use as benign samples.
No GitHub token required — uses public API (60 req/hr unauthenticated).
With a token: 5000 req/hr.

Usage:
    python download_benign_logs.py
    python download_benign_logs.py --token ghp_xxxx --count 50
"""

import os
import sys
import time
import argparse
import zipfile
import io
import requests

# ─── Target Repos (popular open-source, clean CI builds) ─────────────────────

TARGET_REPOS = [
    "pallets/flask",
    "psf/requests",
    "expressjs/express",
    "django/django",
    "numpy/numpy",
    "torvalds/linux",       # will skip if no Actions
    "prettier/prettier",
    "lodash/lodash",
    "fastapi/fastapi",
    "tiangolo/fastapi",
    "pytest-dev/pytest",
    "encode/httpx",
    "aio-libs/aiohttp",
    "python/cpython",
    "scrapy/scrapy",
]

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "benign_logs")
GITHUB_API = "https://api.github.com"


def get_headers(token: str = None) -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def get_completed_runs(repo: str, headers: dict, max_runs: int = 5) -> list:
    """Fetch recent successful workflow runs for a repo."""
    url = f"{GITHUB_API}/repos/{repo}/actions/runs"
    params = {"status": "success", "per_page": max_runs}
    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 404:
            print(f"   [skip] {repo} — no Actions found")
            return []
        if resp.status_code == 403:
            print(f"   [rate-limit] Waiting 60s...")
            time.sleep(60)
            return []
        resp.raise_for_status()
        runs = resp.json().get("workflow_runs", [])
        return runs
    except Exception as e:
        print(f"   [error] {repo}: {e}")
        return []


def download_log_zip(repo: str, run_id: int, headers: dict) -> bytes | None:
    """Download the zipped logs for a workflow run."""
    url = f"{GITHUB_API}/repos/{repo}/actions/runs/{run_id}/logs"
    try:
        resp = requests.get(url, headers=headers, timeout=20, allow_redirects=True)
        if resp.status_code in (404, 410):
            return None  # logs expired
        if resp.status_code == 403:
            print(f"   [rate-limit] Waiting 60s...")
            time.sleep(60)
            return None
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        print(f"   [error] downloading log: {e}")
        return None


def extract_and_save_logs(zip_bytes: bytes, repo: str, run_id: int, saved_count: list, target: int):
    """Extract text log files from zip and save to OUTPUT_DIR."""
    repo_slug = repo.replace("/", "_")
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            log_files = [f for f in zf.namelist() if f.endswith(".txt")]
            for log_file in log_files:
                if saved_count[0] >= target:
                    return
                content = zf.read(log_file).decode("utf-8", errors="ignore")
                if len(content.strip()) < 100:
                    continue  # skip empty/tiny logs

                # Sanitize filename
                safe_name = log_file.replace("/", "_").replace("\\", "_")
                out_filename = f"benign_{repo_slug}_{run_id}_{safe_name}"
                out_path = os.path.join(OUTPUT_DIR, out_filename)

                with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
                    f.write(content)

                saved_count[0] += 1
                print(f"   [+] Saved: {out_filename[:70]} ({saved_count[0]}/{target})")
    except zipfile.BadZipFile:
        pass  # some responses aren't valid zips (redirect HTML etc.)


def main():
    parser = argparse.ArgumentParser(description="Download benign GitHub Actions logs")
    parser.add_argument("--token", default=None, help="GitHub personal access token (optional)")
    parser.add_argument("--count", type=int, default=50, help="Number of log files to download (default: 50)")
    args = parser.parse_args()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    headers = get_headers(args.token)
    saved_count = [0]  # mutable counter

    print(f"\n[*] Downloading {args.count} benign CI/CD logs -> {OUTPUT_DIR}")
    print(f"[*] Token: {'YES (5000 req/hr)' if args.token else 'NO (60 req/hr, may be slow)'}\n")

    for repo in TARGET_REPOS:
        if saved_count[0] >= args.count:
            break

        print(f"\n[>] Repo: {repo}")
        runs = get_completed_runs(repo, headers, max_runs=5)

        for run in runs:
            if saved_count[0] >= args.count:
                break

            run_id = run["id"]
            print(f"   [run] {run_id} — {run.get('name', 'workflow')}")
            zip_bytes = download_log_zip(repo, run_id, headers)

            if zip_bytes:
                extract_and_save_logs(zip_bytes, repo, run_id, saved_count, args.count)

            time.sleep(1)  # polite rate limiting

    print(f"\n[+] Done! Downloaded {saved_count[0]} benign log files.")
    print(f"[+] Saved to: {OUTPUT_DIR}")

    if saved_count[0] < args.count:
        print(f"\n[!] Only got {saved_count[0]}/{args.count} logs.")
        print("    Try adding a GitHub token with --token ghp_xxxx for higher rate limits.")


if __name__ == "__main__":
    main()
