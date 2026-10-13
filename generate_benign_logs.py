"""
generate_benign_logs.py — Synthetic Benign CI/CD Log Generator
Track 3: DFIR Telemetry & ML Anomaly Detection
MIT Bengaluru (MAHE) — Breaking & Hardening the CI/CD Pipeline

Generates realistic benign GitHub Actions build logs for ML training.
These mimic real logs from projects like flask, requests, pytest, etc.
"""

import os
import random
from datetime import datetime, timedelta

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "benign_logs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Realistic log templates ───────────────────────────────────────────────────

REPOS = [
    "pallets/flask", "psf/requests", "pytest-dev/pytest", "encode/httpx",
    "fastapi/fastapi", "django/django", "numpy/numpy", "scrapy/scrapy",
    "aio-libs/aiohttp", "python/cpython", "prettier/prettier", "lodash/lodash",
    "expressjs/express", "vuejs/vue", "facebook/react", "torvalds/linux",
    "rust-lang/rust", "golang/go", "rails/rails", "laravel/laravel",
]

RUNNERS = ["ubuntu-22.04", "ubuntu-20.04", "ubuntu-latest", "macos-13", "windows-2022"]

PYTHON_VERSIONS = ["3.9", "3.10", "3.11", "3.12"]
NODE_VERSIONS   = ["16.x", "18.x", "20.x"]
JAVA_VERSIONS   = ["11", "17", "21"]

TEST_FRAMEWORKS = [
    ("pytest", "Python"),
    ("jest", "Node"),
    ("mocha", "Node"),
    ("junit", "Java"),
    ("rspec", "Ruby"),
    ("cargo test", "Rust"),
    ("go test ./...", "Go"),
]

LINTERS = ["flake8", "ruff", "eslint", "pylint", "mypy", "black --check", "prettier --check"]

RANDOM_SHAS   = [f"a{i:07x}" for i in range(1, 200)]
RANDOM_PRNUMS = list(range(100, 2000))


def rand_ts(base: datetime, offset_seconds: int) -> str:
    return (base + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rand_duration() -> int:
    return random.randint(1, 8)


def make_python_log(repo, runner, py_ver, base_ts, test_pass, run_id) -> str:
    t = 0
    lines = []

    def add(msg, tag="INFO"):
        nonlocal t
        lines.append(f"{rand_ts(base_ts, t)} [{tag}] {msg}")
        t += rand_duration()

    sha = random.choice(RANDOM_SHAS)
    pr  = random.choice(RANDOM_PRNUMS)

    add(f"Runner: {runner}, Job: test (Python {py_ver})")
    add(f"Checking out {repo}@{sha}")
    add(f"Set up Python {py_ver}")
    add(f"Cache hit for pip packages (key: pip-{py_ver}-{sha[:6]})")
    add(f"pip install -r requirements.txt")
    add(f"Collecting flask==3.0.3")
    add(f"Collecting Werkzeug>=3.0.0")
    add(f"Collecting click>=8.1.3")
    add(f"Collecting itsdangerous>=2.1.2")
    add(f"Successfully installed flask-3.0.3 Werkzeug-3.0.3")
    add(f"pip install pytest pytest-cov")
    add(f"Successfully installed pytest-8.1.1 pytest-cov-5.0.0")

    # Linting
    linter = random.choice(["flake8", "ruff", "black --check", "mypy"])
    add(f"Running {linter} .")
    if random.random() < 0.85:
        add(f"{linter}: All checks passed.")
    else:
        add(f"{linter}: 2 warnings (line length)", tag="WARN")

    # Tests
    n_tests  = random.randint(30, 250)
    n_passed = n_tests if test_pass else n_tests - random.randint(1, 3)
    n_failed = n_tests - n_passed
    add(f"pytest tests/ -v --cov=src --cov-report=xml")
    add(f"collected {n_tests} items")
    for i in range(min(6, n_tests)):
        add(f"tests/test_core.py::test_case_{i+1} PASSED")
    add(f"... ({n_tests - 6} more tests) ...")
    if n_failed == 0:
        add(f"{n_passed} passed in {random.randint(3,30)}s")
    else:
        add(f"{n_passed} passed, {n_failed} failed in {random.randint(3,30)}s", tag="WARN")

    add(f"Coverage: {random.randint(72, 98)}%")
    add(f"Uploading coverage report to Codecov")
    add(f"Coverage uploaded successfully")
    add(f"Job finished with status: {'success' if test_pass else 'failure'}")

    return "\n".join(lines)


def make_node_log(repo, runner, node_ver, base_ts, test_pass, run_id) -> str:
    t = 0
    lines = []

    def add(msg, tag="INFO"):
        nonlocal t
        lines.append(f"{rand_ts(base_ts, t)} [{tag}] {msg}")
        t += rand_duration()

    sha = random.choice(RANDOM_SHAS)
    add(f"Runner: {runner}, Job: build (Node {node_ver})")
    add(f"Checking out {repo}@{sha}")
    add(f"Set up Node.js {node_ver}")
    add(f"Cache hit for npm packages")
    add(f"npm ci")
    add(f"added {random.randint(100,800)} packages in {random.randint(5,30)}s")
    add(f"npm run lint")
    add(f"eslint src/ --ext .js,.ts")
    add(f"ESLint: no warnings")
    add(f"npm run build")
    add(f"webpack compiled successfully in {random.randint(2000,8000)}ms")
    add(f"npm test")
    n_tests  = random.randint(20, 120)
    n_passed = n_tests if test_pass else n_tests - random.randint(1, 2)
    add(f"PASS src/__tests__/core.test.js")
    add(f"PASS src/__tests__/utils.test.js")
    add(f"Tests: {n_passed} passed, {n_tests - n_passed} failed, {n_tests} total")
    add(f"Snapshot summary: {random.randint(0, 5)} obsolete snapshots")
    add(f"Done in {random.randint(10,60)}s")

    return "\n".join(lines)


def make_docker_log(repo, runner, base_ts, run_id) -> str:
    t = 0
    lines = []

    def add(msg, tag="INFO"):
        nonlocal t
        lines.append(f"{rand_ts(base_ts, t)} [{tag}] {msg}")
        t += rand_duration()

    sha = random.choice(RANDOM_SHAS)
    tag_ver = f"v{random.randint(1,4)}.{random.randint(0,9)}.{random.randint(0,9)}"

    add(f"Runner: {runner}, Job: docker-publish")
    add(f"Checking out {repo}@{sha}")
    add(f"Set up Docker Buildx")
    add(f"Login to GitHub Container Registry (ghcr.io)")
    add(f"Login Succeeded")
    add(f"docker build --tag ghcr.io/{repo}:{tag_ver} .")
    add(f"Step 1/8 : FROM python:3.11-slim")
    add(f"Step 2/8 : WORKDIR /app")
    add(f"Step 3/8 : COPY requirements.txt .")
    add(f"Step 4/8 : RUN pip install -r requirements.txt")
    add(f"Step 5/8 : COPY . .")
    add(f"Step 6/8 : EXPOSE 8000")
    add(f"Step 7/8 : CMD [\"gunicorn\", \"app:app\"]")
    add(f"Step 8/8 : Successfully built {random.choice(RANDOM_SHAS)}")
    add(f"docker push ghcr.io/{repo}:{tag_ver}")
    add(f"The push refers to repository [ghcr.io/{repo}]")
    add(f"Image pushed successfully")
    add(f"Job finished with status: success")

    return "\n".join(lines)


def make_release_log(repo, runner, base_ts, run_id) -> str:
    t = 0
    lines = []

    def add(msg, tag="INFO"):
        nonlocal t
        lines.append(f"{rand_ts(base_ts, t)} [{tag}] {msg}")
        t += rand_duration()

    sha = random.choice(RANDOM_SHAS)
    ver = f"v{random.randint(1,5)}.{random.randint(0,12)}.{random.randint(0,9)}"

    add(f"Runner: {runner}, Job: release")
    add(f"Checking out {repo}@{sha} (tag: {ver})")
    add(f"Set up Python 3.11")
    add(f"pip install build twine")
    add(f"python -m build")
    add(f"Successfully built dist/{repo.split('/')[1]}-{ver[1:]}.tar.gz")
    add(f"twine check dist/*")
    add(f"Checking dist/app-{ver[1:]}.tar.gz: PASSED")
    add(f"twine upload dist/* --skip-existing")
    add(f"Uploading distributions to https://upload.pypi.org/legacy/")
    add(f"Uploading {repo.split('/')[1]}-{ver[1:]}.tar.gz")
    add(f"View at: https://pypi.org/project/{repo.split('/')[1]}/{ver[1:]}/")
    add(f"gh release create {ver} --generate-notes")
    add(f"Release {ver} created successfully")

    return "\n".join(lines)


# ── Generate 50 logs ──────────────────────────────────────────────────────────

LOG_TYPES = ["python", "python", "python", "node", "node", "docker", "release"]

print(f"\n[*] Generating 50 synthetic benign logs -> {OUTPUT_DIR}\n")

for i in range(1, 51):
    repo      = random.choice(REPOS)
    runner    = random.choice(RUNNERS)
    log_type  = random.choice(LOG_TYPES)
    base_ts   = datetime(2026, random.randint(1, 8), random.randint(1, 28),
                         random.randint(0, 23), random.randint(0, 59))
    test_pass = random.random() > 0.1  # 90% pass rate

    if log_type == "python":
        content = make_python_log(repo, runner, random.choice(PYTHON_VERSIONS), base_ts, test_pass, i)
    elif log_type == "node":
        content = make_node_log(repo, runner, random.choice(NODE_VERSIONS), base_ts, test_pass, i)
    elif log_type == "docker":
        content = make_docker_log(repo, runner, base_ts, i)
    else:
        content = make_release_log(repo, runner, base_ts, i)

    slug     = repo.replace("/", "_")
    filename = f"benign_{i:02d}_{slug}_{log_type}.log"
    filepath = os.path.join(OUTPUT_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"  [{i:02d}/50] {filename}")

print(f"\n[+] Done! 50 benign logs saved to {OUTPUT_DIR}")
