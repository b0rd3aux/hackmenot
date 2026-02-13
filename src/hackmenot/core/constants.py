"""Core constants for hackmenot."""

import os

# Scanner constants
DEFAULT_WORKERS = min(32, (os.cpu_count() or 1) + 4)
WORKER_QUEUE_TIMEOUT = 1.0  # seconds, timeout for worker queue.get() calls
WORKER_SHUTDOWN_TIMEOUT = 10.0  # seconds, max time to wait for workers to finish
WORK_QUEUE_MAXSIZE = 1000  # Max files queued for distribution (provides backpressure)

# File extension sets by language
PYTHON_EXTENSIONS = {".py"}
JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
GO_EXTENSIONS = {".go"}
TERRAFORM_EXTENSIONS = {".tf", ".tfvars"}
RUST_EXTENSIONS = {".rs"}
JAVA_EXTENSIONS = {".java"}

# Derived set of all supported extensions
SUPPORTED_EXTENSIONS = (
    PYTHON_EXTENSIONS
    | JS_EXTENSIONS
    | GO_EXTENSIONS
    | TERRAFORM_EXTENSIONS
    | RUST_EXTENSIONS
    | JAVA_EXTENSIONS
)

# Directories to skip during scanning
SKIP_DIRS = frozenset(
    {
        "node_modules",
        "__pycache__",
        ".git",
        ".hg",
        ".svn",
        "venv",
        ".venv",
        "env",
        ".env",
        ".tox",
        ".nox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".eggs",
        "vendor",
        "third_party",
        ".terraform",
    }
)

# OSV API constants
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_API_URL = "https://api.osv.dev/v1/querybatch"
OSV_TIMEOUT = 10
OSV_MAX_RETRIES = 3
OSV_RETRY_DELAY = 1.0  # seconds, will be multiplied by exponential backoff
