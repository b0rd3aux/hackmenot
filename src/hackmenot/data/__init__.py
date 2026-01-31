"""Package database for dependency scanning."""

from pathlib import Path

DATA_DIR = Path(__file__).parent


def load_package_set(ecosystem: str) -> set[str]:
    """Load package names for an ecosystem into a set."""
    filename = f"{ecosystem.lower()}_top50k.txt"
    filepath = DATA_DIR / filename
    if not filepath.exists():
        return set()
    return set(line.strip().lower() for line in filepath.read_text().strip().split("\n") if line.strip())
