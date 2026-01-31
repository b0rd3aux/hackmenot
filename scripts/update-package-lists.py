#!/usr/bin/env python3
"""Script to update package lists from registries."""

from pathlib import Path


def fetch_pypi_top_packages(limit: int = 50000) -> list[str]:
    """Fetch top PyPI packages by download count."""
    # TODO: Implement using PyPI stats API or BigQuery
    print(f"TODO: Implement PyPI fetch for {limit} packages")
    return []


def fetch_npm_top_packages(limit: int = 50000) -> list[str]:
    """Fetch top npm packages by download count."""
    # TODO: Implement using npm registry API
    print(f"TODO: Implement npm fetch for {limit} packages")
    return []


if __name__ == "__main__":
    data_dir = Path(__file__).parent.parent / "src" / "hackmenot" / "data"

    pypi_packages = fetch_pypi_top_packages()
    if pypi_packages:
        (data_dir / "pypi_top50k.txt").write_text("\n".join(pypi_packages))
        print(f"Wrote {len(pypi_packages)} PyPI packages")

    npm_packages = fetch_npm_top_packages()
    if npm_packages:
        (data_dir / "npm_top50k.txt").write_text("\n".join(npm_packages))
        print(f"Wrote {len(npm_packages)} npm packages")
