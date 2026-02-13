"""Parallel scanning implementation using multiprocessing."""

import os


class ParallelScanner:
    """Parallel scanner for processing files concurrently."""

    def __init__(self, num_workers: int | None = None) -> None:
        """Initialize the ParallelScanner.

        Args:
            num_workers: Number of worker processes to use.
                        Defaults to os.cpu_count() if None.
        """
        self.num_workers = num_workers if num_workers is not None else os.cpu_count()
