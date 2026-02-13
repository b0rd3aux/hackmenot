"""Parallel scanning implementation using multiprocessing."""

from hackmenot.core.constants import DEFAULT_WORKERS


class ParallelScanner:
    """Parallel scanner for processing files concurrently."""

    def __init__(self, num_workers: int | None = None) -> None:
        """Initialize the ParallelScanner.

        Args:
            num_workers: Number of worker processes to use.
                        Defaults to DEFAULT_WORKERS if None.
        """
        self.num_workers = num_workers if num_workers is not None else DEFAULT_WORKERS
