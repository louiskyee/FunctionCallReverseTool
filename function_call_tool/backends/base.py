import os
import argparse
import logging
from abc import ABC, abstractmethod
from typing import Dict

SCRIPTS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), '..', '..', 'scripts')
)


class BaseBackend(ABC):
    """Abstract base class for function call extraction backends."""

    worker_multiplier = 2

    def __init__(self, args: argparse.Namespace, output_dir: str):
        self.args = args
        self.output_dir = output_dir

    @classmethod
    @abstractmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        """Inject backend-specific CLI arguments into the parser."""
        ...

    @abstractmethod
    def validate_environment(self) -> None:
        """Check that the backend tool is available.

        Raises:
            RuntimeError: If the backend tool is not found or not usable.
        """
        ...

    @abstractmethod
    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> Dict:
        """Extract function call graph and disassembly from a binary file.

        Args:
            input_file: Path to the binary file.
            timeout: Maximum seconds to allow for extraction.
            extraction_logger: Logger for recording errors.

        Returns:
            Dict with keys:
            - 'dot_content' (str): DOT format call graph
            - 'functions' (dict): Function info with instructions
            Empty dict if extraction failed.
        """
        ...

    def cleanup(self) -> None:
        """Clean up backend-specific temporary resources. Default: no-op."""
        pass
