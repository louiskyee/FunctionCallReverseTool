import os
import re
import shutil
import logging
import argparse
import subprocess
from typing import Dict
from contextlib import contextmanager

import r2pipe

from function_call_tool.backends.base import BaseBackend, SCRIPTS_DIR

R2_TIMEOUT_SCRIPT = 'r2_timeout_check.sh'


class Radare2Backend(BaseBackend):
    """Radare2-based function call extraction backend."""

    # r2pipe spawns r2 processes; keep worker count conservative
    worker_multiplier = 1

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        pass

    def validate_environment(self) -> None:
        if not shutil.which('r2'):
            raise RuntimeError(
                "Radare2 (r2) not found on PATH. "
                "Please install Radare2 first."
            )
        script_path = os.path.join(SCRIPTS_DIR, R2_TIMEOUT_SCRIPT)
        if not os.path.exists(script_path):
            raise RuntimeError(
                f"{R2_TIMEOUT_SCRIPT} not found in {SCRIPTS_DIR}"
            )
        if not os.access(script_path, os.X_OK):
            raise RuntimeError(
                f"{R2_TIMEOUT_SCRIPT} in {SCRIPTS_DIR} is not executable"
            )

    def extract_features(self, input_file: str, timeout: int,
                         extraction_logger: logging.Logger) -> Dict:
        file_name = os.path.basename(input_file)

        # Pre-flight timeout check
        if not self._check_timeout(input_file, timeout):
            extraction_logger.error(
                f"{file_name}: File analysis timed out "
                f"after {timeout} seconds"
            )
            return {}

        try:
            with self._open_r2pipe(input_file) as r2:
                r2.cmd("aaa")
                functions = r2.cmd('agCd')

                if not functions:
                    extraction_logger.error(
                        f"{file_name}: No functions found - "
                        f"file may be packed, damaged, or incomplete"
                    )
                    return {}

                function_call_graph = ['digraph code {']
                functions_info = {}

                EDGE_START_IDX = 6
                EDGE_END_IDX = -2
                pattern = r'\"(0x[0-9a-fA-F]+)\" \[label=\"([^\"]+)\"\];'

                for line in functions.split('\n')[EDGE_START_IDX:EDGE_END_IDX]:
                    line = re.sub(r' URL="[^"]*"', '', line)
                    line = re.sub(r' \[.*color=[^\]]*\]', '', line)
                    function_call_graph.append(line)

                    match = re.search(pattern, line)
                    if not match:
                        if 'label' in line:
                            extraction_logger.warning(
                                f"{file_name}: No match found "
                                f"for function: {line}"
                            )
                        continue

                    address, name = match.groups()
                    functions_info[address] = {
                        "function_name": name,
                        "instructions": []
                    }

                    try:
                        instructions = r2.cmdj(
                            f'pdfj @ {address}'
                        )['ops']
                        for inst in instructions:
                            disasm = inst.get('disasm', 'invalid')
                            functions_info[address]['instructions'].append(
                                disasm
                            )
                    except Exception as e:
                        extraction_logger.error(
                            f"{file_name}: Error extracting instructions "
                            f"at \"{address}\" for function "
                            f"\"{name}\": {e}"
                        )
                        functions_info[address]['instructions'].append(
                            "error"
                        )

                function_call_graph.append('}')

                dot_content = '\n'.join(function_call_graph)
                return {
                    'dot_content': dot_content,
                    'functions': functions_info
                }

        except Exception as e:
            extraction_logger.error(
                f"{file_name}: Unexpected error - {e}"
            )
            return {}

    @staticmethod
    def _check_timeout(input_file: str, timeout: int) -> bool:
        """Run pre-flight timeout check using r2_timeout_check.sh."""
        script_path = os.path.join(SCRIPTS_DIR, R2_TIMEOUT_SCRIPT)
        try:
            result = subprocess.run(
                [script_path, input_file, str(timeout)],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip() == "true"
        except subprocess.CalledProcessError:
            return False

    @staticmethod
    @contextmanager
    def _open_r2pipe(file_path: str):
        """Context manager for r2pipe to ensure proper cleanup."""
        r2 = None
        try:
            r2 = r2pipe.open(file_path, flags=['-2'])
            yield r2
        finally:
            if r2:
                r2.quit()
