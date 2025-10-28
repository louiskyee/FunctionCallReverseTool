import os
import time
import shutil
import logging
import argparse
import subprocess

from tqdm import tqdm
from typing import List, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed

# Constants
RESULTS_SUBDIR = "results"
GHIDRA_PROJECTS_SUBDIR = "ghidra_projects"
DEFAULT_TIMEOUT_SECONDS = 600
PYTHON_SCRIPT_NAME = "ghidra_function_script.py"

def configure_logging(output_dir: str) -> logging.Logger:
    """
    Configure logging settings.

    Args:
        output_dir (str): Path to the output directory.

    Returns:
        logging.Logger: The extraction_logger object.
    """
    extraction_log_file = os.path.join(output_dir, 'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    # Clear existing handlers to avoid duplication
    extraction_logger.handlers.clear()
    extraction_handler = logging.FileHandler(extraction_log_file)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)

    return extraction_logger

def extract_features(input_file_path: str, output_dir: str, ghidra_headless_path: str,
                    timeout_seconds: int, extraction_logger: logging.Logger) -> bool:
    """
    Extract features from the input file using Ghidra.

    Args:
        input_file_path (str): Path to the input file.
        output_dir (str): Path to the output directory.
        ghidra_headless_path (str): Path to Ghidra headless analyzer.
        timeout_seconds (int): Timeout duration in seconds.
        extraction_logger (logging.Logger): Logger object for recording errors.

    Returns:
        bool: True if extraction succeeded, False otherwise.
    """
    file_name = os.path.basename(input_file_path)
    project_name = f"{file_name}_project"
    project_folder = os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR, project_name)
    results_folder = os.path.join(output_dir, RESULTS_SUBDIR)

    # Create temporary project folder
    os.makedirs(project_folder, exist_ok=True)

    # Get script path
    script_directory = os.path.dirname(os.path.abspath(__file__))
    python_script_path = os.path.join(script_directory, PYTHON_SCRIPT_NAME)

    try:
        # Run Ghidra headless analyzer with timeout
        result = subprocess.run([
            'timeout', '--kill-after=10', str(timeout_seconds),
            ghidra_headless_path, project_folder, project_name,
            '-import', input_file_path,
            '-scriptPath', script_directory,
            '-postScript', PYTHON_SCRIPT_NAME,
            output_dir, results_folder
        ], capture_output=True, text=True)

        # Check if the process timed out (exit code 124)
        if result.returncode == 124:
            extraction_logger.error(f"{file_name}: File analysis timed out after {timeout_seconds} seconds")
            return False

        # Check if there were other errors
        if result.returncode != 0:
            extraction_logger.error(f"{file_name}: Ghidra analysis failed with exit code {result.returncode}")
            if result.stderr:
                extraction_logger.error(f"{file_name}: {result.stderr}")
            return False

        # Check if the output files were generated
        output_folder_path = os.path.join(results_folder, file_name)
        dot_file_path = os.path.join(output_folder_path, f"{file_name}.dot")
        json_file_path = os.path.join(output_folder_path, f"{file_name}.json")

        if os.path.exists(dot_file_path) and os.path.exists(json_file_path):
            return True
        else:
            extraction_logger.error(f"{file_name}: Output files not found")
            return False

    except Exception as e:
        extraction_logger.error(f"{file_name}: Unexpected error - {e}")
        return False
    finally:
        # Clean up temporary project folder
        if os.path.exists(project_folder):
            shutil.rmtree(project_folder, ignore_errors=True)

def extraction(input_file_path: str, output_folder: str, file_name: str,
              extraction_logger: logging.Logger,
              output_dir: str, ghidra_headless_path: str, timeout_seconds: int) -> float:
    """
    Extract function call graph and disassembly information from the specified file and save to DOT and JSON files.

    Args:
        input_file_path (str): File path of the target file.
        output_folder (str): Folder path for the output files.
        file_name (str): Name of the target file.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        output_dir (str): Output directory path.
        ghidra_headless_path (str): Path to Ghidra headless analyzer.
        timeout_seconds (int): Timeout duration in seconds.

    Returns:
        float: Execution time of the extraction process, or 0 if failed.
    """
    dot_file_path = os.path.join(output_folder, f"{file_name}.dot")
    json_file_path = os.path.join(output_folder, f"{file_name}.json")

    # Check if output files already exist
    if os.path.exists(dot_file_path) and os.path.exists(json_file_path):
        extraction_logger.info(f"Files already exist: {dot_file_path}, {json_file_path}")
        return 0

    start_time = time.process_time()

    try:
        success = extract_features(input_file_path, output_dir, ghidra_headless_path,
                                   timeout_seconds, extraction_logger)

        if not success:
            # Error already logged by extract_features
            return 0

        execution_time = time.process_time() - start_time
        # Timing is logged by ghidra_function_script.py for Ghidra analysis time only
        # Output files are already created by ghidra_function_script.py
        return execution_time

    except FileNotFoundError:
        extraction_logger.error(f"{file_name}: File not found - {input_file_path}")
    except Exception as e:
        extraction_logger.exception(f"{file_name}: Unexpected error - {e}")

    return 0

def get_args(binary_path: str, output_path: str, extraction_logger: logging.Logger,
            ghidra_headless_path: str, timeout_seconds: int) -> List[Tuple]:
    """
    Generate a list of arguments for parallel processing.

    Args:
        binary_path (str): Path to the binary directory.
        output_path (str): Path to the output directory.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        ghidra_headless_path (str): Path to Ghidra headless analyzer.
        timeout_seconds (int): Timeout duration in seconds.

    Returns:
        List[Tuple]: A list of tuples containing the binary file path, output folder path, file name, logger, and processing information.
    """
    args = []
    for root, _, files in os.walk(binary_path):
        for file in files:
            if '.' not in file:
                binary_file_path = os.path.join(root, file)
                output_folder_path = os.path.normpath(os.path.join(output_path, RESULTS_SUBDIR, file))
                # Don't create directory here - will be created when needed
                args.append((binary_file_path, output_folder_path, file, extraction_logger,
                           output_path, ghidra_headless_path, timeout_seconds))
    return args

def parallel_process(args: List[Tuple]) -> None:
    """
    Process the extraction tasks in parallel.

    Args:
        args (List[Tuple]): A list of tuples containing the binary file path, output folder path, file name, loggers, and processing information.
    """
    # Use 2x CPU count since Ghidra spends most time waiting for I/O
    max_workers = os.cpu_count() * 2
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(extraction, *arg) for arg in args]
        with tqdm(total=len(futures), desc="Processing files", unit="file") as pbar:
            for _ in as_completed(futures):
                pbar.update(1)

def setup_output_directory(input_dir: str, custom_output_dir: str = None) -> str:
    """
    Set up the output directory for storing the extracted files.

    Args:
        input_dir (str): Path to the input directory.
        custom_output_dir (str, optional): Custom output directory path. If None, uses default naming.

    Returns:
        str: Path to the output directory.
    """
    if custom_output_dir:
        output_dir = custom_output_dir
    else:
        output_dir = os.path.join(os.path.dirname(input_dir), f"{os.path.basename(input_dir)}_disassemble")

    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(output_dir, RESULTS_SUBDIR)
    os.makedirs(results_dir, exist_ok=True)
    ghidra_projects_dir = os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR)
    os.makedirs(ghidra_projects_dir, exist_ok=True)
    return output_dir

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Extract function call graph and disassembly information from binary files using Ghidra.')
    parser.add_argument('-d', '--directory', type=str, required=True, help='Path to the binary directory')
    parser.add_argument('-g', '--ghidra', type=str, required=True, help='Path to Ghidra headless analyzer (analyzeHeadless)')
    parser.add_argument('-o', '--output', type=str, help='Path to the output directory (default: <input_dir>_disassemble)')
    parser.add_argument('-t', '--timeout', type=int, default=DEFAULT_TIMEOUT_SECONDS,
                       help=f'Timeout duration in seconds (default: {DEFAULT_TIMEOUT_SECONDS})')
    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    args.ghidra = os.path.normpath(os.path.expanduser(args.ghidra))
    if args.output:
        args.output = os.path.normpath(os.path.expanduser(args.output))
    return args

def main() -> None:
    """
    Main function to orchestrate the extraction process.
    """
    args = parse_arguments()

    # Verify Ghidra headless path exists
    if not os.path.exists(args.ghidra):
        print(f"Error: Ghidra headless analyzer not found at {args.ghidra}")
        return

    input_dir = args.directory
    output_dir = setup_output_directory(input_dir, args.output)
    extraction_logger = configure_logging(output_dir)

    parallel_process(get_args(input_dir, output_dir, extraction_logger,
                              args.ghidra, args.timeout))

    # Clean up ghidra_projects directory
    ghidra_projects_dir = os.path.join(output_dir, GHIDRA_PROJECTS_SUBDIR)
    if os.path.exists(ghidra_projects_dir):
        shutil.rmtree(ghidra_projects_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
