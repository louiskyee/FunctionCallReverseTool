import os
import re
import time
import json
import r2pipe
import logging
import argparse

from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, as_completed

def configure_logging(output_dir: str) -> tuple:
    """
    Configure logging settings.

    Args:
        output_dir (str): Path to the output directory.

    Returns:
        tuple: A tuple containing the extraction_logger and timing_logger objects.
    """
    extraction_log_file = os.path.join(output_dir, f'extraction.log')
    print(f"Logging to: {extraction_log_file}")
    extraction_logger = logging.getLogger('extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    extraction_handler = logging.FileHandler(extraction_log_file)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)

    timing_log_file = os.path.join(output_dir, f'timing.log')
    print(f"Timing log file: {timing_log_file}")
    timing_logger = logging.getLogger('timing_logger')
    timing_logger.setLevel(logging.INFO)
    timing_handler = logging.FileHandler(timing_log_file)
    timing_handler.setFormatter(logging.Formatter('%(asctime)s,%(message)s'))
    timing_logger.addHandler(timing_handler)

    return extraction_logger, timing_logger

def extraction(input_file_path: str, output_folder: str, file_name: str, extraction_logger: logging.Logger, timing_logger: logging.Logger) -> float:
    """
    Extract function call graph and disassembly information from a binary file.

    Args:
        input_file_path (str): Path to the input binary file.
        output_folder (str): Path to the output folder where the extracted files will be saved.
        file_name (str): Name of the binary file.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.  
    """
    start_time = time.time()
    r2 = None

    try:
        r2 = r2pipe.open(input_file_path, flags=["-2"])
        r2.cmd("aaa")  # Enhanced analysis

        functions = r2.cmd(f'agCd')

        if not functions:
            raise ValueError(f"No functions found for file: {input_file_path}")
        
        os.makedirs(output_folder, exist_ok=True)

        dot_file_path = os.path.join(output_folder, f"{file_name}.dot")
        json_file_path = os.path.join(output_folder, f"{file_name}.json")

        function_call_graph = ['digraph code {']
        functions_info = {}
        
        EDGE_START_IDX = 6
        EDGE_END_IDX = -2
        pattern = r'\"(0x[0-9a-fA-F]+)\" \[label=\"([^\"]+)\"\];'

        for function in functions.split('\n')[EDGE_START_IDX:EDGE_END_IDX]:
            function = re.sub(r' URL="[^"]*"', '', function)
            function = re.sub(r' \[.*color=[^\]]*\]', '', function)
            function_call_graph.append(function)

            match = re.search(pattern, function)
            if not match:
                if 'label' in function:
                    extraction_logger.warning(f"{file_name}: No match found for function: {function}")
                continue

            address, name = match.groups()
            functions_info[address] = {
                "function_name": name,
                "instructions": []
            }

            try:
                instructions = r2.cmdj(f'pdfj @ {address}')['ops']
                for inst in instructions:
                    disasm = inst.get('disasm', 'invalid')
                    functions_info[address]['instructions'].append(disasm)
            except Exception as e:
                extraction_logger.error(f"{file_name}: Error extracting instructions at \"{address}\" for function \"{name}\": {e}")
                functions_info[address]['instructions'].append(f"error")

        function_call_graph.append('}')

        with open(dot_file_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(function_call_graph))

        with open(json_file_path, 'w') as f:
            json.dump(functions_info, f, indent=4)

    except FileNotFoundError:
        extraction_logger.error(f"{file_name}: File not found: {input_file_path}")
    except ValueError as ve:
        extraction_logger.error(f"{file_name}: {str(ve)}")
    except Exception as e:
        extraction_logger.exception(f"{file_name}: An unexpected error occurred: {e}")
    finally:
        if r2:
            r2.quit()

    end_time = time.time()
    execution_time = end_time - start_time
    timing_logger.info(f"{file_name},{execution_time:.2f} seconds")

def get_args(binary_path: str, output_path: str, extraction_logger: logging.Logger, timing_logger: logging.Logger) -> list:
    """
    Generate a list of arguments for parallel processing.

    Args:
        binary_path (str): Path to the binary directory.
        output_path (str): Path to the output directory.
        extraction_logger (logging.Logger): Logger object for recording the extraction process.
        timing_logger (logging.Logger): Logger object for recording execution time.

    Returns:
        list: A list of tuples containing the binary file path, output directory path, file name, and loggers.
    """
    args = []
    for root, _, files in os.walk(binary_path):
        for file in files:
            if '.' not in file:
                binary_file_path = os.path.join(root, file)
                relative_path = os.path.relpath(root, binary_path)
                output_dir_path = os.path.normpath(os.path.join(output_path, "results", relative_path, file))
                args.append((binary_file_path, output_dir_path, file, extraction_logger, timing_logger))
    return args

def parallel_process(args: list) -> None:
    """
    Process the extraction tasks in parallel.

    Args:
        args (list): A list of tuples containing the binary file path, output directory path, file name, and loggers.
    """
    with ProcessPoolExecutor(max_workers=os.cpu_count()) as executor:
        futures = [executor.submit(extraction, *arg) for arg in args]
        for _ in tqdm(as_completed(futures), total=len(futures), desc="Processing files", unit="file"):
            pass

def setup_output_directory(input_dir: str) -> str:
    """
    Set up the output directory for storing the extracted files.

    Args:
        input_dir (str): Path to the input directory.

    Returns:
        str: Path to the output directory.
    """
    output_dir = os.path.join(os.path.dirname(input_dir), f"{os.path.basename(input_dir)}_disassemble")
    print(f"Output directory: {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    results_dir = os.path.join(output_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    return output_dir

def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(description='Extract function call graph and disassembly information from binary files.')
    parser.add_argument('-d', '--directory', type=str, required=True, help='Path to the binary directory')
    args = parser.parse_args()
    args.directory = os.path.normpath(os.path.expanduser(args.directory))
    return args

def main() -> None:
    """
    Main function to orchestrate the extraction process.
    """
    args = parse_arguments()

    input_dir = args.directory
    output_dir = setup_output_directory(input_dir)
    extraction_logger, timing_logger = configure_logging(output_dir)

    parallel_process(get_args(input_dir, output_dir, extraction_logger, timing_logger))

if __name__ == "__main__":
    main()
