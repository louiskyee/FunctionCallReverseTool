import os
import json
import time
import logging

# Get script arguments
argv = getScriptArgs()

# Configure extraction logger
def configure_extraction_logger(output_folder):
    """Configure extraction logger with proper handler management."""
    log_file_path = os.path.join(output_folder, 'extraction.log')
    extraction_logger = logging.getLogger('ghidra_extraction_logger')
    extraction_logger.setLevel(logging.INFO)
    # Clear existing handlers to avoid duplication
    extraction_logger.handlers = []
    extraction_handler = logging.FileHandler(log_file_path)
    extraction_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    extraction_logger.addHandler(extraction_handler)
    return extraction_logger

try:
    # Set save folder
    if len(argv) == 2:
        output_folder = argv[0]
        results_folder = argv[1]
    elif len(argv) == 1:
        output_folder = argv[0]
        results_folder = os.path.join(output_folder, 'results')
    elif len(argv) == 0:
        output_folder = os.getcwd()
        results_folder = os.path.join(os.getcwd(), 'results')
    else:
        raise ValueError("Invalid number of arguments")
except Exception as e:
    # Use basic logging for parameter setup errors
    error_message = "An error occurred while setting parameters: {}".format(e)
    print("ERROR: " + error_message)
    raise

program_name = currentProgram.getName()
program_folder = os.path.join(results_folder, program_name)

# Create the program-specific directory
if not os.path.exists(program_folder):
    os.makedirs(program_folder)

# Set up logging with dedicated logger
extraction_logger = configure_extraction_logger(output_folder)

# Determine file paths for DOT file and JSON file
dot_file_path = os.path.join(program_folder, program_name + '.dot')
json_file_path = os.path.join(program_folder, program_name + '.json')

try:
    # Record start time (CPU time)
    start_time = time.process_time()

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    # Check if functions exist
    func_list = list(funcs)
    if not func_list:
        extraction_logger.error("{}: No functions found - file may be packed, damaged, or incomplete".format(program_name))
        raise Exception("No functions found")

    dot_lines = ["digraph code {"]
    functions_info = {}

    # Collecting all function information
    for func in func_list:
        entry_point = func.getEntryPoint()
        entry_point_offset = hex(entry_point.getOffset())
        name = func.getName()

        # Prepare function information for JSON
        functions_info[entry_point_offset] = {
            "function_name": name,
            "instructions": []
        }

        dot_lines.append('  "{}" [label="{}"];'.format(entry_point_offset, name))

        # Extracting instructions for each function
        try:
            for instruction in currentProgram.getListing().getInstructions(func.getBody(), True):
                disasm = str(instruction)
                functions_info[entry_point_offset]["instructions"].append(disasm)
        except Exception as e:
            extraction_logger.error("{}: Error extracting instructions for function \"{}\": {}".format(program_name, name, str(e)))
            functions_info[entry_point_offset]["instructions"].append("error")

        # Extract function calls
        callees = func.getCalledFunctions(None)
        for callee in callees:
            # Get the entry point of the callee function
            callee_entry_point = callee.getEntryPoint()
            callee_entry_point_offset = hex(callee_entry_point.getOffset())
            # Write DOT file content
            dot_lines.append('  "{}" -> "{}";'.format(entry_point_offset, callee_entry_point_offset))

    dot_lines.append("}")

    # Calculate execution time
    execution_time = time.process_time() - start_time

    # Only create output files if we have extracted function information
    if not functions_info:
        extraction_logger.error("{}: No function information extracted".format(program_name))
        raise Exception("No function information extracted")

    # Writing to DOT file
    with open(dot_file_path, "w", encoding='utf-8') as dot_file:
        dot_file.write("\n".join(dot_lines))

    # Writing to JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(functions_info, json_file, indent=4)

    # Log success with timing information
    extraction_logger.info("{}: Successfully extracted function call information".format(program_name))

    # Write timing information to timing.log
    timing_log_path = os.path.join(output_folder, 'timing.log')
    with open(timing_log_path, 'a') as timing_file:
        timing_file.write("{},{:.2f}\n".format(program_name, execution_time))

except Exception as e:
    error_message = "{}: An error occurred while extracting function calls - {}".format(program_name, str(e))
    extraction_logger.error(error_message, exc_info=True)
