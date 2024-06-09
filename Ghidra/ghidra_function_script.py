import os
import time
import json
import logging
from ghidra.app.util.headless import HeadlessScript
from ghidra.program.model.symbol import Reference

# Get script arguments and determine the save folder
argv = getScriptArgs()

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
    error_message = "An error occurred while setting parameters: {}".format(e)
    logging.error(error_message, exc_info=True)

program_name = currentProgram.getName()
program_folder = os.path.join(results_folder, program_name)

# Create the program-specific directory
if not os.path.exists(program_folder):
    os.makedirs(program_folder)

# Set up logging
log_file_path = os.path.join(output_folder, 'extraction.log')
logging.basicConfig(filename=log_file_path, level=logging.ERROR,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Determine file paths for DOT file and JSON file
dot_file_path = os.path.join(program_folder, program_name + '.dot')
json_file_path = os.path.join(program_folder, program_name + '.json')

try:
    start_time = time.time()
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    dot_lines = ["digraph code {"]
    functions_info = {}

    # Collecting all lines to write in batch
    for func in funcs:
        entry_point = func.getEntryPoint()
        entry_point_offset = hex(entry_point.getOffset())
        name = func.getName()

        # Prepare function information for JSON
        functions_info[name] = {
            "function_address": entry_point_offset,
            "instructions": []
        }

        dot_lines.append('  "{}" [label="{}"];'.format(entry_point_offset, name))

        # Extracting instructions for each function
        for instruction in currentProgram.getListing().getInstructions(func.getBody(), True):
            instruction_info = {
                "instruction_address": str(instruction.getAddress()),
                "instruction": str(instruction)
            }
            functions_info[name]["instructions"].append(instruction_info)

        callees = func.getCalledFunctions(None)
        for callee in callees:
            # get the entry point of the callee function
            callee_entry_point = callee.getEntryPoint()
            callee_entry_point_offset = hex(callee_entry_point.getOffset())
            # Write DOT file content
            dot_lines.append('  "{}" -> "{}";'.format(entry_point_offset, callee_entry_point_offset))

    dot_lines.append("}")

    # Writing to DOT file
    with open(dot_file_path, "w") as dot_file:
        dot_file.write("\n".join(dot_lines))

    # Writing to JSON file
    with open(json_file_path, "w") as json_file:
        json.dump(functions_info, json_file, indent=4)

    end_time = time.time()
    execution_time = end_time - start_time
    with open(os.path.join(output_folder, 'timing.log'), 'a', newline='', encoding='utf-8') as f:
        f.write("{},{:.2f}\n".format(program_name, execution_time))

except Exception as e:
    error_message = "An error occurred while writing the files: {}".format(e)
    logging.error(error_message, exc_info=True)