"""Ghidra postScript for function call graph and disassembly extraction.

Runs inside Ghidra's headless analyzer environment.
Receives one argument: the folder where the temp DOT and JSON files
should be written.

Uses .format() instead of f-strings for Jython/Ghidrathon compatibility.
"""
import os
import json

argv = getScriptArgs()

if len(argv) < 1:
    raise ValueError("Missing argument: output folder path")

output_folder = argv[0]
file_name = currentProgram().getName()

fm = currentProgram().getFunctionManager()
func_list = list(fm.getFunctions(True))

if not func_list:
    raise Exception(
        "{}: No functions found - file may be packed, damaged, "
        "or incomplete".format(file_name)
    )

function_call_graph = ["digraph code {"]
functions_info = {}

for func in func_list:
    entry_point = func.getEntryPoint()
    entry_point_offset = hex(entry_point.getOffset())
    name = func.getName()

    functions_info[entry_point_offset] = {
        "function_name": name,
        "instructions": []
    }

    function_call_graph.append(
        '  "{}" [label="{}"];'.format(entry_point_offset, name)
    )

    # Extract instructions for each function
    try:
        instructions = currentProgram().getListing().getInstructions(
            func.getBody(), True
        )
        for instruction in instructions:
            disasm = str(instruction)
            functions_info[entry_point_offset]["instructions"].append(disasm)
    except Exception as e:
        print("ERROR: {}: Error extracting instructions for "
              "function \"{}\": {}".format(file_name, name, str(e)))
        functions_info[entry_point_offset]["instructions"].append("error")

    # Extract function call edges
    callees = func.getCalledFunctions(None)
    for callee in callees:
        callee_offset = hex(callee.getEntryPoint().getOffset())
        function_call_graph.append(
            '  "{}" -> "{}";'.format(entry_point_offset, callee_offset)
        )

function_call_graph.append("}")

if not functions_info:
    raise Exception(
        "{}: No function information extracted".format(file_name)
    )

# Write DOT file
dot_path = os.path.join(output_folder, file_name + '.dot')
with open(dot_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(function_call_graph))

# Write JSON file
json_path = os.path.join(output_folder, file_name + '.json')
with open(json_path, 'w', encoding='utf-8') as f:
    json.dump(functions_info, f, indent=4)
