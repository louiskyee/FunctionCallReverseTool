# Ghidra Function Call Extraction Scripts

This repository contains two scripts that work together to extract function call information from binary files using the Ghidra headless analyzer.

## Scripts

1. `get_function_call.sh`: This Bash script automates the process of running the Ghidra headless analyzer with the `ghidra_function_script.py` script. It takes the path to the Ghidra headless analyzer, the directory containing the program samples, an optional output directory, and an optional timeout value as input parameters. The script sets up the necessary directories, processes each file in the input directory in parallel using GNU Parallel, and handles timeouts for each file.

2. `ghidra_function_script.py`: This Python script is designed to be run within the Ghidra headless analyzer. It extracts function call information, including function names, addresses, instructions, and call graph relationships, from the disassembled code of the input binary files. The script writes the extracted information to DOT and JSON files in the specified output directory.

## Prerequisites

- Ghidra: Make sure you have Ghidra installed on your system. The `ghidra_headless_path` parameter in the `get_function_call.sh` script should point to the path of the Ghidra headless analyzer executable.
- GNU Parallel: The script uses GNU Parallel to process the files in parallel. Make sure you have GNU Parallel installed on your system.

## Usage

1. Clone this repository to your local machine.

2. Open a terminal and navigate to the directory where the scripts are located.

3. Run the `get_function_call.sh` script with the following command:

   ```bash
   ./get_function_call.sh <ghidra_headless_path> <program_folder> [output_dir] [timeout]
   ```

   - `<ghidra_headless_path>`: Path to the Ghidra headless analyzer executable.
   - `<program_folder>`: Path to the directory containing the program samples you want to analyze.
   - `[output_dir]`: (Optional) Path to the output directory. Default is './output'.
   - `[timeout]`: (Optional) Timeout value in seconds for each file analysis. Default is 600 seconds (10 minutes).

4. The script will create an output directory (default or specified) containing the following:
   - `ghidra_projects`: Temporary directory for Ghidra project files (removed after processing).
   - `results`: Contains subdirectories for each analyzed program sample, named after the program name. Each subdirectory contains:
     - `<program_name>.dot`: The DOT file representing the function call graph of the program.
     - `<program_name>.json`: The JSON file containing detailed information about the functions, including addresses and instructions.
   - `timeout.log`: Log file containing information about any files that timed out during processing.
   - `timed_out_files.txt`: List of files that timed out during processing.
   - `extraction.log`: Log file containing information about the extraction process, including any errors.

## Important Notes

- The `ghidra_function_script.py` script is designed to be run within the Ghidra headless analyzer and should not be executed directly.
- The script uses the `logging` module to log any errors that occur during the execution. The log file is saved in the output directory with the name `extraction.log`.
- If a file analysis times out, it will be recorded in the `timeout.log` and `timed_out_files.txt` files.
- The script processes all files in the input directory in parallel, utilizing all available CPU cores.

## License

This project is licensed under the [MIT License](https://github.com/louiskyee/FunctionCallReverseTool/blob/main/LICENSE).

Feel free to contribute to this project by creating issues or submitting pull requests.