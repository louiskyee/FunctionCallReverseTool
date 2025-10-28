# Function Call Extraction Tool

[English](README.md) | [繁體中文](README.zh-TW.md)

This Python tool is designed to extract function call graphs and disassembly information from binary files and save the results as DOT and JSON files. Here's a detailed explanation of each part of the tool:

## Installation Requirements

Before using this tool, ensure that you have the following Python packages installed:

- `r2pipe`: Used for interacting with Radare2 to perform disassembly and analysis.
- `tqdm`: Used for displaying progress bars to track the processing progress.

You can install these packages using the following command:

```
pip install -r requirements.txt
```
or
```
pip install r2pipe tqdm
```

## Usage

To use this tool, follow these steps:

1. Download the Python file `get_function_call.py` to your local machine.

2. Open a terminal or command prompt and navigate to the directory where the tool is located.

3. Run the following command to use the tool:

   ```bash
   python get_function_call.py -d /path/to/binary/directory
   ```

   Replace `/path/to/binary/directory` with the path to the directory containing the binary files you want to process.

### Command-Line Arguments

- `-d, --directory` (required): Path to the binary directory containing the files to process.
- `-o, --output` (optional): Path to the output directory. If not specified, defaults to `<binary_directory>_disassemble`.
- `-t, --timeout` (optional): Timeout duration in seconds for each file analysis (default: 300 seconds).

### Usage Examples

```bash
# Basic usage with default settings
python get_function_call.py -d /path/to/binary/directory

# Specify custom output directory
python get_function_call.py -d /path/to/binary/directory -o /path/to/output

# Set custom timeout (600 seconds)
python get_function_call.py -d /path/to/binary/directory -t 600

# Combine all options
python get_function_call.py -d /path/to/binary/directory -o /path/to/output -t 600
```

4. The tool will start processing the binary files and save the extracted function call graphs and disassembly information. The progress will be displayed in the terminal.

5. Once the processing is complete, the extracted files will be saved in the output directory. The output directory will contain the following:
   - `results` subdirectory: Contains the extracted files for each binary file, maintaining the same relative path structure as the input directory. For each binary, two files are created:
     - `.dot` file: Function call graph in DOT format
     - `.json` file: Detailed function information including disassembly instructions
   - `extraction.log`: Log file recording the extraction process and any errors or warnings.
   - `timing.log`: Log file recording the execution time for each file processing.

## Features

- **Parallel Processing**: Utilizes multi-core CPUs to process multiple binary files simultaneously for faster extraction.
- **Resource Management**: Implements context managers to ensure proper cleanup of radare2 instances, preventing resource leaks.
- **Timeout Protection**: Built-in timeout mechanism to prevent hanging on problematic binaries.
- **Comprehensive Logging**: Separate logs for extraction process and timing information for analysis and debugging.
- **Error Handling**: Robust error handling for various edge cases including files with no functions or extraction errors.
- **Progress Tracking**: Real-time progress bar to monitor the extraction process.
- **Flexible Output**: Customizable output directory location.
- **Multiple Output Formats**: Generates both DOT files for visualization and JSON files for detailed analysis.

## Code Explanation

Here's a detailed explanation of each part of the tool:

### `configure_logging` Function

This function is used to configure the logging settings. It takes the output directory path as a parameter and returns two logger objects: `extraction_logger` and `timing_logger`.

- `extraction_logger` is used to log errors during the extraction process.
- `timing_logger` is used to log the execution time for each file processing.

The log files will be saved in the output directory. The function also clears existing handlers to prevent duplicate logging entries.

### `check_timeout` Function

This function checks if the file analysis will timeout by running a bash script that performs a preliminary timeout check. It helps prevent the tool from hanging on problematic binaries that would exceed the specified timeout duration.

### `open_r2pipe` Function

This is a context manager that ensures proper resource management for radare2 instances. It automatically opens and closes r2pipe connections, guaranteeing cleanup even if exceptions occur during processing. This prevents resource leaks and ensures system stability during large batch processing.

### `extract_features` Function

This function extracts function call graph and disassembly information from binary files using radare2. It:
- Opens the binary file using the `open_r2pipe` context manager for safe resource handling
- Performs enhanced analysis using the `aaa` command
- Retrieves the function call graph using the `agCd` command
- Parses the graph to extract function addresses and names
- For each function, disassembles instructions using the `pdfj` command
- Returns both the function call graph and detailed function information

If no functions are found, an error is logged and empty results are returned.

### `extraction` Function

This function is responsible for extracting function call graphs and disassembly information from the specified binary file and saving the results as DOT and JSON files. It takes the following parameters:

- `input_file_path`: The path to the target file.
- `output_folder`: The path for the output folder.
- `file_name`: The name of the target file.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.
- `timeout_seconds`: Maximum time allowed for file analysis.
- `bash_script_path`: Path to the timeout check script.

The function performs the following steps:
1. Checks if the output files already exist (skips if they do)
2. Performs a timeout check to avoid hanging on problematic binaries
3. Calls `extract_features` to extract function calls using radare2
4. Validates that functions were successfully extracted
5. Saves the function call graph to a DOT file
6. Saves the detailed function information to a JSON file
7. Logs the execution time

If any errors occur during the extraction process, such as file not found or no valid functions, the error information will be logged using the `extraction_logger`.

### `get_args` Function

This function is used to generate a list of arguments for parallel processing. It takes the following parameters:

- `binary_path`: The path to the directory containing the binary files.
- `output_path`: The path to the directory where the output files will be saved.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.
- `timeout_seconds`: Timeout duration in seconds.
- `bash_script_path`: Path to the timeout check script.

The function iterates over all the files in the binary directory and generates a tuple for each file, containing the input file path, output folder path, file name, logger objects, and timeout information. These tuples will be used as arguments for parallel processing.

### `parallel_process` Function

This function is used to process the extraction tasks in parallel. It takes a list of arguments, where each argument is a tuple containing the input file path, output folder path, file name, logger objects, and timeout information.

The function uses `ProcessPoolExecutor` to create a process pool and submits the extraction tasks to the pool for parallel processing. The progress is displayed in the terminal using the `tqdm` package.

### `setup_output_directory` Function

This function is used to set up the output directory for storing the extracted files. It takes the input directory path and an optional custom output directory path as parameters and returns the path to the output directory.

If a custom output directory is specified, it will be used. Otherwise, the output directory will be named `<binary_directory>_disassemble` and located at the same level as the input directory, where `<binary_directory>` is the name of the input directory. The function creates the output directory if it doesn't exist and also creates a `results` subdirectory within it.

### `parse_arguments` Function

This function is used to parse the command-line arguments. It uses the `argparse` module to define and parse the arguments.

The tool accepts the following arguments:
- `-d` or `--directory` (required): Specifies the path to the directory containing the binary files.
- `-o` or `--output` (optional): Specifies the custom output directory path.
- `-t` or `--timeout` (optional): Specifies the timeout duration in seconds for file analysis (default: 300).

### `main` Function

This function is the main entry point of the tool and coordinates the entire extraction process. It performs the following steps:

1. Parse the command-line arguments to obtain the input directory path.
2. Set up the output directory for storing the extracted files.
3. Configure the logging settings, including the extraction log and timing log.
4. Verify that the timeout check script exists and is executable.
5. Generate the list of arguments for parallel processing.
6. Perform parallel processing to extract function call graphs and disassembly information and save the results as DOT and JSON files.

## Conclusion

This Python tool provides a convenient way to extract function call graphs and disassembly information from binary files and save the results as DOT and JSON files. It leverages Radare2 for disassembly and analysis, and uses parallel processing to speed up the processing.

The tool requires the installation of the `r2pipe` and `tqdm` packages and can be used via the command-line interface. The extracted files will be saved in a directory named `<binary_directory>_disassemble` located at the same level as the input directory, where `<binary_directory>` is the name of the input directory. The `<binary_directory>_disassemble` directory will contain the extracted DOT and JSON files for each binary file, maintaining the same relative path structure as the input directory, along with the extraction and timing log files.

By using this tool, you can easily analyze binary files and obtain valuable function call graph and disassembly information for further research and analysis.

## Reference

This tool utilizes several Python libraries and tools compatible with Python 3.11.4. Below are the references and additional resources for each:

1. **os and time**: Built-in Python libraries for operating system interactions and time-related functions. More details can be found in the official Python documentation specific to Python 3.11.4: [Python Standard Library](https://docs.python.org/3.11/library/).

2. **r2pipe**: A Python library for scripting with Radare2, which is used for binary analysis. Official repository and documentation available at: [Radare2 GitHub](https://github.com/radareorg/radare2).

3. **logging and argparse**: Standard Python libraries for logging and parsing command-line arguments. Documentation for Python 3.11.4 available at: [Logging](https://docs.python.org/3.11/library/logging.html) and [Argparse](https://docs.python.org/3.11/library/argparse.html).

4. **tqdm**: A library for adding progress meters to Python loops. Repository and documentation: [tqdm GitHub](https://github.com/tqdm/tqdm).

5. **subprocess and contextlib**: Python libraries for running external commands and creating context managers. Documentation specific to Python 3.11.4 available at: [Subprocess](https://docs.python.org/3.11/library/subprocess.html) and [Contextlib](https://docs.python.org/3.11/library/contextlib.html).

6. **re and json**: Standard Python libraries for regular expressions and JSON processing. Documentation available at: [Re](https://docs.python.org/3.11/library/re.html) and [Json](https://docs.python.org/3.11/library/json.html).

7. **typing and concurrent.futures**: Python libraries for type hints and asynchronous programming. Documentation specific to Python 3.11.4 available at: [Typing](https://docs.python.org/3.11/library/typing.html) and [Concurrent.futures](https://docs.python.org/3.11/library/concurrent.futures.html).

These references provide a foundation for understanding the tools and libraries used in the development of this function call extraction tool.
