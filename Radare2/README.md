# Function Call Graph and Disassembly Extraction Tool

This Python tool is designed to extract function call graph and disassembly information from binary files and save the results as DOT and JSON files. Here's a detailed explanation of each part of the tool:

## Installation Requirements

Before using this tool, ensure that you have the following Python packages installed:

- `r2pipe`: Used for interacting with Radare2 to perform analysis and disassembly.
- `tqdm`: Used for displaying progress bars to track the processing progress.

You can install these packages using the following command:

```
pip install r2pipe tqdm
```

## Usage

To use this tool, follow these steps:

1. Download the Python file `get_function_call.py` to your local machine.

2. Open a terminal or command prompt and navigate to the directory where the tool is located.

3. Run the following command to use the tool:

   ```
   python get_function_call.py -d /path/to/binary/directory
   ```

   Replace `/path/to/binary/directory` with the path to the directory containing the binary files you want to process.

4. The tool will start processing the binary files and save the extracted function call graph and disassembly information as DOT and JSON files. The progress will be displayed in the terminal.

5. Once the processing is complete, the extracted files will be saved in the same location as the input directory, with the suffix `_disassemble`. Each binary file will have a corresponding DOT file for the function call graph and a JSON file for the disassembly information.

## Code Explanation

Here's a detailed explanation of each part of the tool:

### `configure_logging` Function

This function is used to configure the logging settings. It takes the input directory path as a parameter and returns two logger objects: `extraction_logger` and `timing_logger`.

- `extraction_logger` is used to log errors and warnings during the extraction process.
- `timing_logger` is used to log the execution time for each file processing.

The log files will be saved in the same location as the input directory.

### `extraction` Function

This function is responsible for extracting the function call graph and disassembly information from the specified binary file and saving the results as DOT and JSON files. It takes the following parameters:

- `input_file_path`: The path to the target file.
- `output_folder`: The path to the output folder where the extracted files will be saved.
- `file_name`: The name of the target file.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.

The function uses Radare2 to perform analysis and disassembly. It extracts the function call graph and disassembly information for each function in the binary. The extracted data is then saved as DOT and JSON files.

If any errors occur during the extraction process, such as file not found or invalid analysis results, the error information will be logged using the `extraction_logger`.

### `get_args` Function

This function is used to generate a list of arguments for parallel processing. It takes the following parameters:

- `binary_path`: The path to the directory containing the binary files.
- `output_path`: The path to the directory where the output files will be saved.
- `extraction_logger`: The logger object for recording the extraction process.
- `timing_logger`: The logger object for recording the execution time.

The function iterates over all the files in the binary directory and generates a tuple for each file, containing the input file path, output directory path, file name, and logger objects. These tuples will be used as arguments for parallel processing.

### `parallel_process` Function

This function is used to process the extraction tasks in parallel. It takes a list of arguments, where each argument is a tuple containing the input file path, output directory path, file name, and logger objects.

The function uses `ProcessPoolExecutor` to create a process pool and submits the extraction tasks to the pool for parallel processing. The progress is displayed in the terminal using the `tqdm` package.

### `setup_output_directory` Function

This function is used to set up the output directory for storing the extracted files. It takes the input directory path as a parameter and returns the path to the output directory.

The output directory will be located in the same location as the input directory and have the suffix `_disassemble`. The function creates corresponding subdirectories in the output directory for each subdirectory in the input directory.

### `parse_arguments` Function

This function is used to parse the command-line arguments. It uses the `argparse` module to define and parse the arguments.

The tool accepts one required argument, `-d` or `--directory`, which specifies the path to the directory containing the binary files.

### `main` Function

This function is the main entry point of the tool and coordinates the entire extraction process. It performs the following steps:

1. Parse the command-line arguments to obtain the input directory path.
2. Configure the logging settings, including the extraction log and timing log.
3. Set up the output directory for storing the extracted files.
4. Generate the list of arguments for parallel processing.
5. Perform parallel processing to extract function call graph and disassembly information and save the results as DOT and JSON files.

## Conclusion

This Python tool provides a convenient way to extract function call graph and disassembly information from binary files and save the results as DOT and JSON files. It leverages Radare2 for analysis and disassembly and uses parallel processing to speed up the processing.

The tool requires the installation of the `r2pipe` and `tqdm` packages and can be used via the command-line interface. The extracted files will be saved in the same location as the input directory, with each binary file having a corresponding DOT file for the function call graph and a JSON file for the disassembly information.

By using this tool, you can easily analyze binaries, obtain valuable function call graph and disassembly information for further research and analysis.

## Reference

This tool utilizes several Python libraries and tools compatible with Python 3.11.4. Below are the references and additional resources for each:

1. **os and time**: Built-in Python libraries for operating system interactions and time-related functions. More details can be found in the official Python documentation specific to Python 3.11.4: [Python Standard Library](https://docs.python.org/3.11/library/).

2. **r2pipe**: A Python library for scripting with Radare2, which is used for binary analysis. Official repository and documentation available at: [Radare2 GitHub](https://github.com/radareorg/radare2).

3. **logging and argparse**: Standard Python libraries for logging and parsing command-line arguments. Documentation for Python 3.11.4 available at: [Logging](https://docs.python.org/3.11/library/logging.html) and [Argparse](https://docs.python.org/3.11/library/argparse.html).

4. **tqdm**: A library for adding progress meters to Python loops. Repository and documentation: [tqdm GitHub](https://github.com/tqdm/tqdm).

5. **multiprocessing and concurrent.futures**: Python libraries for parallel execution and asynchronous programming. Documentation specific to Python 3.11.4 available at: [Multiprocessing](https://docs.python.org/3.11/library/multiprocessing.html) and [Concurrent.futures](https://docs.python.org/3.11/library/concurrent.futures.html).

These references provide a foundation for understanding the tools and libraries used in the development of this function call graph and disassembly extraction tool.