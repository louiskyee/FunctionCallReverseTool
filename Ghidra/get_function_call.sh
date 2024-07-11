#!/bin/bash

# Input parameters
ghidra_headless_path=$1
program_folder=$2
output_dir=${3:-'./output'}
timeout=${4:-600}  # Default timeout of 10 minutes (600 seconds)

python_script_path="$(dirname "$0")/ghidra_function_script.py"
result_folder="${output_dir}/results"

# Export variables to make them available in subshells
export ghidra_headless_path
export output_dir
export timeout
export python_script_path
export result_folder

# Function to process a single file
process_file() {
    local file=$1
    local file_name=$(basename "$file")
    local project_name="${file_name}_project"
    local project_folder="${output_dir}/ghidra_projects/${project_name}"

    # Create a temporary project folder
    mkdir -p "$project_folder"

    # Start time measurement
    start_time=$(date +%s.%N)

    # Run Ghidra headless analyzer with timeout
    timeout --kill-after=10 "${timeout}" "$ghidra_headless_path" "$project_folder" "$project_name" -import "$file" -scriptPath "$(dirname "$python_script_path")" -postScript "$(basename "$python_script_path")" "$output_dir" "$result_folder"

    # Check if the process timed out
    if [ $? -eq 124 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S,%3N') - ERROR - Processing of $file_name timed out after $timeout seconds" >> "${output_dir}/extraction.log"
        echo "$file_name" >> "${output_dir}/timed_out_files.txt"
    else
        # End time measurement
        end_time=$(date +%s.%N)

        # Calculate execution time
        execution_time=$(echo "$end_time - $start_time" | bc)

        # Log the execution time
        echo "$(date '+%Y-%m-%d %H:%M:%S,%3N') - INFO - Successfully extracted function call information for $file_name, time: ${execution_time} seconds" >> "${output_dir}/extraction.log"
    fi

    # Remove the temporary project folder
    rm -rf "$project_folder"
}

export -f process_file

# Create necessary directories
mkdir -p "${output_dir}/ghidra_projects"
mkdir -p "$result_folder"

# Process all files in parallel
find "$program_folder" -type f | parallel --jobs $(nproc) process_file

# Clean up
rm -rf "${output_dir}/ghidra_projects"