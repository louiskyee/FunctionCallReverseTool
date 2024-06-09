#!/bin/bash

# Input parameters
ghidra_headless_path=$1
program_folder=$2

# Get the directory of the currently executing script
output_dir="$(dirname "${program_folder}")/$(basename "${program_folder}")_disassemble"
python_script_path="$(dirname "$0")/ghidra_opcode_script.py"
project_name="$(basename "${program_folder}")"

# Set directory path variables based on input parameters
project_folder="${output_dir}/ghidra_projects"
result_folder="${output_dir}/results"
split_dir="${output_dir}/split_folders"

# Set the maximum number of CPUs to use
max_cpu=$(nproc)

if [ -d "${output_dir}" ]; then
    rm -rf "${output_dir}"
fi
mkdir -p "${output_dir}"

# Create the project_folder, result_folder, and split_dir
mkdir -p "${project_folder}"
mkdir -p "${result_folder}"
mkdir -p "${split_dir}"

# Make sure time.txt file does not exist before execution to avoid retaining old results
time_file_name="${output_dir}/total_disassemble_time.txt"
rm -f "${time_file_name}"

# Split the input program_folder into max_cpu subfolders
file_count=$(find "${program_folder}" -type f | wc -l)
if [ $file_count -lt $max_cpu ]; then
    max_cpu=$file_count
fi
files_per_folder=$((file_count / max_cpu))
remainder=$((file_count % max_cpu))

index=1
folder_index=1
for file in "${program_folder}"/*; do
    if [ $((index % (files_per_folder + 1))) -eq 0 ] && [ $folder_index -lt $max_cpu ]; then
        folder_index=$((folder_index + 1))
    fi
    subfolder="${split_dir}/${project_name}_${folder_index}"
    mkdir -p "${subfolder}"
    cp "${file}" "${subfolder}"
    index=$((index + 1))
done

# Handle the remaining files
if [ $remainder -gt 0 ]; then
    subfolder="${split_dir}/${project_name}_${max_cpu}"
    mkdir -p "${subfolder}"
    for file in $(find "${program_folder}" -type f | tail -n $remainder); do
        cp "${file}" "${subfolder}"
    done
fi

# Create corresponding subfolders in project_folder for each split_folder
for subfolder in "${split_dir}"/*; do
    subfolder_name=$(basename "${subfolder}")
    corresponding_project_folder="${project_folder}/${subfolder_name}"
    mkdir -p "${corresponding_project_folder}"
done

start_time=$(date +%s)

# Process each subfolder in parallel using GNU Parallel
find "${split_dir}" -mindepth 1 -maxdepth 1 -type d | parallel --jobs "${max_cpu}" "${ghidra_headless_path}" "${project_folder}/{/}" "{/}" -import "{}" -scriptPath "$(dirname "${python_script_path}")" -postScript "$(basename "${python_script_path}")" "${output_dir}" "${result_folder}" -max-cpu $(nproc)

end_time=$(date +%s)
execution_time=$((end_time - start_time))  # Calculate the total execution time in seconds
# Append the total execution time to the time.txt file
echo "Total Execution Time: ${execution_time} seconds" >> "${time_file_name}"

rm -rf "${split_dir}"