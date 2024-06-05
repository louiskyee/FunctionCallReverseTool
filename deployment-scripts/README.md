# Deployment Scripts

## Overview

This repository contains automation scripts for deploying environments for IDA Pro, Ghidra, and Radare2. These scripts are designed to streamline the setup process for these powerful reverse engineering tools, ensuring you can get up and running quickly with minimal manual configuration.

## Contents

The deployment scripts are organized into separate directories for each tool, each containing a Dockerfile and a shell script:

- **IDA Pro Deployment**
  - **Directory**: `ida_pro_deploy/`
    - `Dockerfile` - Docker configuration for IDA Pro.
    - `ida_pro_deploy.sh` - Script to automatically set up IDA Pro.

- **Ghidra Deployment**
  - **Directory**: `ghidra_deploy/`
    - `Dockerfile` - Docker configuration for Ghidra.
    - `ghidra_deploy.sh` - Script to automatically install and configure Ghidra.

- **Radare2 Deployment**
  - **Directory**: `radare2_deploy/`
    - `Dockerfile` - Docker configuration for Radare2.
    - `radare2_deploy.sh` - Script to facilitate the deployment of Radare2.

## Usage

To use these deployment scripts, clone the repository and run the desired script according to the tool you wish to set up. Ensure you have the necessary permissions to execute the scripts on your system.

```bash
git clone https://github.com/louiskyee/OpCodeReverseTool.git
cd deployment-scripts
cd <tool_directory>  # e.g., ida_pro_deploy, ghidra_deploy, or radare2_deploy
docker build -t <tool_name>-image .
docker run -it --name <tool_name>-container <tool_name>-image
```

## Example
```bash
git clone https://github.com/louiskyee/OpCodeReverseTool.git
cd deployment-scripts/radare2_deploy
docker build -t radare2-image .
docker run -it --name radare2-container radare2-image
```

## Requirements

- Linux OS or a compatible Unix-like system
- Sudo or root access to install packages
- Internet connection to download necessary files

## Contributing

Contributions to improve the scripts or add new functionalities are welcome. Please submit a pull request or open an issue to discuss your ideas.

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/louiskyee/OpCodeReverseTool/blob/main/LICENSE) file for details.