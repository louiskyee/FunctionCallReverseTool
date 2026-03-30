# Deployment Scripts

Docker environments for running [FunctionCallReverseTool](https://github.com/bolin8017/FunctionCallReverseTool) with supported reverse engineering backends.

## Contents

| Directory | Description |
|---|---|
| `ghidra_deploy/` | Dockerfile and `ghidra_deploy.sh` for a Ghidra environment |
| `radare2_deploy/` | Dockerfile and `radare2_deploy.sh` for a Radare2 environment |

## Usage

### Build

```bash
git clone https://github.com/bolin8017/FunctionCallReverseTool.git
cd FunctionCallReverseTool/deployment-scripts

# Ghidra
docker build -t ghidra-env ghidra_deploy/

# Radare2
docker build -t radare2-env radare2_deploy/
```

### Run

Start a container and mount your binary samples directory:

```bash
# Ghidra
docker run -it -v /path/to/binaries:/samples ghidra-env

# Radare2
docker run -it -v /path/to/binaries:/samples radare2-env
```

### Analyze binaries inside the container

```bash
# Ghidra (adjust the analyzeHeadless path to match the installed version)
python -m function_call_tool -b ghidra -d /samples -g /opt/ghidra/support/analyzeHeadless

# Radare2
python -m function_call_tool -b radare2 -d /samples
```

## Requirements

- Docker
- Internet connection (to pull base images and install packages during build)
