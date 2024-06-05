#!/bin/bash

# Update and install dependencies
sudo apt-get update
sudo apt-get install -y git make
sudo apt-get install -y gcc

# Clone the Radare2 repository
git clone https://github.com/radareorg/radare2

if [ ! -d "radare2" ]; then
  echo "Cloning failed. Repository not found."
  exit 1
fi

cd radare2

# Initial installation attempt
sys/user.sh --install-path ~/.local

# Function to handle build problems
handle_build_issues() {
    echo "Handling build issues..."
    sudo make purge
    rm -rf shlr/capstone
    git clean -xdf
    git reset --hard @~50
    sys/install.sh
}

# Check for successful installation
if radare2 -v; then
    echo "Radare2 installed successfully."
else
    echo "Radare2 installation failed, attempting to fix..."
    handle_build_issues
    if radare2 -v; then
        echo "fixed. Radare2 installed successfully."
    fi
fi