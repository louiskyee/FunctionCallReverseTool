#!/bin/bash

# Set non-interactive installation mode
export DEBIAN_FRONTEND=noninteractive

USER="ghidrauser"
PASS="ghidrauser"
echo "$USER:$PASS" | sudo chpasswd

# Function to run commands with sudo
run_sudo() {
    echo $PASS | sudo -S "$@"
}

run_sudo apt-get update
run_sudo apt-get install -y git make wget unzip python3 python3-pip gcc g++ python3-venv python-is-python3 tar curl jq

# Download and install JDK 17
JDK_ARCHIEVE=/home/$USER/tmp/jdk-17.0.7_linux-x64_bin.tar.gz
JDK_DIR=/home/$USER/jdk-17

wget https://download.oracle.com/java/17/archive/jdk-17.0.7_linux-x64_bin.tar.gz -P /home/$USER/tmp || { echo "Failed to download JDK 17"; exit 1; }
mkdir -p $JDK_DIR
tar -xzf $JDK_ARCHIEVE -C $JDK_DIR --strip-components=1 || { echo "Failed to extract JDK 17"; exit 1; }

export JAVA_HOME=$JDK_DIR
export PATH=$JAVA_HOME/bin:$PATH

# Persist environment variables
echo -e "export JAVA_HOME=$JAVA_HOME\nexport PATH=\$JAVA_HOME/bin:\$PATH" >> /home/$USER/.profile
source /home/$USER/.profile

# Check if JDK 17 was setup successfully
if [ -f "$JAVA_HOME/bin/javac" ]; then
    echo "JDK 17 setup was successful."
else
    echo "JDK 17 setup failed."
    exit 1
fi


# Download and install Gradle
GRADLE_ARCHIEVE=/home/$USER/tmp/gradle-7.3-bin.zip
GRADLE_DIR=/home/$USER/gradle

wget https://services.gradle.org/distributions/gradle-7.3-bin.zip -P /home/$USER/tmp || { echo "Failed to download Gradle"; exit 1; }
unzip $GRADLE_ARCHIEVE -d $GRADLE_DIR || { echo "Failed to unzip Gradle"; exit 1; }

export GRADLE_HOME=$GRADLE_DIR/gradle-7.3
export PATH=$GRADLE_HOME/bin:$PATH

# Persist environment variables
echo -e "export GRADLE_HOME=$GRADLE_HOME\nexport PATH=\$GRADLE_HOME/bin:\$PATH" >> /home/$USER/.profile
source /home/$USER/.profile

# Check if Gradle was setup successfully
if [ -f "$GRADLE_HOME/bin/gradle" ]; then
    echo "Gradle setup was successful."
else
    echo "Gradle setup failed."
    exit 1
fi


# Download and install the latest release of Ghidra
GHIDRA_DIR=/home/$USER/ghidra
mkdir -p /home/$USER/tmp

# Get the latest Ghidra release download URL
echo "Fetching latest Ghidra release information..."
GHIDRA_DOWNLOAD_URL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | grep "browser_download_url.*\.zip" | cut -d '"' -f 4)
GHIDRA_ZIP_NAME=$(basename "$GHIDRA_DOWNLOAD_URL")
GHIDRA_ARCHIEVE=/home/$USER/tmp/$GHIDRA_ZIP_NAME

if [ -z "$GHIDRA_DOWNLOAD_URL" ]; then
    echo "Failed to fetch latest Ghidra release URL"
    exit 1
fi

echo "Downloading latest Ghidra: $GHIDRA_ZIP_NAME"
wget "$GHIDRA_DOWNLOAD_URL" -O "$GHIDRA_ARCHIEVE" || { echo "Failed to download Ghidra"; exit 1; }
unzip $GHIDRA_ARCHIEVE -d $GHIDRA_DIR || { echo "Failed to unzip Ghidra"; exit 1; }

# Automatically detect the extracted Ghidra directory
GHIDRA_HOME=$(find $GHIDRA_DIR -maxdepth 1 -type d -name "ghidra_*_PUBLIC" | head -n 1)
if [ -z "$GHIDRA_HOME" ]; then
    echo "Failed to find extracted Ghidra directory"
    exit 1
fi

export GHIDRA_HOME

# Make the ghidraRun script executable
chmod +x $GHIDRA_HOME/ghidraRun

# Check if Ghidra was setup successfully
if [ -f "$GHIDRA_HOME/ghidraRun" ]; then
    echo "Ghidra setup was successful."
else
    echo "Ghidra setup failed."
    exit 1
fi

# Create and activate a virtual environment in the Ghidra directory
python3 -m venv $GHIDRA_HOME/venv || { echo "Failed to create virtual environment"; exit 1; }
if [ -f "$GHIDRA_HOME/venv/bin/activate" ]; then
    source $GHIDRA_HOME/venv/bin/activate
else
    echo "Virtual environment was not created successfully."
    exit 1
fi


# Install JEP
pip install jep || { echo "Failed to install JEP"; exit 1; }

# Assuming GHIDRA_INSTALL_DIR is set to Ghidra's installation directory
export GHIDRA_INSTALL_DIR=$GHIDRA_HOME

# Clone the latest Ghidrathon repository and download the latest JEP jar
cd /home/$USER/tmp
echo "Cloning latest Ghidrathon repository..."
git clone https://github.com/mandiant/Ghidrathon.git || { echo "Failed to clone Ghidrathon repository"; exit 1; }

cd Ghidrathon/lib

# Get the latest JEP release version
echo "Fetching latest JEP release information..."
JEP_VERSION=$(curl -s https://api.github.com/repos/ninia/jep/releases/latest | grep '"tag_name":' | sed -E 's/.*"v([^"]+)".*/\1/')
if [ -z "$JEP_VERSION" ]; then
    echo "Failed to fetch latest JEP version, falling back to 4.2.0"
    JEP_VERSION="4.2.0"
fi

echo "Downloading JEP version: $JEP_VERSION"
wget https://github.com/ninia/jep/releases/download/v${JEP_VERSION}/jep-${JEP_VERSION}.jar || { echo "Failed to download JEP jar"; exit 1; }

cd /home/$USER/tmp/Ghidrathon
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME || { echo "Failed to build Ghidrathon"; exit 1; }

# Copy the built Ghidrathon extension to the Ghidra's Extensions directory
cd dist
zip_file=$(ls *.zip)
cp $zip_file $GHIDRA_HOME/Extensions/Ghidra || { echo "Failed to copy Ghidrathon zip"; exit 1; }
echo "source ${GHIDRA_HOME}/venv/bin/activate" >> $GHIDRA_HOME/ghidraRun

# Clean up tmp directory
rm -rf /home/$USER/tmp || { echo "Failed to clean up tmp directory"; exit 1; }

