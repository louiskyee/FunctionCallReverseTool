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
run_sudo apt-get install -y git make wget unzip python3 python3-pip gcc g++ python3-venv python-is-python3 tar

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


# Download and install the specific release of Ghidra
GHIDRA_ARCHIEVE=/home/$USER/tmp/ghidra_10.3.1_PUBLIC_20230614.zip
GHIDRA_DIR=/home/$USER/ghidra

wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.1_build/ghidra_10.3.1_PUBLIC_20230614.zip -P /home/$USER/tmp || { echo "Failed to download Ghidra"; exit 1; }
unzip $GHIDRA_ARCHIEVE -d $GHIDRA_DIR || { echo "Failed to unzip Ghidra"; exit 1; }

export GHIDRA_HOME=$GHIDRA_DIR/ghidra_10.3.1_PUBLIC

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

# Clone the Ghidrathon repository and download the JEP jar
cd /home/$USER/tmp
git clone https://github.com/mandiant/Ghidrathon.git || { echo "Failed to clone Ghidrathon repository"; exit 1; }

cd Ghidrathon/lib
wget https://github.com/ninia/jep/releases/download/v4.2.0/jep-4.2.0.jar || { echo "Failed to download JEP jar"; exit 1; }

cd /home/$USER/tmp/Ghidrathon
gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_HOME || { echo "Failed to build Ghidrathon"; exit 1; }

# Copy the built Ghidrathon extension to the Ghidra's Extensions directory
cd dist
zip_file=$(ls *.zip)
cp $zip_file $GHIDRA_HOME/Extensions/Ghidra || { echo "Failed to copy Ghidrathon zip"; exit 1; }
echo "source ${GHIDRA_HOME}/venv/bin/activate" >> $GHIDRA_HOME/ghidraRun

# Clean up tmp directory
rm -rf /home/$USER/tmp || { echo "Failed to clean up tmp directory"; exit 1; }

