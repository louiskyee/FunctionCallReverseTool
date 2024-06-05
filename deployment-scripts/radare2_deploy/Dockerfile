# Use an official base image
FROM ubuntu:latest

# Install base utilities
RUN apt-get update && apt-get install -y git make sudo

# Create a new user and add to sudo group
RUN useradd -m radare2user \
    && echo "radare2user:radare2user" | chpasswd \
    && adduser radare2user sudo

# Switch to the new user
USER radare2user

# Set working directory
WORKDIR /home/radare2user

# Copy the installation script into the container
COPY --chown=radare2user:radare2user install_radare2.sh /install_radare2.sh

# Grant execution permissions to the script
RUN chmod +x /install_radare2.sh

# Run the script when the container starts
CMD ["/radare2_deploy.sh"]