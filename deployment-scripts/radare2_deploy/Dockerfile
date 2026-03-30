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
COPY --chown=radare2user:radare2user radare2_deploy.sh /home/radare2user/radare2_deploy.sh

# Grant execution permissions to the script
RUN chmod +x /home/radare2user/radare2_deploy.sh

# Run the script when the container starts
CMD ["/home/radare2user/radare2_deploy.sh"]