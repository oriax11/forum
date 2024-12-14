#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Step 1: Build the Docker image
echo "Building Docker image..."
docker build -t forum-app .

# Step 2: Run the Docker container
echo "Running Docker container..."
docker run --name forum-app-container -p 8080:8080 -d forum-app

# Step 3: Prune unused Docker objects
echo "Pruning unused Docker objects..."
# docker system prune -f

# Output completion message
echo "Docker container is running and unused objects have been pruned."
