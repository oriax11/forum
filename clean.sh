#!/bin/bash

# Stop all running containers
docker stop $(docker ps -q)

# Remove all containers (both running and stopped)
docker rm $(docker ps -aq)

# Remove all images
docker rmi $(docker images -q)

echo "All containers and images have been deleted."
