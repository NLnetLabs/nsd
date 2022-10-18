# NSD Container

This directory contains files to build NSD as a container.

- Configuration (e.g., nsd.conf) is stored in `/config`
- Volatile data stored in `/storage`

## Building

    docker build -f docker/Dockerfile -t nsd:latest .
