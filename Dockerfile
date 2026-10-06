FROM python:3.12-slim

# Install git and ca-certificates
RUN apt-get update && \
    apt-get install -y --no-install-recommends git ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition and source code
COPY pyproject.toml README.md /app/
COPY src/ /app/src/

# Install Gatekeeper package
RUN pip install --no-cache-dir .

# Default entrypoint executes Gatekeeper CLI
ENTRYPOINT ["gatekeeper", "audit"]
