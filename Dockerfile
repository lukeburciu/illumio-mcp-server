# Build stage
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

# Copy the entire project for building
COPY . .

# Install dependencies and create venv
RUN uv venv /app/venv && \
    . /app/venv/bin/activate && \
    uv pip install -e .

# Final stage
FROM python:3.12-slim-bookworm

WORKDIR /app

# Copy only the necessary files from builder
COPY --from=builder /app/venv /app/venv
COPY --from=builder /app/src /app/src

# Set environment variables
ENV PATH="/app/venv/bin:$PATH"
ENV DOCKER_CONTAINER=true
ENV PYTHONWARNINGS=ignore

# Run as non-root user
RUN useradd -m -u 1000 illumio && \
    chown -R illumio:illumio /app

USER illumio

# Command to run the application
ENTRYPOINT ["illumio-mcp"]
