FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS uv

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock README.md ./


# Install dependencies into .venv directory
RUN --mount=type=cache,target=/root/.cache/uv \
    uv venv /app/.venv && \
    . /app/.venv/bin/activate && \
    uv sync --frozen --no-dev --no-install-project --no-editable

# Copy application code
COPY . .

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --no-editable

# Final stage
FROM python:3.12-slim-bookworm

WORKDIR /app

# Create non-root user
RUN useradd --create-home app

# Copy only the virtual environment from the builder stage
COPY --from=uv --chown=app:app /app/.venv /app/.venv

# Switch to non-root user
USER app

# Configure environment
ENV PATH="/app/.venv/bin:$PATH"

# Command to run the application
CMD ["illumio-mcp"]
