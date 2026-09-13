# Stage 1: Build virtual environment with uv
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# Install dependencies without copying source for cache reuse
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-dev

# Copy source and install project
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
COPY README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev

# Stage 2: Final minimal runtime image
FROM python:3.12-slim-bookworm

WORKDIR /app

# Create non-root user
RUN groupadd -r appuser && useradd -r -g appuser -u 10001 appuser

# Copy virtualenv and source
COPY --from=builder --chown=appuser:appuser /app/.venv /app/.venv
COPY --chown=appuser:appuser src/ /app/src/

# Prepare persistent data directory
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    DATA_DIR="/app/data" \
    TZ="Asia/Kolkata"

USER appuser

# Expose Port 8001
EXPOSE 8001

ENTRYPOINT ["python", "-m", "vulnscan.main"]
CMD ["--transport", "sse", "--port", "8001"]
