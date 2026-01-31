# Multi-stage build for smaller image
FROM python:3.12-slim as builder

WORKDIR /app

# Install build dependencies
RUN pip install --no-cache-dir hatchling

# Copy source
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Build wheel
RUN pip wheel --no-deps --wheel-dir /wheels .

# Final stage
FROM python:3.12-slim

LABEL org.opencontainers.image.title="hackmenot"
LABEL org.opencontainers.image.description="AI-Era Code Security Scanner"
LABEL org.opencontainers.image.source="https://github.com/b0rd3aux/hackmenot"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

# Install from wheel
COPY --from=builder /wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Create non-root user
RUN useradd -m -s /bin/bash scanner
USER scanner

# Set up workspace
WORKDIR /workspace

ENTRYPOINT ["hackmenot"]
CMD ["--help"]
