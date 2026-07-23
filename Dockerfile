FROM python:3.12-slim

WORKDIR /app

# Node.js for antonorlov/mcp-postgres-server; curl for healthchecks/tools.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY agents ./agents

RUN pip install --no-cache-dir ".[mlflow]"

# Pre-warm Postgres MCP (npm).
RUN npx -y mcp-postgres-server --help >/dev/null 2>&1 || true

ENV PYTHONUNBUFFERED=1 \
    AGENTS_DIR=/app/agents \
    HOST=0.0.0.0 \
    PORT=8000 \
    MCP_POSTGRES_COMMAND=npx \
    MCP_POSTGRES_ARGS="-y mcp-postgres-server" \
    INTAKE_ENABLED=true \
    INVENTORY_DIR=/app/inventory

EXPOSE 8000

CMD ["uvicorn", "auditor.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
