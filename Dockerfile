FROM python:3.12-slim

WORKDIR /app

# Node.js is required for antonorlov/mcp-postgres-server via `npx`.
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

RUN pip install --no-cache-dir .

# Pre-warm the npm package used by the MCP stdio client.
RUN npx -y mcp-postgres-server --help >/dev/null 2>&1 || true

ENV PYTHONUNBUFFERED=1 \
    AGENTS_DIR=/app/agents \
    HOST=0.0.0.0 \
    PORT=8000 \
    MCP_POSTGRES_COMMAND=npx \
    MCP_POSTGRES_ARGS="-y mcp-postgres-server"

EXPOSE 8000

CMD ["uvicorn", "psql_auditor.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
