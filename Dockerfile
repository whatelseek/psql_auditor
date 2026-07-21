FROM python:3.12-slim

WORKDIR /app

# Node.js for antonorlov/mcp-postgres-server; curl for uv; git for NetBox MCP.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ca-certificates \
    gnupg \
    git \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.local/bin:${PATH}"

COPY pyproject.toml README.md ./
COPY src ./src
COPY agents ./agents

RUN pip install --no-cache-dir .

# Pre-warm Postgres MCP (npm) and NetBox MCP (git clone + uv; not on PyPI yet).
RUN npx -y mcp-postgres-server --help >/dev/null 2>&1 || true
RUN git clone --depth 1 https://github.com/netboxlabs/netbox-mcp-server.git /opt/netbox-mcp-server \
    && cd /opt/netbox-mcp-server && uv sync

ENV PYTHONUNBUFFERED=1 \
    AGENTS_DIR=/app/agents \
    HOST=0.0.0.0 \
    PORT=8000 \
    MCP_POSTGRES_COMMAND=npx \
    MCP_POSTGRES_ARGS="-y mcp-postgres-server" \
    MCP_NETBOX_COMMAND=uv \
    MCP_NETBOX_ARGS="--directory /opt/netbox-mcp-server run netbox-mcp-server" \
    INTAKE_ENABLED=true \
    INVENTORY_DIR=/app/inventory

EXPOSE 8000

CMD ["uvicorn", "auditor.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
