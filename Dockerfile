FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY checklists ./checklists

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1 \
    CHECKLIST_PATH=/app/checklists/postgres_cis.md \
    HOST=0.0.0.0 \
    PORT=8000

EXPOSE 8000

CMD ["uvicorn", "psql_auditor.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
