FROM python:3.12-slim

# tini reaps zombies from the scanner's thread pools; curl backs the healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-web.txt ./
RUN pip install --no-cache-dir -r requirements-web.txt

COPY pyproject.toml README.md ./
COPY domain_scanner ./domain_scanner
RUN pip install --no-cache-dir --no-deps -e .

# Run unprivileged; /app/data is the only path that needs to be writable.
RUN useradd --system --uid 10001 --create-home scanner \
 && mkdir -p /app/data \
 && chown -R scanner:scanner /app
USER scanner

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SCANNER_DB=/app/data/scanner.db

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "domain_scanner.web.main:app", "--host", "0.0.0.0", "--port", "8000"]
