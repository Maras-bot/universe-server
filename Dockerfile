FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UNIVERSE_ENABLE_DOCS=0 \
    UNIVERSE_DRY_RUN=1 \
    UNIVERSE_REQUIRE_TLS=1 \
    UNIVERSE_CONFIGS_DIR=configs

# UNIVERSE_ALLOW_LIVE non è impostata: resta il dry-run.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY universe ./universe
COPY configs ./configs

EXPOSE 8080

# Railway e gli altri host iniettano PORT. Bind su 0.0.0.0: TLS è terminato all'edge.
CMD ["sh", "-c", "uvicorn universe.app:app --host 0.0.0.0 --port ${PORT:-8080} --no-server-header --proxy-headers --forwarded-allow-ips=*"]
