FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

FROM python:3.11-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

WORKDIR /app
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /root/.cache/huggingface /app/.cache/huggingface

COPY --chown=appuser:appuser scripts/ scripts/
COPY --chown=appuser:appuser src/ src/
COPY --chown=appuser:appuser data/chromadb/ data/chromadb/
COPY --chown=appuser:appuser sample_alert.json .

RUN mkdir -p /app/outputs \
    && chmod -R a+rX /app/.cache \
    && chown -R appuser:appuser /app

ENV HF_HOME=/app/.cache/huggingface \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROMA_WRITABLE_COPY=1

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

ENTRYPOINT ["/app/scripts/docker_entrypoint.sh"]
CMD ["uvicorn", "scripts.webhook_receiver:app", "--host", "0.0.0.0", "--port", "8000"]
