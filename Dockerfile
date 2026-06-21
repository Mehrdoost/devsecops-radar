# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd -r pipeline && useradd -r -g pipeline -m -u 1000 pipeline

WORKDIR /app

# Copy everything needed for the build and install the package (NON-editable)
COPY pyproject.toml .
COPY devsecops_radar devsecops_radar
RUN pip install --no-cache-dir . && \
    chown -R pipeline:pipeline /app

USER pipeline

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080')" || exit 1

CMD ["devsecops-radar-web"]