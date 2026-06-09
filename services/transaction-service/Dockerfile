# CK-01 — Vulnerable base image.
FROM python:3.12.13-slim-bookworm

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# CK-02 / IV-05 — runs as root. No HEALTHCHECK.
RUN groupadd -r app && useradd -r -g app app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

USER app


HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:5002/health || exit 1

EXPOSE 5002

CMD ["python", "app.py"]
