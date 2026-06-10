# CK-01 — Vulnerable base image. python:3.9-slim carries outdated system libraries.
FROM python:3.12.13-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# CK-02 — No USER directive. Container runs as root (uid 0).
# IV-05 — Same: no non-root user.
# Deliberately missing HEALTHCHECK.
RUN addgroup -S app && adduser -S -G app app

USER app


HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5001/health', timeout=3).read()" || exit 1

EXPOSE 5001

CMD ["python", "app.py"]



