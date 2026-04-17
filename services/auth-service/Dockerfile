# CK-01 — Vulnerable base image. python:3.9-slim carries outdated system libraries.
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# CK-02 — No USER directive. Container runs as root (uid 0).
# IV-05 — Same: no non-root user.
# Deliberately missing HEALTHCHECK.

EXPOSE 5001

CMD ["python", "app.py"]
