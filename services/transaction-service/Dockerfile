# CK-01 — Vulnerable base image.
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# CK-02 / IV-05 — runs as root. No HEALTHCHECK.

EXPOSE 5002

CMD ["python", "app.py"]
