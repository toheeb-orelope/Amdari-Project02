# CK-01 — Vulnerable base image.
FROM python:3.12.13-alpine

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# CK-02 / IV-05 — runs as root. No HEALTHCHECK.
RUN addgroup -S app && adduser -S -G app app

USER app

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health', timeout=3).read()" || exit 1

EXPOSE 5000

CMD ["python", "app.py"]
